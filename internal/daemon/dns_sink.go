package daemon

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

// DNSFilterSink is the exact-tier transaction boundary used by DNSServer.
// BeginAdmission acquires the attachment mutation barrier; callers then take
// the DNSServer policy lock, revalidate their generation/owner, and invoke
// AdmitCanonicalResponse. ReconcilePolicy/Expire are called by server paths which
// already own the mutation barrier. This split preserves the global lock order:
// attachment barrier -> DNS policy/generation -> ownership manager.
type DNSFilterSink interface {
	BeginAdmission() (func(), error)
	AdmitCanonicalResponse(dnsCanonicalAdmissionRequest) error
	ReconcilePolicy(dnsAdmissionLimits, map[string]struct{}, dnsOwnershipResolver, bool) error
	PreflightPolicy(dnsAdmissionLimits, map[string]struct{}, dnsOwnershipResolver, bool) error
	Expire(time.Time) error
	SeedPinned() error
	ValidateLimits(dnsAdmissionLimits) error
	FailClosedIfAmbiguous(error) error
	QuarantineAmbiguity(error) error
}

// dnsCapacityWarnInterval rate-limits admission-pressure warnings per attachment.
const dnsCapacityWarnInterval = 30 * time.Second

type dnsFilterSink struct {
	server  *Server
	id      string
	filter  filter.Filter
	manager *dnsOwnershipManager
	dns     *DNSServer
	logger  zerolog.Logger

	lastCapacityWarn atomic.Int64
	capacityDrops    atomic.Uint64
}

func (s *dnsFilterSink) bindDNS(server *DNSServer) {
	s.dns = server
}

func (s *Server) newDNSFilterSink(id string, f filter.Filter) (*dnsFilterSink, error) {
	manager, err := newDNSOwnershipManager(f, s.dnsAdmissionCeilings, s.dnsMinFilterTTL, func() time.Time { return s.now() })
	if err != nil {
		return nil, err
	}
	return &dnsFilterSink{
		server:  s,
		id:      id,
		filter:  f,
		manager: manager,
		logger:  s.logger.With().Str("id", id).Logger(),
	}, nil
}

func (s *dnsFilterSink) BeginAdmission() (func(), error) {
	state, done, err := s.server.beginAttachmentMutation(s.id)
	if err != nil {
		return nil, err
	}
	if state.filter != s.filter || state.dnsSink != s || state.dns != s.dns {
		done()
		return nil, fmt.Errorf("attachment DNS filter sink is stale")
	}
	return done, nil
}

func (s *dnsFilterSink) AdmitResponse(req dnsAdmissionRequest) error {
	return s.recordAdmissionResult(s.manager.admit(req))
}

func (s *dnsFilterSink) AdmitCanonicalResponse(req dnsCanonicalAdmissionRequest) error {
	return s.recordAdmissionResult(s.manager.admitCanonical(req))
}

func (s *dnsFilterSink) recordAdmissionResult(err error) error {
	if err == nil {
		return nil
	}
	if isDNSCapacityError(err) {
		s.capacityDrops.Add(1)
		if !errors.Is(err, filter.ErrDNSAllowRollback) {
			s.warnAdmission(err)
		}
	}
	return err
}

func (s *dnsFilterSink) ReconcilePolicy(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	// A rejected configuration/remap is not a dropped DNS response insertion,
	// so it does not contribute to compatibility map_full_drops. The command
	// path returns and logs its precise error.
	return s.manager.reconcile(limits, policyDomains, resolve, authoritative)
}

func isDNSCapacityError(err error) bool {
	return errors.Is(err, errDNSAdmissionCapacity) || errors.Is(err, filter.ErrDNSAllowCapacity) || isMapFull(err)
}

func (s *dnsFilterSink) CapacityDropCount() uint64 {
	if s == nil {
		return 0
	}
	return s.capacityDrops.Load()
}

func (s *dnsFilterSink) PreflightPolicy(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	return s.manager.preflightReconcile(limits, policyDomains, resolve, authoritative)
}

func (s *dnsFilterSink) Expire(now time.Time) error {
	return s.manager.expire(now)
}

func (s *dnsFilterSink) SeedPinned() error {
	return s.manager.seedPinned()
}

func (s *dnsFilterSink) ValidateLimits(limits dnsAdmissionLimits) error {
	return s.manager.validateLimits(limits)
}

func (s *dnsFilterSink) LimitCeilings() dnsAdmissionLimits {
	return s.manager.limits
}

// FailClosedIfAmbiguous stages BLOCK_ALL synchronously while the caller still
// owns the attachment mutation barrier. That is the only safe response when
// the exact-tier rollback could not prove the kernel snapshot. The caller may
// subsequently persist full quarantine after releasing the barrier.
func (s *dnsFilterSink) FailClosedIfAmbiguous(err error) error {
	if !errors.Is(err, filter.ErrDNSAllowRollback) {
		return nil
	}
	var stageErr error
	if s.filter == nil {
		stageErr = fmt.Errorf("DNS exact-tier rollback was ambiguous and the filter is unavailable")
	} else if modeErr := s.filter.SetMode(filter.ModeBlockAll); modeErr != nil {
		stageErr = fmt.Errorf("forcing BLOCK_ALL after ambiguous DNS exact-tier rollback: %w", modeErr)
	}
	// Close admission before the caller releases its existing mutation RLock.
	// A queued command can then never reopen the packet mode in the gap before
	// full quarantine drains the barrier and persists BLOCK_ALL.
	s.server.mu.Lock()
	state := s.server.attachments[s.id]
	if state == nil || state.filter != s.filter {
		stageErr = errors.Join(stageErr, fmt.Errorf("closing mutation admission after ambiguous DNS rollback: attachment ownership changed"))
	} else {
		state.mutationsClosed = true
		state.info.Mode = filterModeToAPIMode(filter.ModeBlockAll).String()
	}
	s.server.mu.Unlock()
	return errors.Join(fmt.Errorf("DNS exact-tier rollback was ambiguous: %w", err), stageErr)
}

func (s *dnsFilterSink) QuarantineAmbiguity(err error) error {
	if !errors.Is(err, filter.ErrDNSAllowRollback) {
		return nil
	}
	s.server.mu.RLock()
	state := s.server.attachments[s.id]
	s.server.mu.RUnlock()
	if state == nil || state.filter != s.filter {
		return fmt.Errorf("persisting DNS rollback quarantine: attachment ownership changed")
	}
	return s.server.quarantineAttachment(s.id, state)
}

func (s *dnsFilterSink) warnAdmission(err error) {
	now := s.server.now().UnixNano()
	last := s.lastCapacityWarn.Load()
	if (last != 0 && now-last < int64(dnsCapacityWarnInterval)) || !s.lastCapacityWarn.CompareAndSwap(last, now) {
		return
	}
	s.logger.Warn().Err(err).
		Uint64("capacity_drops", s.capacityDrops.Load()).
		Uint32("dns_max_ips_per_family", s.manager.limits.maxIPsPerFamily).
		Uint32("exact_ipv4_capacity", s.manager.capacity.IPv4Capacity).
		Uint32("exact_ipv6_capacity", s.manager.capacity.IPv6Capacity).
		Msg("DNS exact-tier admission rejected; existing working set preserved; wait for TTL expiry or increase filter.max_dns_rule_entries and the bounded dns.* limits before retrying")
}
