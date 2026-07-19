package daemon

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

// DNSFilterSink is the exact-tier transaction boundary used by DNSServer.
// BeginAdmission acquires the attachment mutation barrier and its exclusive
// mutationSerialMu lane; callers then take the DNSServer policy lock,
// revalidate their generation/owner, and invoke AdmitCanonicalResponse.
// ReconcilePolicy/Expire are called by server paths already holding that same
// serialized mutation lease. SeedPinned is startup-only before publication.
// This split preserves the global lock order: attachment mutation lane -> DNS
// policy/generation -> ownership manager.
type DNSFilterSink interface {
	BeginAdmission() (func(), error)
	AdmitCanonicalResponse(dnsCanonicalAdmissionRequest) error
	ReconcilePolicy(dnsAdmissionLimits, dnsChurnLimits, map[string]struct{}, dnsOwnershipResolver, bool) error
	PreflightPolicy(dnsAdmissionLimits, dnsChurnLimits, map[string]struct{}, dnsOwnershipResolver, bool) error
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

	lastCapacityWarn  dnsPressureLogLimiter
	lastBudgetWarn    dnsPressureLogLimiter
	lastWorkWarn      dnsPressureLogLimiter
	capacityDrops     atomic.Uint64
	admissionFailures atomic.Uint64
	budgetThrottles   atomic.Uint64
	pressureActive    atomic.Uint32
	pressureReported  atomic.Uint32
}

func (s *dnsFilterSink) bindDNS(server *DNSServer) {
	s.dns = server
}

func (s *Server) newDNSFilterSink(id string, f filter.Filter) (*dnsFilterSink, error) {
	manager, err := newDNSOwnershipManagerWithChurn(f, s.dnsAdmissionCeilings, s.dnsChurnCeiling, s.dnsMinFilterTTL, func() time.Time { return s.now() })
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
	outcome, err := s.manager.admitDetailed(req)
	return s.recordAdmissionResult(err, outcome)
}

func (s *dnsFilterSink) AdmitCanonicalResponse(req dnsCanonicalAdmissionRequest) error {
	outcome, err := s.manager.admitCanonicalDetailed(req)
	return s.recordAdmissionResult(err, outcome)
}

const (
	dnsCapacityPressure uint32 = 1 << iota
	dnsBudgetPressure
	dnsWorkPressure
)

func (s *dnsFilterSink) recordAdmissionResult(err error, outcome dnsAdmissionOutcome) error {
	if err == nil {
		s.logPressureRecovery(outcome)
		return nil
	}
	s.admissionFailures.Add(1)
	if errors.Is(err, errDNSAdmissionBudget) || errors.Is(err, errDNSAdmissionWorkBudget) {
		s.budgetThrottles.Add(1)
		pressure := dnsBudgetPressure
		if errors.Is(err, errDNSAdmissionWorkBudget) {
			pressure = dnsWorkPressure
		}
		s.warnAdmission(err, pressure)
		return err
	}
	if isDNSCapacityError(err) {
		s.capacityDrops.Add(1)
		if !errors.Is(err, filter.ErrDNSAllowRollback) {
			s.warnAdmission(err, dnsCapacityPressure)
		}
	}
	return err
}

func (s *dnsFilterSink) ReconcilePolicy(limits dnsAdmissionLimits, churn dnsChurnLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	// A rejected configuration/remap is not a dropped DNS response insertion,
	// so it does not contribute to compatibility map_full_drops. The command
	// path returns and logs its precise error.
	return s.manager.reconcileWithChurn(limits, churn, policyDomains, resolve, authoritative)
}

func isDNSCapacityError(err error) bool {
	return errors.Is(err, errDNSAdmissionCapacity) || errors.Is(err, filter.ErrDNSAllowCapacity) || isMapFull(err)
}

func isDNSAdmissionPressure(err error) bool {
	return isDNSCapacityError(err) || errors.Is(err, errDNSAdmissionBudget) || errors.Is(err, errDNSAdmissionWorkBudget)
}

func (s *dnsFilterSink) CapacityDropCount() uint64 {
	if s == nil {
		return 0
	}
	return s.capacityDrops.Load()
}

func (s *dnsFilterSink) AdmissionFailureCount() uint64 {
	if s == nil {
		return 0
	}
	return s.admissionFailures.Load()
}

func (s *dnsFilterSink) BudgetThrottleCount() uint64 {
	if s == nil {
		return 0
	}
	return s.budgetThrottles.Load()
}

func (s *dnsFilterSink) OwnershipStats() dnsOwnershipStats {
	if s == nil || s.manager == nil {
		return dnsOwnershipStats{}
	}
	return s.manager.stats()
}

func (s *dnsFilterSink) PreflightPolicy(limits dnsAdmissionLimits, churn dnsChurnLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	return s.manager.preflightReconcileWithChurn(limits, churn, policyDomains, resolve, authoritative)
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

func (s *dnsFilterSink) ChurnCeiling() dnsChurnLimits {
	return dnsChurnLimits{maxUnits: s.manager.churnBudget.ceiling, window: s.manager.churnBudget.window}
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

func (s *dnsFilterSink) warnAdmission(err error, pressure uint32) {
	lastWarn := &s.lastCapacityWarn
	switch pressure {
	case dnsBudgetPressure:
		lastWarn = &s.lastBudgetWarn
	case dnsWorkPressure:
		lastWarn = &s.lastWorkWarn
	}
	for {
		old := s.pressureActive.Load()
		if s.pressureActive.CompareAndSwap(old, old|pressure) {
			break
		}
	}
	now := s.server.now().UnixNano()
	if !dnsPressureLogAllowed(lastWarn, now) {
		return
	}
	atomicSetBits(&s.pressureReported, pressure)
	event := s.logger.Warn().Err(err).
		Uint64("capacity_drops", s.capacityDrops.Load()).
		Uint64("budget_throttles", s.budgetThrottles.Load()).
		Uint32("dns_max_ips_per_family", s.manager.limits.maxIPsPerFamily).
		Uint32("dns_max_churn_units", s.manager.churnLimits.maxUnits).
		Uint32("dns_work_scale", s.manager.workScale).
		Uint32("dns_work_limit", s.manager.currentWorkLimit()).
		Uint32("exact_ipv4_capacity", s.manager.capacity.IPv4Capacity).
		Uint32("exact_ipv6_capacity", s.manager.capacity.IPv6Capacity)
	if pressure == dnsBudgetPressure {
		event.Msg("DNS rolling churn budget throttled admission; existing working set preserved; wait for dns.churn_window recovery, lower response churn, or raise DnsConfig.max_churn_units up to the daemon dns.max_churn_units ceiling (raising the daemon ceiling requires restart)")
		return
	}
	if pressure == dnsWorkPressure {
		event.Msg("DNS rolling ownership-planning work budget throttled admission; existing working set preserved; wait for dns.churn_window recovery, reduce repeated capacity pressure, or raise DnsConfig.max_churn_units up to the daemon dns.max_churn_units ceiling (raising the daemon ceiling requires restart)")
		return
	}
	event.Msg("DNS exact-tier admission rejected; existing working set preserved; wait for TTL expiry/LRU eligibility or increase filter.max_dns_rule_entries and the bounded dns.* limits before retrying")
}

func (s *dnsFilterSink) logPressureRecovery(outcome dnsAdmissionOutcome) {
	resolved := outcome.resolvedPressure
	if outcome.committedUnits == 0 {
		resolved &^= dnsBudgetPressure
	}
	if !outcome.changed || resolved == 0 {
		return
	}
	var recovered, remaining uint32
	for {
		old := s.pressureActive.Load()
		if old == 0 {
			return
		}
		recovered = old & resolved
		if recovered == 0 {
			return
		}
		next := old &^ recovered
		if !s.pressureActive.CompareAndSwap(old, next) {
			continue
		}
		remaining = next
		break
	}
	reported := atomicClearBits(&s.pressureReported, recovered)
	if reported == 0 {
		return
	}
	stats := s.manager.stats()
	event := s.logger.Info().
		Uint64("capacity_drops", s.capacityDrops.Load()).
		Uint64("budget_throttles", s.budgetThrottles.Load()).
		Uint32("exact_ipv4_entries", stats.occupancy.IPv4Entries).
		Uint32("exact_ipv6_entries", stats.occupancy.IPv6Entries).
		Bool("capacity_recovered", recovered&dnsCapacityPressure != 0).
		Bool("budget_recovered", recovered&dnsBudgetPressure != 0).
		Bool("work_budget_recovered", recovered&dnsWorkPressure != 0).
		Bool("pressure_remaining", remaining != 0)
	if remaining != 0 {
		event.Msg("DNS admission pressure partially recovered; another pressure condition remains active")
		return
	}
	event.Msg("DNS admission pressure recovered; address-bearing responses are being admitted again")
}

func atomicSetBits(target *atomic.Uint32, bits uint32) {
	for {
		old := target.Load()
		if target.CompareAndSwap(old, old|bits) {
			return
		}
	}
}

func atomicClearBits(target *atomic.Uint32, bits uint32) uint32 {
	for {
		old := target.Load()
		cleared := old & bits
		if cleared == 0 || target.CompareAndSwap(old, old&^bits) {
			return cleared
		}
	}
}

type dnsPressureLogLimiter struct {
	mu          sync.Mutex
	initialized bool
	last        int64
}

func dnsPressureLogAllowed(limiter *dnsPressureLogLimiter, now int64) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.initialized && now-limiter.last < int64(dnsCapacityWarnInterval) {
		return false
	}
	limiter.initialized = true
	limiter.last = now
	return true
}
