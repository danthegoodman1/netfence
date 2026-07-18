package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type Server struct {
	apiv1.UnimplementedDaemonServiceServer

	cfg      *config.Config
	store    *store.Store
	logger   zerolog.Logger
	daemonID string
	hostname string
	version  string

	mu          sync.RWMutex
	stopping    bool
	attachWG    sync.WaitGroup
	portPool    map[int]bool
	attachments map[string]*attachmentState
	targetIndex map[string]string // target -> attachment ID (for reverse lookup on removal)

	cpClient atomic.Pointer[ControlPlaneClient]
	watcher  *TargetWatcher

	// TTL janitor state. now is injectable for deterministic tests.
	now                func() time.Time
	ttlJanitorInterval time.Duration
	janitorStop        chan struct{}
	janitorStopOnce    sync.Once
	janitorWG          sync.WaitGroup

	// dnsMinFilterTTL floors the lifetime of DNS-resolved IPs in the filter
	// (see config dns.min_filter_ttl).
	dnsMinFilterTTL time.Duration
	// maxRuleEntries sizes each eBPF rule map at filter load time
	// (see config filter.max_rule_entries; 0 = compiled-in default).
	maxRuleEntries uint32

	// pinRoot is the bpffs directory attachment BPF state is pinned under
	// (config filter.bpf_pin_dir; "" disables pinning). detachOnStop selects
	// Stop's teardown path: false (default) keeps the pins so the kernel
	// keeps enforcing while the daemon is down; true detaches and unpins.
	pinRoot      string
	detachOnStop bool

	// newFilter constructs the eBPF filter for an attachment. It is a struct
	// field (always createFilter in production, set once in NewServer and
	// never reassigned) purely so unit tests can inject fake filters and
	// forced construction failures. pinDir is the attachment's bpffs pin
	// directory ("" disables pinning).
	newFilter func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error)
	// loadPinnedFilter re-adopts an attachment's BPF state from its pin
	// directory during restore, without re-attaching (production:
	// loadPinnedFilter; a seam for the same reason as newFilter).
	loadPinnedFilter func(pinDir, target string, attachType apiv1.AttachmentType, direction apiv1.TcDirection) (filter.Filter, error)
	// ensurePinRoot prepares pinRoot on bpffs (production: ensureBPFPinRoot;
	// a seam so unit tests can use plain temp directories).
	ensurePinRoot func(pinRoot string) error
	// targetExists reports whether an attachment target is still present
	// (production: targetPresent; a seam so unit tests can restore
	// attachments whose fake targets never existed).
	targetExists func(attachType apiv1.AttachmentType, target string) bool
	// targetIdentity resolves the kernel object an attachment name/path
	// currently denotes (ifindex or cgroup id). Attach validates this identity
	// across filter construction and watcher registration so a same-name/path
	// replacement can never bind the filter and watcher to different objects.
	targetIdentity func(attachType apiv1.AttachmentType, target string) (uint64, error)
}

type attachmentState struct {
	info   *store.Attachment
	dns    *DNSServer
	filter filter.Filter
	// reconcileMu serializes an authoritative SubscribedAck apply against
	// teardown of this exact state. Server.mu is never held while waiting for
	// it: teardown uses lookup -> lock -> revalidate, while ack uses lock ->
	// exact-live validation, avoiding lock inversion and preventing a delayed
	// store save/filter call from resurrecting or touching a detached state.
	reconcileMu sync.Mutex
	// needsResync is set only for attachments successfully restored by Start
	// (whether their filter was re-adopted from pins or recreated empty). The
	// control-plane client re-drives Subscribed -> SubscribedAck after each
	// connection's fresh SyncRequest and clears this flag only after an
	// authoritative full-state ack has been applied successfully to this exact
	// attachmentState. Guarded by Server.mu.
	needsResync bool
	// watch identifies the exact watcher registration owned by this
	// attachment. A delayed callback for an older same-target generation is
	// ignored unless this token still matches.
	watch watchToken
	// ttls tracks expiry deadlines for this attachment's TTL'd CIDR entries
	// and serializes its CIDR-rule mutations. See ttlRegistry.
	ttls *ttlRegistry
}

func NewServer(cfg *config.Config, st *store.Store, logger zerolog.Logger, version string) (*Server, error) {
	hostname, _ := os.Hostname()

	// The proto promises the daemon id is stable across restarts, so it lives
	// in the store: file-backed stores (data_dir set) yield the same UUID on
	// every boot, while :memory: stores get a fresh ephemeral one per process.
	daemonID, err := st.GetOrCreateDaemonID()
	if err != nil {
		return nil, fmt.Errorf("resolving daemon id: %w", err)
	}

	janitorInterval := cfg.TTLJanitorInterval
	if janitorInterval <= 0 {
		janitorInterval = time.Second
	}
	// Zero/unset means the default floor, not "no floor" (mirrors the
	// janitor-interval coercion above).
	dnsMinFilterTTL := cfg.DNS.MinFilterTTL
	if dnsMinFilterTTL <= 0 {
		dnsMinFilterTTL = 60 * time.Second
	}
	var maxRuleEntries uint32
	if cfg.Filter.MaxRuleEntries > 0 {
		maxRuleEntries = uint32(cfg.Filter.MaxRuleEntries)
	}

	s := &Server{
		cfg:                cfg,
		store:              st,
		logger:             logger.With().Str("component", "daemon").Logger(),
		daemonID:           daemonID,
		hostname:           hostname,
		version:            version,
		portPool:           make(map[int]bool),
		attachments:        make(map[string]*attachmentState),
		targetIndex:        make(map[string]string),
		now:                time.Now,
		ttlJanitorInterval: janitorInterval,
		janitorStop:        make(chan struct{}),
		dnsMinFilterTTL:    dnsMinFilterTTL,
		maxRuleEntries:     maxRuleEntries,
		pinRoot:            cfg.Filter.BPFPinDir,
		detachOnStop:       cfg.Filter.DetachOnStop,
		newFilter:          createFilter,
		loadPinnedFilter:   loadPinnedFilter,
		ensurePinRoot:      ensureBPFPinRoot,
		targetExists:       targetPresent,
		targetIdentity:     currentTargetIdentity,
	}

	s.watcher = NewTargetWatcher(logger, s.handleTargetRemoved)

	for port := cfg.DNS.PortMin; port <= cfg.DNS.PortMax; port++ {
		s.portPool[port] = false
	}

	existing, err := st.GetAllAttachments()
	if err != nil {
		return nil, fmt.Errorf("loading existing attachments: %w", err)
	}
	for i := range existing {
		s.attachments[existing[i].ID] = &attachmentState{info: &existing[i], ttls: newTTLRegistry()}
		s.targetIndex[existing[i].Target] = existing[i].ID
		// Only mark ports that belong to the configured pool: a persisted
		// port outside [PortMin, PortMax] (e.g. after a config change) must
		// not be inserted as a poolable key, or a later release would let
		// allocatePort hand out an out-of-range port.
		port := extractPort(existing[i].DnsAddress)
		if _, ok := s.portPool[port]; ok {
			s.portPool[port] = true
		}
	}

	return s, nil
}

func (s *Server) SetControlPlaneClient(cp *ControlPlaneClient) {
	s.cpClient.Store(cp)
}

// setTargetIdentityResolver is a test seam that keeps Server's lifecycle
// validation and TargetWatcher's post-registration validation on the same
// deterministic identity source.
func (s *Server) setTargetIdentityResolver(resolve func(apiv1.AttachmentType, string) (uint64, error)) {
	s.targetIdentity = resolve
	s.watcher.setTargetIdentityResolver(resolve)
}

func (s *Server) Start() error {
	if s.pinRoot != "" {
		if err := s.ensurePinRoot(s.pinRoot); err != nil {
			return fmt.Errorf("preparing BPF pin root: %w", err)
		}
	}

	s.mu.Lock()
	var toRemove []string
	for id, state := range s.attachments {
		attachType := parseAttachmentType(state.info.Type)
		mode := parsePolicyMode(state.info.Mode)
		direction := parseTcDirection(state.info.Direction)
		expectedIdentity, err := s.targetIdentity(attachType, state.info.Target)
		if err != nil {
			s.logger.Warn().Err(err).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("failed to resolve target identity on restore")
			toRemove = append(toRemove, id)
			continue
		}

		ebpfFilter, adopted, err := s.restoreFilter(id, state.info.Target, attachType, mode, direction)
		if err != nil {
			var abort *restoreAbortError
			if errors.As(err, &abort) {
				s.mu.Unlock()
				return fmt.Errorf("restoring attachment %s: %w", id, abort.err)
			}
			s.logger.Warn().Err(err).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("failed to restore filter, target may be gone")
			toRemove = append(toRemove, id)
			continue
		}
		if adopted {
			if err := s.seedAdoptedState(id, state, ebpfFilter); err != nil {
				// Inventory is required for an authoritative delta reconcile: if a
				// live pinned rule is absent from the registry, a later ack could
				// falsely report convergence while leaving stale enforcement behind.
				// Abort startup and Close (not Detach) so the pins keep enforcing the
				// last-known policy for a clean retry.
				if closeErr := ebpfFilter.Close(); closeErr != nil {
					s.logger.Warn().Err(closeErr).Str("id", id).Msg("failed to close adopted filter after inventory failure")
				}
				s.mu.Unlock()
				return fmt.Errorf("inventorying re-adopted attachment %s: %w", id, err)
			}
		}

		var proxyFunc DnsProxyFunc
		if cpClient := s.cpClient.Load(); cpClient != nil {
			proxyFunc = cpClient.MakeProxyFunc(id)
		}
		sink := s.newDNSFilterSink(id, ebpfFilter, state.ttls)
		dnsServer := NewDNSServer(id, state.info.DnsAddress, s.cfg.DNS.Upstream, s.logger, sink, proxyFunc)
		if err := dnsServer.Start(); err != nil {
			s.logger.Warn().Err(err).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("failed to start DNS server on restore")
			if ebpfFilter != nil {
				// The attachment is being dropped for good: Detach (not
				// Close) so its pinned state is destroyed too.
				if err := ebpfFilter.Detach(); err != nil {
					s.logger.Warn().Err(err).Str("id", id).Msg("error detaching filter after restore DNS failure")
				}
			}
			toRemove = append(toRemove, id)
			continue
		}

		var (
			token    watchToken
			watchErr = s.validateTargetIdentity(attachType, state.info.Target, expectedIdentity)
		)
		if watchErr == nil {
			switch attachType {
			case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
				token, watchErr = s.watcher.WatchInterface(state.info.Target, expectedIdentity)
			case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
				token, watchErr = s.watcher.WatchCgroup(state.info.Target, expectedIdentity)
			}
		}
		if watchErr != nil {
			s.logger.Warn().Err(watchErr).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("failed to watch target on restore")
			if err := dnsServer.Stop(); err != nil {
				s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server after restore watch failure")
			}
			if ebpfFilter != nil {
				// Dropped for good: Detach so pinned state goes too.
				if err := ebpfFilter.Detach(); err != nil {
					s.logger.Warn().Err(err).Str("id", id).Msg("error detaching filter after restore watch failure")
				}
			}
			toRemove = append(toRemove, id)
			continue
		}
		state.watch = token
		state.filter = ebpfFilter
		state.dns = dnsServer
		state.needsResync = true

		s.logger.Info().
			Str("id", id).
			Str("target", state.info.Target).
			Str("type", attachType.String()).
			Bool("readopted_from_pins", adopted).
			Msg("restored attachment")
	}

	for _, id := range toRemove {
		state := s.attachments[id]
		if state != nil {
			delete(s.targetIndex, state.info.Target)
			port := extractPort(state.info.DnsAddress)
			if port > 0 {
				s.releasePort(port)
			}
		}
		delete(s.attachments, id)
		if err := s.store.DeleteAttachment(id); err != nil {
			s.logger.Error().Err(err).Str("id", id).Msg("failed to delete stale attachment from store")
		}
	}

	// Reconcile orphaned pin dirs: bpffs state with no surviving store row
	// (e.g. a crash between pinning and the store save, or a row dropped just
	// above) is unowned — remove it so no stale enforcement or kernel
	// objects leak.
	if s.pinRoot != "" {
		if entries, err := os.ReadDir(s.pinRoot); err != nil {
			s.logger.Warn().Err(err).Msg("failed to scan BPF pin root for orphans")
		} else {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				if _, ok := s.attachments[entry.Name()]; ok {
					continue
				}
				orphan := filepath.Join(s.pinRoot, entry.Name())
				if err := os.RemoveAll(orphan); err != nil {
					s.logger.Warn().Err(err).Str("pin_dir", orphan).Msg("failed to remove orphaned BPF pin dir")
				} else {
					s.logger.Info().Str("pin_dir", orphan).Msg("removed orphaned BPF pin dir (no matching attachment)")
				}
			}
		}
	}
	s.mu.Unlock()

	if err := s.watcher.Start(); err != nil {
		return fmt.Errorf("starting target watcher: %w", err)
	}

	s.janitorWG.Add(1)
	go s.runTTLJanitor()

	return nil
}

// pinDirFor returns the bpffs pin directory for an attachment, or "" when
// pinning is disabled.
func (s *Server) pinDirFor(id string) string {
	if s.pinRoot == "" {
		return ""
	}
	return filepath.Join(s.pinRoot, id)
}

// restoreAbortError marks a restoreFilter failure that must abort daemon
// startup (e.g. the pin state's existence cannot be determined) instead of
// being treated as a gone target and cleaning the attachment up.
type restoreAbortError struct{ err error }

func (e *restoreAbortError) Error() string { return e.err.Error() }
func (e *restoreAbortError) Unwrap() error { return e.err }

// restoreFilter obtains the eBPF filter for a persisted attachment during
// Start. The keep-enforcing path re-adopts the attachment's pinned BPF state
// (rules intact, links never re-attached — so no transient allow/block
// window and no duplicate attachment; the kernel was enforcing the whole
// time the daemon was down). Absent or unusable pins fall back to recreating
// an empty filter in the persisted mode — the pre-pinning behavior, e.g.
// after a detach_on_stop run or on data from a pre-pinning daemon — and the
// caller's log line records which path was taken. adopted reports whether
// the pinned path was used.
func (s *Server) restoreFilter(id, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection) (_ filter.Filter, adopted bool, _ error) {
	pinDir := s.pinDirFor(id)
	if pinDir != "" {
		_, statErr := os.Stat(pinDir)
		if statErr != nil && !os.IsNotExist(statErr) {
			// Cannot tell whether pinned (live, kernel-enforcing) state
			// exists. Falling through to recreate-empty would silently
			// discard it on a transient EACCES/EIO, so abort startup and
			// surface the error instead of guessing.
			return nil, false, &restoreAbortError{err: fmt.Errorf("checking pin dir %s: %w", pinDir, statErr)}
		}
		if statErr == nil {
			if !s.targetExists(attachType, target) {
				// The target vanished while the daemon was down, so the
				// pinned links are defunct. Drop the pins and let the
				// recreate path below fail against the missing target, which
				// routes the attachment into the caller's cleanup.
				s.logger.Warn().Str("id", id).Str("target", target).
					Msg("target gone while daemon was down; discarding pinned BPF state")
				if rmErr := os.RemoveAll(pinDir); rmErr != nil {
					s.logger.Warn().Err(rmErr).Str("id", id).Str("pin_dir", pinDir).Msg("failed to remove stale pin dir")
				}
			} else {
				restored, lerr := s.loadPinnedFilter(pinDir, target, attachType, direction)
				if lerr == nil {
					return restored, true, nil
				}
				s.logger.Warn().Err(lerr).Str("id", id).Str("pin_dir", pinDir).
					Msg("failed to re-adopt pinned BPF state; discarding pins and recreating empty filter")
				if rmErr := os.RemoveAll(pinDir); rmErr != nil {
					s.logger.Warn().Err(rmErr).Str("id", id).Str("pin_dir", pinDir).Msg("failed to remove unusable pin dir")
				}
			}
		} else {
			s.logger.Info().Str("id", id).Str("pin_dir", pinDir).
				Msg("no pinned BPF state for attachment (detach_on_stop run or pre-pinning data); recreating empty filter")
		}
	}

	f, err := s.newFilter(pinDir, target, attachType, mode, direction, s.maxRuleEntries)
	if err != nil {
		return nil, false, err
	}
	return f, false, nil
}

// seedAdoptedState re-syncs daemon bookkeeping with kernel state adopted
// from pins: the store row's mode is corrected to the live (pinned) mode if
// they diverged (the pinned map IS what is enforcing; it is never rewritten
// on restore, so there is no transient mode window), and every adopted rule
// is seeded into the TTL registry as a permanent control-plane entry so a
// later BulkUpdate diff-reconcile sees — and can remove — it. TTL deadlines
// are not persisted, so TTL'd rules come back permanent until the next
// control-plane sync corrects them; that fails toward last-known policy.
// Called with s.mu held during Start (no concurrent rule traffic yet).
func (s *Server) seedAdoptedState(id string, state *attachmentState, f filter.Filter) error {
	var seedErr error
	if liveMode, err := f.GetMode(); err != nil {
		s.logger.Warn().Err(err).Str("id", id).Msg("failed to read mode from re-adopted filter")
		seedErr = errors.Join(seedErr, fmt.Errorf("reading adopted mode: %w", err))
	} else if apiMode := filterModeToAPIMode(liveMode); apiMode.String() != state.info.Mode {
		s.logger.Info().Str("id", id).
			Str("store_mode", state.info.Mode).
			Str("live_mode", apiMode.String()).
			Msg("store mode lagged pinned mode; trusting kernel state")
		state.info.Mode = apiMode.String()
		if err := s.store.SaveAttachment(cloneAttachment(state.info)); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Msg("failed to persist re-adopted mode")
			seedErr = errors.Join(seedErr, fmt.Errorf("persisting adopted mode: %w", err))
		}
	}

	lister, ok := f.(interface {
		Rules() (allowed, denied []*net.IPNet, err error)
	})
	if !ok {
		return errors.Join(seedErr, fmt.Errorf("adopted filter does not support rule inventory"))
	}
	allowed, denied, err := lister.Rules()
	if err != nil {
		return errors.Join(seedErr, fmt.Errorf("listing adopted rules: %w", err))
	}
	now := s.now()
	for _, cidr := range allowed {
		if err := state.ttls.addCP(f, cidr, listAllow, 0, now); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Str("cidr", cidr.String()).Msg("failed to seed re-adopted allow rule")
			seedErr = errors.Join(seedErr, fmt.Errorf("seeding adopted allow %s: %w", cidr, err))
		}
	}
	for _, cidr := range denied {
		if err := state.ttls.addCP(f, cidr, listDeny, 0, now); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Str("cidr", cidr.String()).Msg("failed to seed re-adopted deny rule")
			seedErr = errors.Join(seedErr, fmt.Errorf("seeding adopted deny %s: %w", cidr, err))
		}
	}
	s.logger.Info().Str("id", id).
		Int("allow_rules", len(allowed)).
		Int("deny_rules", len(denied)).
		Msg("re-adopted pinned rules (permanent until next control-plane sync; TTL deadlines are not persisted)")
	return seedErr
}

// targetPresent reports whether an attachment target still exists.
func targetPresent(attachType apiv1.AttachmentType, target string) bool {
	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		_, err := os.Stat(target)
		return err == nil
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		_, err := net.InterfaceByName(target)
		return err == nil
	default:
		return false
	}
}

func (s *Server) validateTargetIdentity(attachType apiv1.AttachmentType, target string, expected uint64) error {
	current, err := s.targetIdentity(attachType, target)
	if err != nil {
		return fmt.Errorf("resolving current target identity: %w", err)
	}
	if current != expected {
		return fmt.Errorf("target identity changed during attachment setup: was %d, now %d", expected, current)
	}
	return nil
}

func (s *Server) Stop() {
	// Publish terminal lifecycle state before waiting on any exact attachment
	// lock. A claimed ack that already owns reconcileMu may finish; every later
	// ack fails its exact-live check. Stop then joins each owner before closing
	// its filter/DNS resources, so no apply can run against a closed handle.
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	// Add is performed under the same mutex before an Attach begins, so once
	// stopping is published no new Add can race this Wait. Let in-flight
	// Attach calls commit or roll back before taking the terminal snapshot.
	s.attachWG.Wait()

	// Stop the janitor before closing filters so a sweep never races with
	// wholesale filter teardown.
	s.janitorStopOnce.Do(func() { close(s.janitorStop) })
	s.janitorWG.Wait()

	s.watcher.Stop()

	s.mu.RLock()
	attachments := make([]*attachmentState, 0, len(s.attachments))
	for _, state := range s.attachments {
		attachments = append(attachments, state)
	}
	s.mu.RUnlock()

	if s.detachOnStop {
		s.logger.Info().Int("attachments", len(attachments)).
			Msg("stopping with detach_on_stop: detaching filters and removing pinned BPF state (traffic will be unfiltered)")
	} else if len(attachments) > 0 && s.pinRoot != "" {
		s.logger.Info().Int("attachments", len(attachments)).
			Msg("stopping; pinned BPF state keeps enforcing the last-known policy while the daemon is down")
	}

	for _, state := range attachments {
		if cpClient := s.cpClient.Load(); cpClient != nil {
			cpClient.cancelSubscription(state.info.ID, fmt.Errorf("daemon stopping"))
		}
		state.reconcileMu.Lock()
		if !s.attachmentStatePresent(state.info.ID, state) {
			state.reconcileMu.Unlock()
			continue
		}
		if state.dns != nil {
			state.dns.Stop()
		}
		if state.filter != nil {
			if s.detachOnStop {
				if err := state.filter.Detach(); err != nil {
					s.logger.Warn().Err(err).Msg("error detaching filter on stop")
				}
			} else {
				state.filter.Close()
			}
		}
		state.reconcileMu.Unlock()
	}
}

// runTTLJanitor periodically removes expired TTL'd CIDR entries across all
// attachments. Expiry work is ordinary userspace map-update syscalls —
// identical to a control-plane remove command — and never touches the packet
// path.
func (s *Server) runTTLJanitor() {
	defer s.janitorWG.Done()
	ticker := time.NewTicker(s.ttlJanitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.janitorStop:
			return
		case <-ticker.C:
			s.sweepExpiredTTLs(s.now())
		}
	}
}

// sweepExpiredTTLs runs one janitor pass over every attachment. Split from
// runTTLJanitor so tests can drive it deterministically with a fake clock.
// Attachment state is snapshotted under s.mu, then each registry does its
// own expiry under its leaf lock — s.mu is never held during filter calls,
// and an attachment detached mid-scan just yields an already-purged registry
// (or idempotent/failed removes on a closed filter, which are retried and
// then dropped when the detach purge lands).
func (s *Server) sweepExpiredTTLs(now time.Time) {
	type sweepTarget struct {
		id     string
		reg    *ttlRegistry
		filter filter.Filter
	}

	s.mu.RLock()
	targets := make([]sweepTarget, 0, len(s.attachments))
	for id, state := range s.attachments {
		targets = append(targets, sweepTarget{id: id, reg: state.ttls, filter: state.filter})
	}
	s.mu.RUnlock()

	for _, t := range targets {
		for _, swept := range t.reg.expire(t.filter, now) {
			if swept.err != nil {
				s.logger.Warn().Err(swept.err).
					Str("id", t.id).
					Str("cidr", swept.cidr).
					Str("list", swept.list.String()).
					Msg("failed to remove expired CIDR, will retry")
				continue
			}
			s.logger.Debug().
				Str("id", t.id).
				Str("cidr", swept.cidr).
				Str("list", swept.list.String()).
				Msg("removed expired CIDR")
		}
	}
}

func (s *Server) handleTargetRemoved(token watchToken) {
	target := token.target
	s.mu.RLock()
	id, ok := s.targetIndex[target]
	if !ok {
		s.mu.RUnlock()
		return
	}
	state, ok := s.attachments[id]
	if !ok || state.watch != token {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	state.reconcileMu.Lock()
	defer state.reconcileMu.Unlock()
	s.mu.Lock()
	if s.stopping || s.targetIndex[target] != id || s.attachments[id] != state || state.watch != token {
		s.mu.Unlock()
		return
	}

	port := extractPort(state.info.DnsAddress)
	if port > 0 {
		s.releasePort(port)
	}

	switch parseAttachmentType(state.info.Type) {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.UnwatchInterface(token)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		s.watcher.UnwatchCgroup(token)
	}

	delete(s.attachments, id)
	delete(s.targetIndex, target)
	s.mu.Unlock()

	// A SubscribedAck that was in flight for this exact attachment is stale
	// once ownership has been removed. Cancel it before tearing down the
	// filter/DNS resources so a late ack cannot race the teardown.
	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.cancelSubscription(id, fmt.Errorf("attachment target was removed"))
	}

	// Drop TTL bookkeeping so an in-flight janitor sweep does not keep
	// retrying removals against the filter we are about to close.
	state.ttls.purge()

	if state.dns != nil {
		if err := state.dns.Stop(); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server")
		}
	}

	if state.filter != nil {
		// Genuine removal: Detach (not Close) so the pinned BPF state is
		// destroyed along with the kernel attachment.
		if err := state.filter.Detach(); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Msg("error detaching eBPF filter")
		}
	}

	if err := s.store.DeleteAttachment(id); err != nil {
		s.logger.Error().Err(err).Str("id", id).Msg("error deleting attachment from store")
	}

	s.logger.Info().
		Str("id", id).
		Str("target", target).
		Msg("cleaned up attachment after target removal")

	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
			Id:     id,
			Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_REMOVED,
		})
	}
}

func (s *Server) Attach(ctx context.Context, req *apiv1.AttachRequest) (*apiv1.AttachResponse, error) {
	var target string
	var attachType apiv1.AttachmentType

	switch t := req.Target.(type) {
	case *apiv1.AttachRequest_InterfaceName:
		target = t.InterfaceName
		attachType = apiv1.AttachmentType_ATTACHMENT_TYPE_TC
	case *apiv1.AttachRequest_CgroupPath:
		target = t.CgroupPath
		attachType = apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP
	default:
		return nil, fmt.Errorf("target must be interface_name or cgroup_path")
	}

	// Direction only applies to TC attachments; it is ignored for cgroups.
	// UNSPECIFIED normalizes to EGRESS (the pre-direction behavior).
	direction := apiv1.TcDirection_TC_DIRECTION_UNSPECIFIED
	if attachType == apiv1.AttachmentType_ATTACHMENT_TYPE_TC {
		direction = req.TcDirection
		if direction == apiv1.TcDirection_TC_DIRECTION_UNSPECIFIED {
			direction = apiv1.TcDirection_TC_DIRECTION_EGRESS
		}
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("daemon is stopping")
	}
	s.attachWG.Add(1)
	defer s.attachWG.Done()
	if existingID, ok := s.targetIndex[target]; ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("target already attached: %s (%s)", target, existingID)
	}

	port, err := s.allocatePort()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()

	id := uuid.Must(uuid.NewV7()).String()
	dnsAddr := net.JoinHostPort(s.cfg.DNS.ListenAddr, strconv.Itoa(port))

	// Always start in DISABLED mode - the control plane provides the initial
	// configuration via SubscribedAck
	mode := apiv1.PolicyMode_POLICY_MODE_DISABLED

	attachment := &store.Attachment{
		ID:         id,
		Target:     target,
		Type:       attachType.String(),
		Mode:       mode.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: dnsAddr,
		Metadata:   req.Metadata,
		AttachedAt: time.Now(),
	}
	if attachType == apiv1.AttachmentType_ATTACHMENT_TYPE_TC {
		attachment.Direction = direction.String()
	}

	// Staged setup with a single deferred rollback. Resources are acquired
	// in order (port -> filter -> DNS server -> store row -> registration ->
	// watch -> CP subscribe) and the rollback unwinds exactly the stages
	// reached, in reverse, so every failure/early return leaks nothing and
	// frees each resource exactly once. `committed` flips only after the
	// final under-lock liveness check.
	var (
		ebpfFilter filter.Filter
		dnsServer  *DNSServer
		ttls       = newTTLRegistry()
		rowSaved   bool
		registered *attachmentState
		notifyCP   bool
		committed  bool
	)
	defer func() {
		if committed {
			return
		}
		if registered != nil {
			// The attachment was publicly visible, so a concurrent Detach or
			// target removal (or a claimed SubscribedAck) may already own it.
			// Wait for the exact state's reconcile lock WITHOUT Server.mu, then
			// revalidate and claim ownership by removing the registration. If it
			// is already gone,
			// the remover tore down EVERYTHING (filter, DNS, port, store row,
			// watch) and this rollback must be a no-op — anything else would
			// double-free.
			registered.reconcileMu.Lock()
			defer registered.reconcileMu.Unlock()
			s.mu.Lock()
			if s.attachments[id] != registered {
				s.mu.Unlock()
				return
			}
			delete(s.attachments, id)
			delete(s.targetIndex, target)
			s.releasePort(port)
			switch attachType {
			case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
				s.watcher.UnwatchInterface(registered.watch)
			case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
				s.watcher.UnwatchCgroup(registered.watch)
			}
			s.mu.Unlock()
			if cpClient := s.cpClient.Load(); cpClient != nil {
				cpClient.cancelSubscription(id, fmt.Errorf("attachment setup rolled back"))
			}

			// Drop TTL bookkeeping so an in-flight janitor sweep does not
			// keep retrying removals against the filter we are closing.
			ttls.purge()

			if err := dnsServer.Stop(); err != nil {
				s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server during attach rollback")
			}
			// The rollback destroys the half-built attachment for good, so
			// Detach: the pins this Attach created must not outlive it.
			if err := ebpfFilter.Detach(); err != nil {
				s.logger.Warn().Err(err).Str("id", id).Msg("error detaching eBPF filter during attach rollback")
			}
			if err := s.store.DeleteAttachment(id); err != nil {
				s.logger.Error().Err(err).Str("id", id).Msg("error deleting attachment from store during attach rollback")
			}

			if notifyCP {
				if cpClient := s.cpClient.Load(); cpClient != nil {
					cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
						Id:     id,
						Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR,
						Error:  "control plane subscription failed",
					})
				}
			}
			return
		}

		// Pre-registration: nothing else can see these resources, so unwind
		// whatever was staged, in reverse acquisition order.
		if dnsServer != nil {
			if err := dnsServer.Stop(); err != nil {
				s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server during attach rollback")
			}
		}
		if ebpfFilter != nil {
			// Destroying the staged filter for good: Detach so its pins (if
			// any were created) go with it.
			if err := ebpfFilter.Detach(); err != nil {
				s.logger.Warn().Err(err).Str("id", id).Msg("error detaching eBPF filter during attach rollback")
			}
		}
		if rowSaved {
			if err := s.store.DeleteAttachment(id); err != nil {
				s.logger.Error().Err(err).Str("id", id).Msg("error deleting attachment from store during attach rollback")
			}
		}
		s.mu.Lock()
		s.releasePort(port)
		s.mu.Unlock()
	}()

	expectedIdentity, err := s.targetIdentity(attachType, target)
	if err != nil {
		return nil, fmt.Errorf("resolving target identity before filter attachment: %w", err)
	}

	ebpfFilter, err = s.newFilter(s.pinDirFor(id), target, attachType, mode, direction, s.maxRuleEntries)
	if err != nil {
		return nil, fmt.Errorf("creating eBPF filter: %w", err)
	}
	if err := s.validateTargetIdentity(attachType, target, expectedIdentity); err != nil {
		return nil, err
	}

	var proxyFunc DnsProxyFunc
	if cpClient := s.cpClient.Load(); cpClient != nil {
		proxyFunc = cpClient.MakeProxyFunc(id)
	}
	sink := s.newDNSFilterSink(id, ebpfFilter, ttls)
	dnsServer = NewDNSServer(id, dnsAddr, s.cfg.DNS.Upstream, s.logger, sink, proxyFunc)
	if err := dnsServer.Start(); err != nil {
		dnsServer = nil // never started; nothing to stop
		return nil, fmt.Errorf("starting DNS server: %w", err)
	}

	// Persist only after the enforcing resources (filter + DNS) exist: a
	// crash before this point leaves no store row, so restore never
	// resurrects an attachment that was never enforcing.
	if err := s.store.SaveAttachment(attachment); err != nil {
		return nil, fmt.Errorf("saving attachment: %w", err)
	}
	rowSaved = true

	state := &attachmentState{info: attachment, dns: dnsServer, filter: ebpfFilter, ttls: ttls}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("daemon is stopping")
	}
	if existingID, ok := s.targetIndex[target]; ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("target already attached: %s (%s)", target, existingID)
	}
	s.attachments[id] = state
	s.targetIndex[target] = id
	// Arm the post-registration rollback regime while still under s.mu, so the
	// deferred cleanup can never observe a publicly-registered attachment with
	// registered still nil.
	registered = state
	var (
		token    watchToken
		watchErr = s.validateTargetIdentity(attachType, target, expectedIdentity)
	)
	if watchErr == nil {
		switch attachType {
		case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
			token, watchErr = s.watcher.WatchInterface(target, expectedIdentity)
		case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
			token, watchErr = s.watcher.WatchCgroup(target, expectedIdentity)
		}
	}
	if watchErr == nil {
		state.watch = token
	}
	s.mu.Unlock()
	if watchErr != nil {
		s.logger.Error().Err(watchErr).Str("target", target).Msg("failed to watch target")
		return nil, fmt.Errorf("watching target: %w", watchErr)
	}

	logEvent := s.logger.Info().
		Str("id", id).
		Str("target", target).
		Str("type", attachType.String()).
		Str("dns_address", dnsAddr)
	if attachType == apiv1.AttachmentType_ATTACHMENT_TYPE_TC {
		logEvent = logEvent.Str("direction", direction.String())
	}
	logEvent.Msg("attached filter")

	if cpClient := s.cpClient.Load(); cpClient != nil {
		sub := subscribedFromAttachment(attachment)

		// s.mu is NOT held here: SubscribeAndWait can block for the full
		// subscribe_ack_timeout.
		if _, err := cpClient.SubscribeAndWait(ctx, sub); err != nil {
			s.logger.Error().Err(err).Str("id", id).Msg("control plane subscription failed, detaching")
			notifyCP = true
			return nil, fmt.Errorf("control plane subscription failed: %w", err)
		}
	}

	// Commit: the attachment must still be live. A concurrent Detach or
	// target removal during the (unlocked) subscribe wait tears the
	// attachment down completely — returning success then would hand the
	// caller an attachment that nothing is enforcing. The rollback above is
	// a guaranteed no-op in that case (ownership check), so this error path
	// never double-frees.
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("daemon is stopping")
	}
	if s.attachments[id] != registered {
		s.mu.Unlock()
		return nil, fmt.Errorf("attachment was detached during setup: %s", id)
	}
	committed = true
	s.mu.Unlock()

	return &apiv1.AttachResponse{
		Id:         id,
		DnsAddress: dnsAddr,
	}, nil
}

func (s *Server) Detach(ctx context.Context, req *apiv1.DetachRequest) (*emptypb.Empty, error) {
	s.mu.RLock()
	state, ok := s.attachments[req.Id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("attachment not found: %s", req.Id)
	}

	// Never hold Server.mu while waiting: an ack that won reconcileMu may be
	// inside a server method that needs Server.mu. After acquiring the exact
	// state lock, revalidate registration before claiming teardown ownership.
	state.reconcileMu.Lock()
	defer state.reconcileMu.Unlock()
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("daemon is stopping")
	}
	if s.attachments[req.Id] != state {
		s.mu.Unlock()
		return nil, fmt.Errorf("attachment not found: %s", req.Id)
	}

	port := extractPort(state.info.DnsAddress)
	if port > 0 {
		s.releasePort(port)
	}

	switch parseAttachmentType(state.info.Type) {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.UnwatchInterface(state.watch)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		s.watcher.UnwatchCgroup(state.watch)
	}

	delete(s.attachments, req.Id)
	delete(s.targetIndex, state.info.Target)
	s.mu.Unlock()

	// Remove any exact pending Subscribed handshake before resource teardown.
	// The waiter (a new Attach) is unblocked with an error; a background
	// restore attempt simply retains needsResync for a later connection.
	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.cancelSubscription(req.Id, fmt.Errorf("attachment detached"))
	}

	// Drop TTL bookkeeping so an in-flight janitor sweep does not keep
	// retrying removals against the filter we are about to close.
	state.ttls.purge()

	if state.dns != nil {
		if err := state.dns.Stop(); err != nil {
			s.logger.Warn().Err(err).Str("id", req.Id).Msg("error stopping DNS server")
		}
	}

	if state.filter != nil {
		// Explicit detach destroys the attachment for good: unpin + close so
		// no bpffs state or kernel links survive.
		if err := state.filter.Detach(); err != nil {
			s.logger.Warn().Err(err).Str("id", req.Id).Msg("error detaching eBPF filter")
		}
	}

	if err := s.store.DeleteAttachment(req.Id); err != nil {
		s.logger.Error().Err(err).Str("id", req.Id).Msg("error deleting attachment from store")
	}

	s.logger.Info().
		Str("id", req.Id).
		Str("target", state.info.Target).
		Msg("detached filter")

	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
			Id:     req.Id,
			Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_DETACHED,
		})
	}

	return &emptypb.Empty{}, nil
}

func (s *Server) List(ctx context.Context, req *apiv1.ListRequest) (*apiv1.ListResponse, error) {
	attachments, nextToken, total, err := s.store.ListAttachments(int(req.PageSize), req.PageToken)
	if err != nil {
		return nil, fmt.Errorf("listing attachments: %w", err)
	}

	statsRefs := make(map[string]attachmentStatsRef, len(attachments))
	s.mu.RLock()
	for _, a := range attachments {
		if state := s.attachments[a.ID]; state != nil {
			statsRefs[a.ID] = attachmentStatsRef{
				id:     a.ID,
				filter: state.filter,
				dns:    state.dns,
			}
		}
	}
	s.mu.RUnlock()

	var infos []*apiv1.AttachmentInfo
	for _, a := range attachments {
		info := &apiv1.AttachmentInfo{
			Id:         a.ID,
			Target:     a.Target,
			Type:       parseAttachmentType(a.Type),
			Mode:       parsePolicyMode(a.Mode),
			DnsMode:    parseDnsMode(a.DnsMode),
			DnsAddress: a.DnsAddress,
			Metadata:   a.Metadata,
			AttachedAt: timestamppb.New(a.AttachedAt),
		}
		if info.Type == apiv1.AttachmentType_ATTACHMENT_TYPE_TC {
			info.TcDirection = parseTcDirection(a.Direction)
		}
		if refs, ok := statsRefs[a.ID]; ok {
			if refs.filter != nil {
				if stats, err := refs.filter.GetStats(); err == nil {
					info.PacketsAllowed = stats.Allowed
					info.PacketsBlocked = stats.Blocked
				}
			}
			if refs.dns != nil {
				info.DnsQueriesAllowed, info.DnsQueriesBlocked = refs.dns.Stats()
			}
		}
		infos = append(infos, info)
	}

	return &apiv1.ListResponse{
		Attachments:   infos,
		NextPageToken: nextToken,
		TotalCount:    int32(total),
	}, nil
}

func (s *Server) GetStatus(ctx context.Context, _ *emptypb.Empty) (*apiv1.DaemonStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cpState := apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED
	cpAddr := ""
	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpState = cpClient.State()
		cpAddr = s.cfg.ControlPlane.URL
	}

	return &apiv1.DaemonStatus{
		Version:             s.version,
		DaemonId:            s.daemonID,
		Hostname:            s.hostname,
		ControlPlaneState:   cpState,
		ControlPlaneAddress: cpAddr,
		AttachmentCount:     int32(len(s.attachments)),
	}, nil
}

func (s *Server) GetSyncAttachments() []*apiv1.Attachment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var attachments []*apiv1.Attachment
	for _, state := range s.attachments {
		a := state.info
		att := &apiv1.Attachment{
			Id:       a.ID,
			Target:   a.Target,
			Type:     parseAttachmentType(a.Type),
			Mode:     parsePolicyMode(a.Mode),
			DnsMode:  parseDnsMode(a.DnsMode),
			Metadata: a.Metadata,
		}
		if att.Type == apiv1.AttachmentType_ATTACHMENT_TYPE_TC {
			att.TcDirection = parseTcDirection(a.Direction)
		}
		attachments = append(attachments, att)
	}
	return attachments
}

// restoreResyncSubscription binds a complete Subscribed snapshot to the exact
// restored attachmentState it represents. The pointer is an ownership token:
// success may clear needsResync only while that same state is still registered.
type restoreResyncSubscription struct {
	state *attachmentState
	sub   *apiv1.Subscribed
}

// GetRestoreResyncSubscriptions snapshots the restored attachments that still
// need authoritative control-plane state. It performs no mutation and is safe
// when no control plane is configured: the flags simply remain set while the
// kernel continues enforcing the restored last-known policy.
func (s *Server) GetRestoreResyncSubscriptions() []restoreResyncSubscription {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resyncs := make([]restoreResyncSubscription, 0)
	if s.stopping {
		return resyncs
	}
	for _, state := range s.attachments {
		if !state.needsResync {
			continue
		}
		resyncs = append(resyncs, restoreResyncSubscription{
			state: state,
			sub:   subscribedFromAttachment(state.info),
		})
	}
	return resyncs
}

func (s *Server) getAttachmentState(id string) *attachmentState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stopping {
		return nil
	}
	return s.attachments[id]
}

func (s *Server) attachmentStateStillLive(id string, expected *attachmentState) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.stopping && expected != nil && s.attachments[id] == expected
}

func (s *Server) attachmentStatePresent(id string, expected *attachmentState) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return expected != nil && s.attachments[id] == expected
}

// restoreResyncStillNeeded validates the exact-state ownership token before a
// pending restore ack is registered or applied.
func (s *Server) restoreResyncStillNeeded(id string, expected *attachmentState) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.attachments[id]
	return !s.stopping && state == expected && state != nil && state.needsResync
}

// clearRestoreResync marks an authoritative restore ack complete only if the
// same attachmentState is still live. A detach/replacement race therefore
// cannot clear a newer state's flag or resurrect removed bookkeeping.
func (s *Server) clearRestoreResync(id string, expected *attachmentState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.attachments[id]
	if s.stopping || state != expected || state == nil || !state.needsResync {
		return false
	}
	state.needsResync = false
	return true
}

func (s *Server) GetAttachmentStats() []*apiv1.AttachmentStats {
	refs := s.snapshotAttachmentStats()

	var stats []*apiv1.AttachmentStats
	for _, ref := range refs {
		stat := &apiv1.AttachmentStats{
			Id: ref.id,
		}
		if ref.filter != nil {
			if filterStats, err := ref.filter.GetStats(); err == nil {
				stat.PacketsAllowed = filterStats.Allowed
				stat.PacketsBlocked = filterStats.Blocked
			}
		}
		if ref.dns != nil {
			stat.DnsQueriesAllowed, stat.DnsQueriesBlocked = ref.dns.Stats()
		}
		stat.MapFullDrops = ref.ttls.mapFullCount()
		stats = append(stats, stat)
	}
	return stats
}

type attachmentStatsRef struct {
	id     string
	filter filter.Filter
	dns    *DNSServer
	ttls   *ttlRegistry
}

func (s *Server) snapshotAttachmentStats() []attachmentStatsRef {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refs := make([]attachmentStatsRef, 0, len(s.attachments))
	for id, state := range s.attachments {
		refs = append(refs, attachmentStatsRef{
			id:     id,
			filter: state.filter,
			dns:    state.dns,
			ttls:   state.ttls,
		})
	}
	return refs
}

func (s *Server) DaemonID() string {
	return s.daemonID
}

func (s *Server) Hostname() string {
	return s.hostname
}

func (s *Server) SetDnsMode(id string, mode apiv1.DnsMode) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	dnsServer := state.dns
	s.mu.RUnlock()

	if dnsServer != nil {
		dnsServer.SetMode(mode)
	}

	s.mu.Lock()
	state, ok = s.attachments[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	state.info.DnsMode = mode.String()
	attachment := cloneAttachment(state.info)
	s.mu.Unlock()

	if err := s.store.SaveAttachment(attachment); err != nil {
		return fmt.Errorf("saving DNS mode: %w", err)
	}
	return nil
}

func (s *Server) AllowDomain(id string, domain string, includeSubdomains bool) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	dnsServer := state.dns
	s.mu.RUnlock()

	if dnsServer != nil {
		dnsServer.AllowDomain(domain, includeSubdomains)
	}
	return nil
}

func (s *Server) DenyDomain(id string, domain string, includeSubdomains bool) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	dnsServer := state.dns
	s.mu.RUnlock()

	if dnsServer != nil {
		dnsServer.DenyDomain(domain, includeSubdomains)
	}
	return nil
}

func (s *Server) RemoveDomain(id string, domain string) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	dnsServer := state.dns
	s.mu.RUnlock()

	if dnsServer != nil {
		dnsServer.RemoveDomain(domain)
	}
	return nil
}

func (s *Server) ReplaceDNSRules(id string, mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	dnsServer := state.dns
	s.mu.RUnlock()

	if dnsServer != nil {
		dnsServer.ReplaceRules(mode, allowDomains, denyDomains)
	}

	s.mu.Lock()
	state, ok = s.attachments[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	state.info.DnsMode = mode.String()
	attachment := cloneAttachment(state.info)
	s.mu.Unlock()

	if err := s.store.SaveAttachment(attachment); err != nil {
		return fmt.Errorf("saving DNS rules: %w", err)
	}
	return nil
}

func (s *Server) ClearRules(id string) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	ebpfFilter := state.filter
	reg := state.ttls
	s.mu.RUnlock()

	// Clearing goes through the TTL registry so tracked entries (including
	// DNS-populated IPs) are purged atomically with the filter wipe — the
	// janitor must never "expire" an entry that a clear (e.g. bulk update)
	// already removed or that a rebuild re-added as permanent, and cleared
	// DNS IPs must be re-addable on the next resolution.
	return reg.clear(ebpfFilter)
}

func (s *Server) SetFilterMode(id string, mode apiv1.PolicyMode) error {
	s.mu.RLock()
	state, ok := s.attachments[id]
	if !ok {
		s.mu.RUnlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	ebpfFilter := state.filter
	s.mu.RUnlock()

	if ebpfFilter != nil {
		if err := ebpfFilter.SetMode(apiModeToFilterMode(mode)); err != nil {
			return err
		}
	}

	s.mu.Lock()
	state, ok = s.attachments[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	state.info.Mode = mode.String()
	attachment := cloneAttachment(state.info)
	s.mu.Unlock()

	if err := s.store.SaveAttachment(attachment); err != nil {
		return fmt.Errorf("saving filter mode: %w", err)
	}
	return nil
}

// AllowCIDR adds the CIDR to the attachment's allowlist under the registry's
// max-deadline / permanent-pin model (see ttlRegistry): a ttl > 0 schedules
// removal by the TTL janitor, with a re-add only ever EXTENDING an existing
// deadline to the later of the two (never shortening it); ttl <= 0 pins the
// entry permanent, and a permanent entry is never demoted by a later TTL'd
// re-add. Use RemoveAllowedCIDR to drop an entry early.
func (s *Server) AllowCIDR(id string, cidr *net.IPNet, ttl time.Duration) error {
	ebpfFilter, reg, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	return reg.addCP(ebpfFilter, cidr, listAllow, ttl, s.now())
}

// DenyCIDR adds the CIDR to the attachment's denylist. TTL semantics match
// AllowCIDR.
func (s *Server) DenyCIDR(id string, cidr *net.IPNet, ttl time.Duration) error {
	ebpfFilter, reg, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	return reg.addCP(ebpfFilter, cidr, listDeny, ttl, s.now())
}

func (s *Server) RemoveAllowedCIDR(id string, cidr *net.IPNet) error {
	ebpfFilter, reg, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	return reg.remove(ebpfFilter, cidr, listAllow)
}

func (s *Server) RemoveDeniedCIDR(id string, cidr *net.IPNet) error {
	ebpfFilter, reg, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	return reg.remove(ebpfFilter, cidr, listDeny)
}

// ReconcileCIDRs applies a bulk update — target mode plus declared CIDR
// sets — as add/remove deltas against the registry's live CP entries (see
// ttlRegistry.reconcileCP), in an order that is window-free for EVERY mode
// pair. The BPF program consults exactly one rule map per mode (allowlist
// -> allowed_*, denylist -> denied_*, block-all/disabled -> none), so:
//
//  1. The list the NEW mode consults is reconciled first — adds AND
//     removes. During a mode flip that list is inert under the OLD mode, so
//     correcting it opens no window; on a same-mode resync this is the live
//     list, and survivor dedup means a rule present before and after is
//     never touched.
//  2. The mode is flipped only once the map it will read is fully correct.
//     (Without this order, e.g. allowlist->denylist would consult a
//     still-empty deny map and fail OPEN until the deny rules landed.)
//  3. The other list is reconciled last — inert under the NEW mode, so its
//     churn (e.g. stale allow entries that would otherwise sit live at a
//     later flip back) is harmless.
//
// DNS-populated entries absent from the declared set stay in the filter
// until their own DNS TTL lapses. Per-CIDR failures (e.g. map-full) are
// aggregated, not aborting the rest of the reconcile.
func (s *Server) ReconcileCIDRs(id string, mode apiv1.PolicyMode, allow, deny []parsedCIDR) error {
	ebpfFilter, reg, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}

	// Which list does the new mode consult? Denylist reads denied_*;
	// allowlist reads allowed_*; block-all/disabled read neither, so the
	// order is arbitrary — allow-first, deterministically.
	first, second := listAllow, listDeny
	firstSet, secondSet := allow, deny
	if mode == apiv1.PolicyMode_POLICY_MODE_DENYLIST {
		first, second = listDeny, listAllow
		firstSet, secondSet = deny, allow
	}

	firstErr := reg.reconcileCP(ebpfFilter, first, firstSet, s.now())
	modeErr := s.SetFilterMode(id, mode)
	secondErr := reg.reconcileCP(ebpfFilter, second, secondSet, s.now())
	return errors.Join(firstErr, modeErr, secondErr)
}

// filterAndRegistry snapshots an attachment's filter and TTL registry under
// s.mu. Callers then operate under the registry's own lock only, so s.mu is
// never held across filter syscalls.
func (s *Server) filterAndRegistry(id string) (filter.Filter, *ttlRegistry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.attachments[id]
	if !ok {
		return nil, nil, fmt.Errorf("attachment not found: %s", id)
	}
	return state.filter, state.ttls, nil
}

func (s *Server) allocatePort() (int, error) {
	for port, inUse := range s.portPool {
		if !inUse {
			s.portPool[port] = true
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available DNS ports in range %d-%d", s.cfg.DNS.PortMin, s.cfg.DNS.PortMax)
}

func (s *Server) releasePort(port int) {
	if _, ok := s.portPool[port]; ok {
		s.portPool[port] = false
	}
}

func extractPort(addr string) int {
	_, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return 0
	}
	return port
}

func cloneAttachment(a *store.Attachment) *store.Attachment {
	if a == nil {
		return nil
	}
	clone := *a
	if a.Metadata != nil {
		clone.Metadata = make(map[string]string, len(a.Metadata))
		for k, v := range a.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// subscribedFromAttachment builds the complete control-plane snapshot used by
// both a brand-new Attach and a restored-attachment re-sync. Keeping one builder
// prevents restart handshakes from silently omitting fields the initial
// subscription carries (notably DNS address, metadata, and TC direction).
func subscribedFromAttachment(a *store.Attachment) *apiv1.Subscribed {
	if a == nil {
		return nil
	}
	metadata := make(map[string]string, len(a.Metadata))
	for key, value := range a.Metadata {
		metadata[key] = value
	}
	return &apiv1.Subscribed{
		Id:          a.ID,
		Target:      a.Target,
		Type:        parseAttachmentType(a.Type),
		Mode:        parsePolicyMode(a.Mode),
		DnsMode:     parseDnsMode(a.DnsMode),
		DnsAddress:  a.DnsAddress,
		Metadata:    metadata,
		TcDirection: parseTcDirection(a.Direction),
	}
}

func parseAttachmentType(s string) apiv1.AttachmentType {
	if v, ok := apiv1.AttachmentType_value[s]; ok {
		return apiv1.AttachmentType(v)
	}
	return apiv1.AttachmentType_ATTACHMENT_TYPE_UNSPECIFIED
}

// filterModeToAPIMode is the inverse of apiModeToFilterMode.
func filterModeToAPIMode(mode filter.PolicyMode) apiv1.PolicyMode {
	switch mode {
	case filter.ModeAllowlist:
		return apiv1.PolicyMode_POLICY_MODE_ALLOWLIST
	case filter.ModeBlockAll:
		return apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL
	case filter.ModeDenylist:
		return apiv1.PolicyMode_POLICY_MODE_DENYLIST
	default:
		return apiv1.PolicyMode_POLICY_MODE_DISABLED
	}
}

func parsePolicyMode(s string) apiv1.PolicyMode {
	if v, ok := apiv1.PolicyMode_value[s]; ok {
		return apiv1.PolicyMode(v)
	}
	return apiv1.PolicyMode_POLICY_MODE_UNSPECIFIED
}

func parseDnsMode(s string) apiv1.DnsMode {
	if v, ok := apiv1.DnsMode_value[s]; ok {
		return apiv1.DnsMode(v)
	}
	return apiv1.DnsMode_DNS_MODE_UNSPECIFIED
}

// parseTcDirection maps a persisted direction to the API enum. Empty (rows
// predating the direction column, or cgroup attachments) and unknown values
// default to EGRESS, which preserves pre-direction behavior.
func parseTcDirection(s string) apiv1.TcDirection {
	if v, ok := apiv1.TcDirection_value[s]; ok && apiv1.TcDirection(v) == apiv1.TcDirection_TC_DIRECTION_INGRESS {
		return apiv1.TcDirection_TC_DIRECTION_INGRESS
	}
	return apiv1.TcDirection_TC_DIRECTION_EGRESS
}
