package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	commandWG   sync.WaitGroup
	dnsWatchWG  sync.WaitGroup
	portPool    map[int]bool
	attachments map[string]*attachmentState
	targetIndex map[string]string // target -> attachment ID (for reverse lookup on removal)

	cpClient     atomic.Pointer[ControlPlaneClient]
	watcher      *TargetWatcher
	startWatcher func() error
	stopWatcher  func()

	// TTL janitor state. now is injectable for deterministic tests.
	now                func() time.Time
	ttlJanitorInterval time.Duration
	janitorStop        chan struct{}
	janitorStopOnce    sync.Once
	janitorWG          sync.WaitGroup

	// dnsMinFilterTTL floors the lifetime of DNS-resolved IPs in the filter
	// (see config dns.min_filter_ttl).
	dnsMinFilterTTL time.Duration
	// dnsListenIP is the concrete, startup-resolved listener address returned
	// to workloads and protected in each attachment's allow map. Wildcard
	// listeners are rejected because they are not usable resolver endpoints.
	dnsListenIP string
	// defaultDNSUpstream is the validated/canonical daemon-global fallback for
	// attachments whose authoritative DNS config has no overrides.
	defaultDNSUpstream string
	// maxRuleEntries sizes each eBPF rule map at filter load time
	// (see config filter.max_rule_entries; 0 = compiled-in default).
	maxRuleEntries uint32
	// maxDNSRuleEntries independently sizes each exact DNS-derived host map.
	maxDNSRuleEntries uint32
	// dnsAdmissionCeilings are both the zero-value per-attachment defaults and
	// hard daemon ceilings for bounded resolver ownership metadata.
	dnsAdmissionCeilings dnsAdmissionLimits
	// dnsChurnCeiling bounds the rolling per-attachment exact admission/LRU
	// budget. Its window is immutable for this daemon generation.
	dnsChurnCeiling dnsChurnLimits

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
	// targetPresence reports whether an attachment target is still present
	// (production: targetPresent; a seam so unit tests can restore
	// attachments whose fake targets never existed).
	targetPresence func(attachType apiv1.AttachmentType, target string) (bool, error)
	// targetIdentity resolves the kernel object an attachment name/path
	// currently denotes (ifindex or cgroup id). Attach validates this identity
	// across filter construction and watcher registration so a same-name/path
	// replacement can never bind the filter and watcher to different objects.
	targetIdentity func(attachType apiv1.AttachmentType, target string) (uint64, error)
	// watchTarget registers the exact target identity with the shared watcher.
	// Keeping this boundary injectable lets restore tests distinguish ambiguous
	// registration I/O from a typed identity change on every build platform.
	watchTarget func(attachType apiv1.AttachmentType, target string, identity uint64) (watchToken, error)
	// resolveDNSListenIP canonicalizes configured/persisted listener hostnames
	// once per attachment restore. It is a seam for deterministic dual-stack
	// and DNS-change tests; production uses resolveConcreteDNSListenIP.
	resolveDNSListenIP func(string) (string, error)
	// bindDNSServer and serveDNSServer keep restore/attach rollback tests able
	// to exercise each half of the dual-protocol listener lifecycle without
	// weakening DNSServer's concrete production implementation.
	bindDNSServer  func(*DNSServer) error
	serveDNSServer func(*DNSServer) error
	// Attachment-store seams let rollback tests inject a one-shot primary
	// failure while keeping degraded-state persistence available. Production
	// always uses the Store methods directly through these fields.
	saveAttachment   func(*store.Attachment) error
	deleteAttachment func(string) error
	// removePinDir is the restart cleanup primitive for durable tombstones.
	// Removing every bpffs entry drops the persistent kernel references even
	// though the userspace handles belonged to the previous process.
	removePinDir     func(string) error
	readPinRoot      func(string) ([]os.DirEntry, error)
	validatePinRoot  func(string) error
	inspectPinSchema func(string) (filter.PinnedSchemaState, error)
	// mutationAdmissionHook is a test-only seam invoked after the drain RLock
	// is held but before the serialized mutation section is acquired.
	mutationAdmissionHook func(string, *attachmentState)
}

type attachmentState struct {
	// mutationMu is the exact-state admission/drain barrier. Ordinary filter,
	// DNS, TTL, and stats work holds it for reading after revalidating live
	// ownership. Teardown first closes admission under Server.mu, then takes it
	// for writing to drain all earlier work before closing filter handles.
	mutationMu sync.RWMutex
	// mutationSerialMu makes the admitted mutation section single-writer even
	// though mutationMu remains an admission/drain RW barrier. This is required
	// for rollback quarantine: once one operation stages BLOCK_ALL and closes
	// admission, no previously admitted mode write can run afterward and reopen
	// policy before the writer-side quarantine drain.
	mutationSerialMu sync.Mutex
	mutationsClosed  bool // guarded by Server.mu

	info    *store.Attachment
	dns     *DNSServer
	dnsSink *dnsFilterSink
	filter  filter.Filter
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
	// Fresh Attach keeps the staged filter BLOCK_ALL until setup commits.
	// A fire-and-forget attach-purpose SubscribedAck waits on setupDone before
	// it may mutate policy; teardown closes it with setupCommitted false.
	setupDone      chan struct{}
	setupDoneOnce  sync.Once
	setupCommitted atomic.Bool
	dnsWatchOnce   sync.Once
	// cleanupNeeded marks a failed Attach/Detach whose target, port, and
	// durable BLOCK_ALL row are deliberately retained until destructive
	// cleanup can be retried. Ordinary policy/DNS commands must reject it.
	cleanupNeeded bool // guarded by Server.mu
}

func (s *attachmentState) finishSetup(committed bool) {
	if s == nil || s.setupDone == nil {
		return
	}
	if committed {
		s.setupCommitted.Store(true)
	}
	s.setupDoneOnce.Do(func() { close(s.setupDone) })
}

// beginAttachmentMutation admits one exact-state operation and returns a
// release callback. The double check around mutationMu closes the snapshot
// race with teardown: once teardown publishes mutationsClosed, no waiter can
// pass the second check, while already-admitted readers are drained before
// any filter/DNS handle is closed.
func (s *Server) beginAttachmentMutation(id string) (*attachmentState, func(), error) {
	s.mu.RLock()
	state := s.attachments[id]
	allowStopping := attachmentSetupApplyInProgress(state)
	if s.stopping && !allowStopping {
		s.mu.RUnlock()
		return nil, nil, fmt.Errorf("daemon is stopping")
	}
	if state == nil {
		s.mu.RUnlock()
		return nil, nil, fmt.Errorf("attachment not found: %s", id)
	}
	if state.cleanupNeeded || state.mutationsClosed {
		s.mu.RUnlock()
		return nil, nil, fmt.Errorf("attachment %s is not accepting mutations", id)
	}
	s.mu.RUnlock()

	state.mutationMu.RLock()
	if s.mutationAdmissionHook != nil {
		s.mutationAdmissionHook(id, state)
	}
	state.mutationSerialMu.Lock()
	s.mu.RLock()
	live := (!s.stopping || attachmentSetupApplyInProgress(state)) && s.attachments[id] == state && !state.cleanupNeeded && !state.mutationsClosed
	s.mu.RUnlock()
	if !live {
		state.mutationSerialMu.Unlock()
		state.mutationMu.RUnlock()
		return nil, nil, fmt.Errorf("attachment %s is not accepting mutations", id)
	}
	return state, func() {
		state.mutationSerialMu.Unlock()
		state.mutationMu.RUnlock()
	}, nil
}

func (s *Server) beginControlCommand(_ string) (func(), bool) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, false
	}
	s.commandWG.Add(1)
	s.mu.Unlock()
	return func() {
		s.commandWG.Done()
	}, true
}

func attachmentSetupApplyInProgress(state *attachmentState) bool {
	if state == nil || state.setupDone == nil || !state.setupCommitted.Load() {
		return false
	}
	select {
	case <-state.setupDone:
		return false
	default:
		return true
	}
}

func (s *Server) startDNSLifecycleWatch(id string, state *attachmentState) {
	if state == nil || state.dns == nil || state.dns.Done() == nil {
		return
	}
	state.dnsWatchOnce.Do(func() {
		s.dnsWatchWG.Add(1)
		go func(dnsServer *DNSServer) {
			defer s.dnsWatchWG.Done()
			<-dnsServer.Done()
			fatalErr := dnsServer.Err()
			if fatalErr == nil {
				return // intentional Stop/cleanup
			}

			state.reconcileMu.Lock()
			defer state.reconcileMu.Unlock()
			s.mu.RLock()
			live := !s.stopping && s.attachments[id] == state && state.dns == dnsServer && !state.cleanupNeeded && !state.mutationsClosed
			s.mu.RUnlock()
			if !live {
				return
			}
			quarantineErr := s.quarantineAttachment(id, state)
			s.logger.Error().Err(errors.Join(fatalErr, quarantineErr)).Str("id", id).
				Msg("attachment DNS listener died; attachment quarantined block-all")
			if cpClient := s.cpClient.Load(); cpClient != nil {
				cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
					Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR,
					Error: "attachment DNS listener died",
				})
			}
		}(state.dns)
	})
}

func dnsServerSetupError(dnsServer *DNSServer) error {
	if dnsServer == nil || dnsServer.Done() == nil {
		return nil
	}
	select {
	case <-dnsServer.Done():
		if err := dnsServer.Err(); err != nil {
			return err
		}
		return fmt.Errorf("DNS server stopped during attachment setup")
	default:
		return nil
	}
}

type restoreStartResource struct {
	id                   string
	state                *attachmentState
	filter               filter.Filter
	dns                  *DNSServer
	adopted              bool
	bootstrap            *net.IPNet
	bootstrapInstalled   bool
	watch                watchToken
	originalDNSAddress   string
	originalPinDir       string
	originalPinPathKnown bool
	canonicalDNSAddress  string
	addressPersisted     bool
	pinIdentityChanged   bool
}

// rollbackRestoreStart unwinds every userspace resource acquired by this
// Start invocation. Adopted filters are only Closed (pins/links remain), while
// recreated staged filters are Detached. Called with Server.mu held.
func (s *Server) rollbackRestoreStart(resources []*restoreStartResource) error {
	var rollbackErrs []error
	persistBlockAll := func(resource *restoreStartResource, cause string) {
		resource.state.info.Mode = apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String()
		if saveErr := s.saveAttachment(cloneAttachment(resource.state.info)); saveErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("persisting block-all for %s after %s: %w", resource.id, cause, saveErr))
		}
	}
	persistCleanup := func(resource *restoreStartResource, cause string) {
		resource.state.info.Mode = apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String()
		resource.state.info.CleanupNeeded = true
		resource.state.cleanupNeeded = true
		if saveErr := s.saveAttachment(cloneAttachment(resource.state.info)); saveErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("persisting cleanup tombstone for %s after %s: %w", resource.id, cause, saveErr))
		}
	}
	forceBlockAll := func(resource *restoreStartResource, cause string) {
		if modeErr := resource.filter.SetMode(filter.ModeBlockAll); modeErr != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("forcing %s block-all after %s: %w", resource.id, cause, modeErr))
			s.logger.Error().Err(modeErr).Str("id", resource.id).Msg("failed to force block-all during startup rollback")
		}
		// Persist the desired fail-closed recovery state even when the immediate
		// map write failed; the returned error makes that ambiguity observable.
		persistBlockAll(resource, cause)
	}
	for i := len(resources) - 1; i >= 0; i-- {
		resource := resources[i]
		if resource.watch.valid() {
			switch parseAttachmentType(resource.state.info.Type) {
			case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
				s.watcher.UnwatchInterface(resource.watch)
			case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
				s.watcher.UnwatchCgroup(resource.watch)
			}
		}
		if resource.dns != nil {
			if err := resource.dns.Stop(); err != nil {
				s.logger.Warn().Err(err).Str("id", resource.id).Msg("failed to stop DNS during startup rollback")
				rollbackErrs = append(rollbackErrs, fmt.Errorf("stopping DNS for %s: %w", resource.id, err))
			}
		}
		// Adopted maps survive rollback, so precisely remove the system rule
		// added by this Start. Recreated maps are destroyed wholesale below;
		// attempting a per-rule compensation first can spuriously persist
		// BLOCK_ALL even when Detach cleanly removes all staged enforcement.
		if resource.adopted && resource.bootstrapInstalled {
			if err := resource.state.ttls.removeSystem(resource.filter, resource.bootstrap, listAllow); err != nil {
				s.logger.Error().Err(err).Str("id", resource.id).Msg("failed to restore pre-start DNS bootstrap state")
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restoring bootstrap for %s: %w", resource.id, err))
				// A failed removal would otherwise leave a newly broadened allowlist
				// pinned after startup abort. Force the effective mode fail-closed.
				forceBlockAll(resource, "bootstrap removal failure")
			}
		}
		if resource.filter != nil {
			if resource.adopted {
				if err := resource.filter.Close(); err != nil {
					s.logger.Warn().Err(err).Str("id", resource.id).Msg("failed to close adopted filter during startup rollback")
					rollbackErrs = append(rollbackErrs, fmt.Errorf("closing adopted filter for %s: %w", resource.id, err))
				}
			} else {
				// Detach may close map FDs even when unpinning fails, so stage the
				// surviving map fail-closed while it is certainly still writable.
				// A successful Detach discards this staged mode and preserves the
				// original store row; only ambiguous cleanup is persisted BLOCK_ALL.
				preDetachModeErr := resource.filter.SetMode(filter.ModeBlockAll)
				if detachErr := resource.filter.Detach(); detachErr != nil {
					s.logger.Warn().Err(detachErr).Str("id", resource.id).Msg("failed to detach recreated filter during startup rollback")
					rollbackErrs = append(rollbackErrs, fmt.Errorf("detaching recreated filter for %s: %w", resource.id, detachErr))
					if preDetachModeErr != nil {
						rollbackErrs = append(rollbackErrs, fmt.Errorf("forcing %s block-all before failed detach: %w", resource.id, preDetachModeErr))
					}
					persistCleanup(resource, "recreated filter detach failure")
				}
				resource.state.ttls = newTTLRegistry()
			}
		}
		resource.state.filter = nil
		resource.state.dns = nil
		resource.state.watch = watchToken{}
		resource.state.needsResync = false
		// A failed recreated Detach is now a durable cleanup tombstone and must
		// retain the exact pin identity used by that failed attempt. Ordinary
		// startup rollback restores the pre-Start row exactly.
		if !resource.state.cleanupNeeded {
			if resource.originalDNSAddress != "" {
				resource.state.info.DnsAddress = resource.originalDNSAddress
			}
			resource.state.info.PinDir = resource.originalPinDir
			resource.state.info.PinPathKnown = resource.originalPinPathKnown
		}
		if resource.addressPersisted && !resource.state.cleanupNeeded {
			if err := s.saveAttachment(cloneAttachment(resource.state.info)); err != nil {
				s.logger.Error().Err(err).Str("id", resource.id).Msg("failed to restore persisted attachment identity during startup rollback")
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restoring persisted attachment identity for %s: %w", resource.id, err))
			}
		}
	}
	return errors.Join(rollbackErrs...)
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
	var maxDNSRuleEntries uint32
	if cfg.Filter.MaxDNSRuleEntries > 0 {
		maxDNSRuleEntries = uint32(cfg.Filter.MaxDNSRuleEntries)
	}
	dnsAdmissionCeilings := resolveDNSAdmissionCeilings(maxDNSRuleEntries, dnsAdmissionLimitOverrides{
		maxIPsPerFamily:       uint32(cfg.DNS.MaxIPsPerFamily),
		maxIPsPerResponse:     uint32(cfg.DNS.MaxIPsPerResponse),
		maxIPsPerPolicyDomain: uint32(cfg.DNS.MaxIPsPerPolicyDomain),
		maxTrackedDomains:     uint32(cfg.DNS.MaxTrackedDomains),
		maxOwnershipEdges:     uint32(cfg.DNS.MaxOwnershipEdges),
	})
	dnsChurnCeiling := resolveDNSChurnCeiling(uint32(cfg.DNS.MaxChurnUnits), cfg.DNS.ChurnWindow)
	dnsListenIP, err := resolveConcreteDNSListenIP(cfg.DNS.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolving dns.listen_addr: %w", err)
	}
	defaultUpstreams, err := normalizeUpstreamServers(nil, cfg.DNS.Upstream)
	if err != nil {
		return nil, fmt.Errorf("validating dns.upstream: %w", err)
	}
	pinRoot := cfg.Filter.BPFPinDir
	if pinRoot != "" {
		pinRoot, err = canonicalizeConfiguredPath(pinRoot)
		if err != nil {
			return nil, fmt.Errorf("canonicalizing filter.bpf_pin_dir: %w", err)
		}
	}

	s := &Server{
		cfg:                  cfg,
		store:                st,
		logger:               logger.With().Str("component", "daemon").Logger(),
		daemonID:             daemonID,
		hostname:             hostname,
		version:              version,
		portPool:             make(map[int]bool),
		attachments:          make(map[string]*attachmentState),
		targetIndex:          make(map[string]string),
		now:                  time.Now,
		ttlJanitorInterval:   janitorInterval,
		janitorStop:          make(chan struct{}),
		dnsMinFilterTTL:      dnsMinFilterTTL,
		dnsListenIP:          dnsListenIP,
		defaultDNSUpstream:   defaultUpstreams[0],
		maxRuleEntries:       maxRuleEntries,
		maxDNSRuleEntries:    maxDNSRuleEntries,
		dnsAdmissionCeilings: dnsAdmissionCeilings,
		dnsChurnCeiling:      dnsChurnCeiling,
		pinRoot:              pinRoot,
		detachOnStop:         cfg.Filter.DetachOnStop,
		newFilter: func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRules uint32) (filter.Filter, error) {
			return createFilter(pinDir, target, attachType, mode, direction, maxRules, maxDNSRuleEntries)
		},
		loadPinnedFilter: func(pinDir, target string, attachType apiv1.AttachmentType, direction apiv1.TcDirection) (filter.Filter, error) {
			return loadPinnedFilterWithOptions(pinDir, target, attachType, direction, maxDNSRuleEntries)
		},
		ensurePinRoot:      ensureBPFPinRoot,
		targetPresence:     targetPresent,
		targetIdentity:     currentTargetIdentity,
		resolveDNSListenIP: resolveConcreteDNSListenIP,
		bindDNSServer:      (*DNSServer).Bind,
		serveDNSServer:     (*DNSServer).Serve,
		saveAttachment:     st.SaveAttachment,
		deleteAttachment:   st.DeleteAttachment,
		removePinDir:       os.RemoveAll,
		readPinRoot:        os.ReadDir,
		validatePinRoot:    validateExistingBPFPinRoot,
		inspectPinSchema:   filter.InspectPinnedSchema,
	}

	s.watcher = NewTargetWatcher(logger, s.handleTargetRemoved)
	s.startWatcher = s.watcher.Start
	s.stopWatcher = s.watcher.Stop
	s.watchTarget = s.registerTargetWatch

	for port := cfg.DNS.PortMin; port <= cfg.DNS.PortMax; port++ {
		s.portPool[port] = false
	}

	existing, err := st.GetAllAttachments()
	if err != nil {
		return nil, fmt.Errorf("loading existing attachments: %w", err)
	}
	for i := range existing {
		s.attachments[existing[i].ID] = &attachmentState{
			info:          &existing[i],
			ttls:          newTTLRegistry(),
			cleanupNeeded: existing[i].CleanupNeeded,
		}
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

// canonicalizeConfiguredPath resolves symlinks in the longest existing
// prefix, then appends any not-yet-created suffix. This makes paths stable
// before they are persisted (notably macOS /var -> /private/var) without
// requiring the configured leaf to exist before Start prepares it.
func canonicalizeConfiguredPath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	existing := abs
	var suffix []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("no existing prefix for %s", abs)
		}
		suffix = append(suffix, filepath.Base(existing))
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	for i := len(suffix) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, suffix[i])
	}
	return filepath.Clean(resolved), nil
}

func (s *Server) resetWatcher() {
	watcher := NewTargetWatcher(s.logger, s.handleTargetRemoved)
	watcher.setTargetIdentityResolver(s.targetIdentity)
	s.watcher = watcher
	s.startWatcher = watcher.Start
	s.stopWatcher = watcher.Stop
}

func (s *Server) SetControlPlaneClient(cp *ControlPlaneClient) {
	s.cpClient.Store(cp)
}

func (s *Server) enterTerminal(cause error) {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.stopAdmission(cause)
	}
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
	// Cleanup tombstones are never restored as policy attachments. They were
	// durably written before a prior destructive detach became ambiguous, so
	// complete that exact teardown before starting watchers, DNS, or control-
	// plane resync. Ownership is released only after both pin removal and row
	// deletion are proven; a failure leaves the tombstone retryable on the
	// next Start/restart.
	if err := s.retryDurableCleanup(); err != nil {
		return err
	}
	// Start the shared watcher before any restored filter is mutated. A global
	// watcher startup failure is therefore a zero-resource, exact-policy abort.
	if err := s.startWatcher(); err != nil {
		return fmt.Errorf("starting target watcher: %w", err)
	}

	s.mu.Lock()
	var toRemove []string
	var resources []*restoreStartResource
	abortStart := func(err error) error {
		rollbackErr := s.rollbackRestoreStart(resources)
		s.mu.Unlock()
		s.stopWatcher()
		s.resetWatcher()
		return errors.Join(err, rollbackErr)
	}
	ids := make([]string, 0, len(s.attachments))
	for id := range s.attachments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		state := s.attachments[id]
		originalPinDir := state.info.PinDir
		originalPinPathKnown := state.info.PinPathKnown
		pinDir := state.info.PinDir
		pinIdentityChanged := false
		// Legacy rows did not record pin identity. Establish it from the current
		// configuration before creating/adopting anything. A known unpinned row
		// may opt into newly-enabled pinning; a known non-empty path is retained
		// even if config changed so old pinned enforcement is never orphaned.
		if !state.info.PinPathKnown || (pinDir == "" && s.pinRoot != "") {
			pinDir = s.pinDirFor(id)
			state.info.PinDir = pinDir
			state.info.PinPathKnown = true
			pinIdentityChanged = true
		}
		if pinDir != "" {
			validatedPinDir, err := s.validatedCleanupPinDir(id, state.info)
			if err != nil {
				return abortStart(fmt.Errorf("validating persisted pin identity for attachment %s: %w", id, err))
			}
			pinDir = validatedPinDir
		}
		attachType := parseAttachmentType(state.info.Type)
		mode := parsePolicyMode(state.info.Mode)
		direction := parseTcDirection(state.info.Direction)
		expectedIdentity, err := s.targetIdentity(attachType, state.info.Target)
		if err != nil {
			if !isExplicitTargetNotFound(err) {
				return abortStart(fmt.Errorf("resolving target identity for attachment %s: %w", id, err))
			}
			s.logger.Warn().Err(err).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("failed to resolve target identity on restore")
			if schemaErr := s.provePinnedStateSafeForStaleCleanup(pinDir); schemaErr != nil {
				return abortStart(fmt.Errorf("preserving pinned state for missing attachment target %s: %w", id, schemaErr))
			}
			toRemove = append(toRemove, id)
			continue
		}

		ebpfFilter, adopted, err := s.restoreFilter(id, pinDir, state.info.Target, attachType, mode, direction)
		if err != nil {
			var abort *restoreAbortError
			if errors.As(err, &abort) {
				return abortStart(fmt.Errorf("restoring attachment %s: %w", id, abort.err))
			}
			if !isExplicitTargetStale(err) {
				return abortStart(fmt.Errorf("restoring attachment %s while target remains present: %w", id, err))
			}
			s.logger.Warn().Err(err).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("target explicitly disappeared during filter restore; scheduling stale attachment cleanup")
			toRemove = append(toRemove, id)
			continue
		}
		resource := &restoreStartResource{
			id:                   id,
			state:                state,
			filter:               ebpfFilter,
			adopted:              adopted,
			originalDNSAddress:   state.info.DnsAddress,
			originalPinDir:       originalPinDir,
			originalPinPathKnown: originalPinPathKnown,
			pinIdentityChanged:   pinIdentityChanged,
		}
		resources = append(resources, resource)
		dnsSink, sinkErr := s.newDNSFilterSink(id, ebpfFilter)
		if sinkErr != nil {
			return abortStart(fmt.Errorf("initializing DNS exact-tier ownership for attachment %s: %w", id, sinkErr))
		}
		state.dnsSink = dnsSink
		if adopted {
			if err := s.seedAdoptedState(id, state, ebpfFilter); err != nil {
				// Inventory is required for an authoritative delta reconcile: if a
				// live pinned rule is absent from the registry, a later ack could
				// falsely report convergence while leaving stale enforcement behind.
				// Abort startup and Close (not Detach) so the pins keep enforcing the
				// last-known policy for a clean retry.
				return abortStart(fmt.Errorf("inventorying re-adopted attachment %s: %w", id, err))
			}
		}
		canonicalDNSAddress, bootstrapCIDR, setupErr := canonicalDNSListenerAddress(resource.originalDNSAddress, s.resolveDNSListenIP)
		var proxyFunc DnsProxyFunc
		if cpClient := s.cpClient.Load(); cpClient != nil {
			proxyFunc = cpClient.MakeProxyFunc(id)
		}
		dnsServer := NewDNSServer(id, canonicalDNSAddress, s.defaultDNSUpstream, s.logger,
			dnsSink, proxyFunc, dnsSink.LimitCeilings())
		// Domain rules and per-attachment upstream overrides are authoritative
		// CP state and are not persisted. Restoring ALLOWLIST/DENYLIST/PROXY as
		// constructor-default DISABLED would forward everything during an
		// outage. Preserve explicit DISABLED, but hold every filtering mode in
		// an empty ALLOWLIST (REFUSED) until the full SubscribedAck arrives.
		if persistedDNSMode := parseDnsMode(state.info.DnsMode); persistedDNSMode != apiv1.DnsMode_DNS_MODE_DISABLED {
			dnsServer.setModeForRestore(apiv1.DnsMode_DNS_MODE_ALLOWLIST)
		}
		resource.dns = dnsServer
		if setupErr == nil {
			setupErr = s.bindDNSServer(dnsServer)
		}
		if setupErr == nil {
			setupErr = s.serveDNSServer(dnsServer)
		}
		if setupErr != nil {
			if adopted {
				return abortStart(fmt.Errorf("starting DNS server for re-adopted attachment %s: %w", id, setupErr))
			}
			return abortStart(fmt.Errorf("starting DNS server for recreated attachment %s: %w", id, setupErr))
		}

		watchErr := s.validateTargetIdentity(attachType, state.info.Target, expectedIdentity)
		if watchErr == nil {
			resource.watch, watchErr = s.watchTarget(attachType, state.info.Target, expectedIdentity)
		}
		if watchErr != nil {
			restoreKind := "recreated"
			if adopted {
				restoreKind = "re-adopted"
			}
			triggerErr := fmt.Errorf("watching %s attachment %s: %w", restoreKind, id, watchErr)
			if !isExplicitTargetStale(watchErr) {
				return abortStart(triggerErr)
			}
			// An exact identity change/not-found result proves this persisted
			// attachment no longer names the object its filter targeted. Close or
			// detach the staged resource, then route the durable row through the
			// same tombstone-first stale cleanup as an initially missing target.
			rollbackErr := s.rollbackRestoreStart(resources[len(resources)-1:])
			resources = resources[:len(resources)-1]
			if rollbackErr != nil {
				return abortStart(errors.Join(triggerErr, rollbackErr))
			}
			toRemove = append(toRemove, id)
			continue
		}

		resource.bootstrap = bootstrapCIDR
		resource.canonicalDNSAddress = canonicalDNSAddress
	}

	// Prepare/commit boundary: every resolver is dual-protocol serving, every
	// target has an exact watch, and every canonical endpoint is known before
	// the first adopted map is changed. Store changes are reversible here.
	for _, resource := range resources {
		if resource.canonicalDNSAddress == resource.originalDNSAddress && !resource.pinIdentityChanged {
			continue
		}
		resource.state.info.DnsAddress = resource.canonicalDNSAddress
		if err := s.saveAttachment(cloneAttachment(resource.state.info)); err != nil {
			return abortStart(fmt.Errorf("persisting concrete DNS address for attachment %s: %w", resource.id, err))
		}
		resource.addressPersisted = true
	}
	// Add-only commit. If a later add fails, rollback removes prior additions;
	// an ambiguous removal failure is forced BLOCK_ALL by rollbackRestoreStart.
	for i := 0; i < len(resources); {
		resource := resources[i]
		if err := resource.state.ttls.addSystem(resource.filter, resource.bootstrap, listAllow); err != nil {
			if resource.adopted {
				return abortStart(fmt.Errorf("installing protected DNS bootstrap route for attachment %s: %w", resource.id, err))
			}
			return abortStart(fmt.Errorf("installing protected DNS bootstrap route for recreated attachment %s: %w", resource.id, err))
		}
		resource.bootstrapInstalled = true
		i++
	}
	for _, resource := range resources {
		state := resource.state
		if err := dnsServerSetupError(resource.dns); err != nil {
			return abortStart(fmt.Errorf("DNS listener exited before restore commit for attachment %s: %w", resource.id, err))
		}
		state.info.DnsAddress = resource.canonicalDNSAddress
		state.watch = resource.watch
		state.filter = resource.filter
		state.dns = resource.dns
		state.needsResync = true
		s.logger.Info().
			Str("id", resource.id).
			Str("target", state.info.Target).
			Str("type", state.info.Type).
			Bool("readopted_from_pins", resource.adopted).
			Msg("restored attachment")
	}

	for _, id := range toRemove {
		state := s.attachments[id]
		if state == nil {
			continue
		}
		// Persist the cleanup intent before deleting the row. If deletion is
		// unavailable, retain target/port ownership and abort startup; the next
		// Start sees the tombstone and retries cleanup instead of restoring it.
		state.info.Mode = apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String()
		state.info.CleanupNeeded = true
		state.cleanupNeeded = true
		if !state.info.PinPathKnown {
			// This case follows a recreated-resource rollback that restored the
			// legacy row after successfully Detaching the exact current path.
			state.info.PinDir = s.pinDirFor(id)
			state.info.PinPathKnown = true
		}
		if err := s.saveAttachment(cloneAttachment(state.info)); err != nil {
			return abortStart(fmt.Errorf("persisting stale attachment cleanup tombstone %s: %w", id, err))
		}
		pinDir, err := s.validatedCleanupPinDir(id, state.info)
		if err != nil {
			return abortStart(err)
		}
		if pinDir != "" {
			if err := s.removePinDir(pinDir); err != nil {
				return abortStart(fmt.Errorf("removing pinned state for stale attachment %s: %w", id, err))
			}
		}
		if err := s.deleteAttachment(id); err != nil {
			return abortStart(fmt.Errorf("deleting stale attachment %s: %w", id, err))
		}
		delete(s.attachments, id)
		if s.targetIndex[state.info.Target] == id {
			delete(s.targetIndex, state.info.Target)
		}
		if port := extractPort(state.info.DnsAddress); port > 0 {
			s.releasePort(port)
		}
	}

	// Reconcile orphaned pin dirs: bpffs state with no surviving store row
	// (e.g. a crash between pinning and the store save, or a row dropped just
	// above) is removable only after the schema inspector proves a complete,
	// current, coherent set. Uncommitted/future/incompatible state is preserved
	// and aborts startup rather than being guessed away.
	if s.pinRoot != "" {
		entries, err := s.readPinRoot(s.pinRoot)
		if err != nil {
			return abortStart(fmt.Errorf("scanning BPF pin root for orphans: %w", err))
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			orphan := filepath.Join(s.pinRoot, entry.Name())
			owned := false
			for _, state := range s.attachments {
				if state.info.PinPathKnown && state.info.PinDir == orphan {
					owned = true
					break
				}
			}
			if owned {
				continue
			}
			schemaState, err := s.inspectPinSchema(orphan)
			if err != nil {
				return abortStart(fmt.Errorf("classifying orphaned BPF pin dir %s before cleanup: %w", orphan, err))
			}
			if schemaState != filter.PinnedSchemaCurrent {
				return abortStart(fmt.Errorf("orphaned BPF pin dir %s has an uncommitted schema marker; preserving possible live enforcement for retry/inspection", orphan))
			}
			if err := s.removePinDir(orphan); err != nil {
				return abortStart(fmt.Errorf("removing orphaned BPF pin dir %s: %w", orphan, err))
			}
			s.logger.Info().Str("pin_dir", orphan).Msg("removed orphaned BPF pin dir (no matching attachment)")
		}
	}
	s.mu.Unlock()
	for _, resource := range resources {
		s.startDNSLifecycleWatch(resource.id, resource.state)
	}

	s.janitorWG.Add(1)
	go s.runTTLJanitor()

	return nil
}

func (s *Server) retryDurableCleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0)
	for id, state := range s.attachments {
		if state.cleanupNeeded || state.info.CleanupNeeded {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		state := s.attachments[id]
		if state == nil {
			continue
		}
		pinDir, err := s.validatedCleanupPinDir(id, state.info)
		if err != nil {
			return err
		}
		if pinDir != "" {
			if err := s.removePinDir(pinDir); err != nil {
				return fmt.Errorf("removing pinned state for cleanup attachment %s: %w", id, err)
			}
		}
		if err := s.deleteAttachment(id); err != nil {
			return fmt.Errorf("deleting cleanup attachment %s: %w", id, err)
		}
		delete(s.attachments, id)
		if s.targetIndex[state.info.Target] == id {
			delete(s.targetIndex, state.info.Target)
		}
		if port := extractPort(state.info.DnsAddress); port > 0 {
			s.releasePort(port)
		}
		s.logger.Info().Str("id", id).Msg("completed durable attachment cleanup during startup")
	}
	return nil
}

func (s *Server) validatedCleanupPinDir(id string, attachment *store.Attachment) (string, error) {
	if attachment == nil || !attachment.PinPathKnown {
		return "", fmt.Errorf("cleanup attachment %s has unknown original pin path", id)
	}
	pinDir := attachment.PinDir
	if pinDir == "" {
		return "", nil // explicitly persisted as unpinned
	}
	if !filepath.IsAbs(pinDir) || filepath.Clean(pinDir) != pinDir {
		return "", fmt.Errorf("cleanup attachment %s has non-canonical pin path %q", id, pinDir)
	}
	if filepath.Base(pinDir) != id {
		return "", fmt.Errorf("cleanup attachment %s pin path %q is not its attachment leaf", id, pinDir)
	}
	root := filepath.Dir(pinDir)
	if root == string(filepath.Separator) || root == "." || root == pinDir {
		return "", fmt.Errorf("cleanup attachment %s has unsafe pin root %q", id, root)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolving cleanup attachment %s pin root %q: %w", id, root, err)
	}
	if resolvedRoot != root {
		return "", fmt.Errorf("cleanup attachment %s pin root %q contains a symlink", id, root)
	}
	if info, err := os.Lstat(pinDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("cleanup attachment %s pin leaf %q is a symlink", id, pinDir)
	} else if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("checking cleanup attachment %s pin leaf %q: %w", id, pinDir, err)
	}
	if err := s.validatePinRoot(root); err != nil {
		return "", fmt.Errorf("validating cleanup attachment %s pin root: %w", id, err)
	}
	return pinDir, nil
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

// provePinnedStateSafeForStaleCleanup is the destructive-cleanup gate for a
// missing target. Target absence alone says nothing about whether a pin
// directory is a future schema, a crash-partial migration, or a mixed live
// set. Only a complete current schema whose maps/links and target identities
// are coherent may be removed automatically.
func (s *Server) provePinnedStateSafeForStaleCleanup(pinDir string) error {
	if pinDir == "" {
		return nil
	}
	if _, err := os.Stat(pinDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking pin dir %s before stale cleanup: %w", pinDir, err)
	}
	state, err := s.inspectPinSchema(pinDir)
	if err != nil {
		return fmt.Errorf("inspecting pin dir %s before stale cleanup: %w", pinDir, err)
	}
	if state != filter.PinnedSchemaCurrent {
		return fmt.Errorf("pin dir %s is uncommitted; possible live enforcement requires inspection", pinDir)
	}
	return nil
}

// restoreFilter obtains the eBPF filter for a persisted attachment during
// Start. The keep-enforcing path re-adopts the attachment's pinned BPF state
// (rules intact, links never re-attached — so no transient allow/block
// window and no duplicate attachment; the kernel was enforcing the whole
// time the daemon was down). Absent or unusable pins fall back to recreating
// an empty filter in the persisted mode — the pre-pinning behavior, e.g.
// after a detach_on_stop run or on data from a pre-pinning daemon — and the
// caller's log line records which path was taken. adopted reports whether
// the pinned path was used.
func (s *Server) restoreFilter(id, pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection) (_ filter.Filter, adopted bool, _ error) {
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
			present, presenceErr := s.targetPresence(attachType, target)
			if presenceErr != nil {
				return nil, false, &restoreAbortError{err: fmt.Errorf("checking target presence for %s: %w", target, presenceErr)}
			}
			if !present {
				// Target absence never outranks schema safety. A future,
				// uncommitted, or incoherent pin set is preserved even when the
				// persisted target name no longer resolves.
				if schemaErr := s.provePinnedStateSafeForStaleCleanup(pinDir); schemaErr != nil {
					return nil, false, &restoreAbortError{err: schemaErr}
				}
				s.logger.Warn().Str("id", id).Str("target", target).
					Msg("target gone while daemon was down; current coherent pins are eligible for stale cleanup")
				return nil, false, fmt.Errorf("target %s disappeared while daemon was down: %w", target, os.ErrNotExist)
			} else {
				restored, lerr := s.loadPinnedFilter(pinDir, target, attachType, direction)
				if lerr == nil {
					return restored, true, nil
				}
				// Production loaders close their own partially-opened handles,
				// but keep this boundary defensive for alternate implementations
				// and future loaders. A close ambiguity never authorizes unpinning.
				if restored != nil {
					if closeErr := restored.Close(); closeErr != nil {
						return nil, false, &restoreAbortError{err: errors.Join(
							fmt.Errorf("re-adopting pinned BPF state from %s: %w", pinDir, lerr),
							fmt.Errorf("closing partially re-adopted BPF state from %s: %w", pinDir, closeErr),
						)}
					}
				}
				if errors.Is(lerr, filter.ErrPinnedStateCloseFailed) {
					// A production loader could not prove all partial handles
					// closed. That ambiguity vetoes every otherwise-discardable
					// classification; preserve the exact pins for retry/inspection.
					return nil, false, &restoreAbortError{err: fmt.Errorf("re-adopting pinned BPF state from %s: %w", pinDir, lerr)}
				}
				if isExplicitTargetNotFound(lerr) &&
					!errors.Is(lerr, filter.ErrPinnedStateInvalid) {
					// The target vanished during adoption. Let Start route the row
					// through stale-target cleanup only after independently proving
					// the complete current pin schema is coherent.
					if schemaErr := s.provePinnedStateSafeForStaleCleanup(pinDir); schemaErr != nil {
						return nil, false, &restoreAbortError{err: errors.Join(lerr, schemaErr)}
					}
					return nil, false, lerr
				}
				if !errors.Is(lerr, filter.ErrPinnedStateInvalid) &&
					!errors.Is(lerr, filter.ErrPinnedTargetMismatch) {
					// EACCES, EIO, ENOMEM, and every other untyped error leave the
					// exact pins in place. They may still be the live enforcing state.
					return nil, false, &restoreAbortError{err: fmt.Errorf("re-adopting pinned BPF state from %s: %w", pinDir, lerr)}
				}
				s.logger.Warn().Err(lerr).Str("id", id).Str("pin_dir", pinDir).
					Msg("pinned BPF state is explicitly invalid or targets a replaced object; discarding pins and recreating empty filter")
				if rmErr := s.removePinDir(pinDir); rmErr != nil {
					return nil, false, &restoreAbortError{err: fmt.Errorf("removing unusable pin dir %s: %w", pinDir, rmErr)}
				}
			}
		} else {
			s.logger.Info().Str("id", id).Str("pin_dir", pinDir).
				Msg("no pinned BPF state for attachment (detach_on_stop run or pre-pinning data); recreating empty filter")
		}
	}

	f, err := s.newFilter(pinDir, target, attachType, mode, direction, s.maxRuleEntries)
	if err != nil {
		if f != nil {
			if cleanupErr := f.Detach(); cleanupErr != nil {
				return nil, false, &restoreAbortError{err: errors.Join(
					fmt.Errorf("creating replacement filter: %w", err),
					fmt.Errorf("cleaning partially constructed replacement filter: %w", cleanupErr),
				)}
			}
		}
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
	if state.dnsSink == nil {
		seedErr = errors.Join(seedErr, fmt.Errorf("DNS exact-tier ownership sink is unavailable"))
	} else if err := state.dnsSink.SeedPinned(); err != nil {
		seedErr = errors.Join(seedErr, fmt.Errorf("seeding restored DNS exact-tier ownership: %w", err))
	}
	if liveMode, err := f.GetMode(); err != nil {
		s.logger.Warn().Err(err).Str("id", id).Msg("failed to read mode from re-adopted filter")
		seedErr = errors.Join(seedErr, fmt.Errorf("reading adopted mode: %w", err))
	} else if apiMode := filterModeToAPIMode(liveMode); apiMode.String() != state.info.Mode {
		s.logger.Info().Str("id", id).
			Str("store_mode", state.info.Mode).
			Str("live_mode", apiMode.String()).
			Msg("store mode lagged pinned mode; trusting kernel state")
		state.info.Mode = apiMode.String()
		if err := s.saveAttachment(cloneAttachment(state.info)); err != nil {
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

// targetPresent distinguishes explicit target disappearance from ambiguous
// permission/netlink/I/O failures. Only the former authorizes unpin/delete.
func targetPresent(attachType apiv1.AttachmentType, target string) (bool, error) {
	_, err := currentTargetIdentity(attachType, target)
	if err == nil {
		return true, nil
	}
	if isExplicitTargetNotFound(err) {
		return false, nil
	}
	return false, err
}

func isExplicitTargetNotFound(err error) bool {
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	// net.InterfaceByName returns an unexported plain error on some platforms.
	return strings.Contains(strings.ToLower(err.Error()), "no such network interface")
}

var errTargetIdentityChanged = errors.New("target identity changed")

// isExplicitTargetStale is deliberately narrower than a generic setup error.
// Destructive restore cleanup is authorized only when the target is proven
// absent or when an exact identity comparison proves that the same name/path
// now refers to a different object. Permission, capacity, and I/O failures are
// ambiguous and must retain the durable attachment for a later retry.
func isExplicitTargetStale(err error) bool {
	return isExplicitTargetNotFound(err) || errors.Is(err, errTargetIdentityChanged)
}

func (s *Server) validateTargetIdentity(attachType apiv1.AttachmentType, target string, expected uint64) error {
	current, err := s.targetIdentity(attachType, target)
	if err != nil {
		return fmt.Errorf("resolving current target identity: %w", err)
	}
	if current != expected {
		return fmt.Errorf("target identity changed during attachment setup: was %d, now %d: %w", expected, current, errTargetIdentityChanged)
	}
	return nil
}

func (s *Server) registerTargetWatch(attachType apiv1.AttachmentType, target string, identity uint64) (watchToken, error) {
	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		return s.watcher.WatchInterface(target, identity)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		return s.watcher.WatchCgroup(target, identity)
	default:
		return watchToken{}, fmt.Errorf("unsupported attachment type %s", attachType)
	}
}

func (s *Server) Stop() {
	// Publish terminal lifecycle state before waiting on any exact attachment
	// lock. A claimed ack that already owns reconcileMu may finish; every later
	// ack fails its exact-live check. Stop then joins each owner before closing
	// its filter/DNS resources, so no apply can run against a closed handle.
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.stopAdmission(fmt.Errorf("daemon stopping"))
	}
	// Add is performed under the same mutex before an Attach begins, so once
	// stopping is published no new Add can race this Wait. Let in-flight
	// Attach calls commit or roll back before taking the terminal snapshot.
	s.attachWG.Wait()
	s.commandWG.Wait()
	s.mu.Lock()
	for _, state := range s.attachments {
		state.mutationsClosed = true
	}
	s.mu.Unlock()

	// Stop the janitor before closing filters so a sweep never races with
	// wholesale filter teardown.
	s.janitorStopOnce.Do(func() { close(s.janitorStop) })
	s.janitorWG.Wait()

	s.stopWatcher()

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
		state.finishSetup(false)
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
		state.mutationMu.Lock()
		if state.filter != nil {
			if s.detachOnStop {
				if err := state.filter.Detach(); err != nil {
					s.logger.Warn().Err(err).Msg("error detaching filter on stop")
				}
			} else {
				state.filter.Close()
			}
		}
		state.mutationMu.Unlock()
		state.reconcileMu.Unlock()
	}
	s.dnsWatchWG.Wait()
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
// IDs are snapshotted under s.mu, then each expiry takes exact-state mutation
// admission. Teardown closes admission and drains an already-running expiry
// before closing handles; a stale snapshot is simply rejected.
func (s *Server) sweepExpiredTTLs(now time.Time) {
	s.mu.RLock()
	ids := make([]string, 0, len(s.attachments))
	for id := range s.attachments {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	for _, id := range ids {
		state, done, err := s.beginAttachmentMutation(id)
		if err != nil {
			continue
		}
		for _, swept := range state.ttls.expire(state.filter, now) {
			if swept.err != nil {
				s.logger.Warn().Err(swept.err).
					Str("id", id).
					Str("cidr", swept.cidr).
					Str("list", swept.list.String()).
					Msg("failed to remove expired CIDR, will retry")
				continue
			}
			s.logger.Debug().
				Str("id", id).
				Str("cidr", swept.cidr).
				Str("list", swept.list.String()).
				Msg("removed expired CIDR")
		}
		var dnsExpiryErr error
		if state.dnsSink != nil {
			dnsExpiryErr = state.dnsSink.Expire(now)
			if dnsExpiryErr != nil {
				dnsExpiryErr = errors.Join(dnsExpiryErr, state.dnsSink.FailClosedIfAmbiguous(dnsExpiryErr))
			}
		}
		if finishErr := s.finishDNSMutation(state, done, dnsExpiryErr); finishErr != nil {
			s.logger.Warn().Err(finishErr).Str("id", id).Msg("failed to expire DNS exact-tier ownership; will retry or remain quarantined")
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
	s.mu.RLock()
	if s.stopping || s.targetIndex[target] != id || s.attachments[id] != state || state.watch != token {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	cleanupErr := s.cleanupAttachmentState(id, state, fmt.Errorf("attachment target was removed"))
	s.mu.RLock()
	_, retained := s.attachments[id]
	s.mu.RUnlock()
	if cleanupErr != nil && retained {
		s.logger.Error().Err(cleanupErr).Str("id", id).Msg("target removal cleanup retained for retry")
		if cpClient := s.cpClient.Load(); cpClient != nil {
			cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
				Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR,
				Error: cleanupErr.Error(),
			})
		}
		return
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
	if cleanupErr != nil {
		s.logger.Warn().Err(cleanupErr).Str("id", id).Msg("target cleanup completed with DNS shutdown error")
	}
}

func (s *Server) Attach(ctx context.Context, req *apiv1.AttachRequest) (resp *apiv1.AttachResponse, retErr error) {
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

	id := uuid.Must(uuid.NewV7()).String()
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
	// Reserve same-target setup before any kernel mutation. The id is the
	// setup ownership token and becomes the live targetIndex value on commit;
	// every rollback either releases it after proven Detach or retains it with
	// an explicit degraded owner.
	s.targetIndex[target] = id
	s.mu.Unlock()

	dnsAddr := net.JoinHostPort(s.dnsListenIP, strconv.Itoa(port))

	// Always start in DISABLED mode - the control plane provides the initial
	// configuration via SubscribedAck
	mode := apiv1.PolicyMode_POLICY_MODE_DISABLED

	attachment := &store.Attachment{
		ID:           id,
		Target:       target,
		Type:         attachType.String(),
		Mode:         mode.String(),
		DnsMode:      apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress:   dnsAddr,
		Metadata:     req.Metadata,
		AttachedAt:   time.Now(),
		PinDir:       s.pinDirFor(id),
		PinPathKnown: true,
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
		dnsSink    *dnsFilterSink
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
		var cleanupErrs []error
		ownedState := registered
		if registered != nil {
			// The attachment was publicly visible, so a concurrent Detach or
			// target removal (or a claimed SubscribedAck) may already own it.
			// Wait for the exact state's reconcile lock WITHOUT Server.mu and
			// revalidate ownership. Keep the registration until destructive
			// cleanup has definitely succeeded: an ambiguous Detach must remain
			// an inspectable, target/port-owned degraded attachment.
			ownedState.reconcileMu.Lock()
			defer ownedState.reconcileMu.Unlock()
			s.mu.RLock()
			stillOwned := s.attachments[id] == ownedState
			s.mu.RUnlock()
			if !stillOwned {
				ownedState.finishSetup(false)
				return
			}
			s.mu.Lock()
			if s.attachments[id] == ownedState {
				ownedState.mutationsClosed = true
				ownedState.cleanupNeeded = true
				ownedState.needsResync = false
			}
			s.mu.Unlock()
		}

		if cpClient := s.cpClient.Load(); cpClient != nil {
			cpClient.cancelSubscription(id, fmt.Errorf("attachment setup rolled back"))
		}
		if dnsServer != nil {
			if err := dnsServer.Stop(); err != nil {
				s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server during attach rollback")
				cleanupErrs = append(cleanupErrs, fmt.Errorf("stopping DNS during attach rollback: %w", err))
			}
		}
		if ownedState != nil {
			ownedState.mutationMu.Lock()
			defer ownedState.mutationMu.Unlock()
		}
		attachment.Mode = apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String()
		attachment.CleanupNeeded = true
		if ownedState != nil {
			ownedState.info.Mode = attachment.Mode
			ownedState.info.CleanupNeeded = true
		}
		retainDegraded := func(retainedFilter filter.Filter) {
			s.mu.Lock()
			if ownedState == nil {
				ownedState = &attachmentState{info: attachment, dns: dnsServer, dnsSink: dnsSink, filter: retainedFilter, ttls: ttls, mutationsClosed: true}
				s.attachments[id] = ownedState
			} else {
				ownedState.info.Mode = attachment.Mode
				ownedState.info.CleanupNeeded = true
				ownedState.dns = dnsServer
				ownedState.dnsSink = dnsSink
				ownedState.filter = retainedFilter
			}
			ownedState.cleanupNeeded = true
			ownedState.mutationsClosed = true
			if ownedState.watch.valid() {
				switch attachType {
				case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
					s.watcher.UnwatchInterface(ownedState.watch)
				case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
					s.watcher.UnwatchCgroup(ownedState.watch)
				}
				ownedState.watch = watchToken{}
			}
			if existingID, exists := s.targetIndex[target]; !exists || existingID == id {
				s.targetIndex[target] = id
			} else {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("retaining degraded attachment target ownership: target already owned by %s", existingID))
			}
			s.mu.Unlock()
		}
		enterTerminal := func(cause error) {
			s.enterTerminal(cause)
			cleanupErrs = append(cleanupErrs, fmt.Errorf("durable fail-closed quarantine unavailable; daemon entered terminal state: %w", cause))
		}

		var preDetachModeErr error
		if ebpfFilter != nil {
			// Detach may close map FDs even when pin removal fails. Stage the
			// still-writable map fail-closed before any destructive operation.
			preDetachModeErr = ebpfFilter.SetMode(filter.ModeBlockAll)
		}
		// If a row already exists, durably change its recovery policy to
		// BLOCK_ALL before either Detach or row deletion can become ambiguous.
		quarantinePersisted := false
		var quarantinePersistErr error
		if rowSaved {
			quarantinePersistErr = s.saveAttachment(cloneAttachment(attachment))
			if quarantinePersistErr != nil {
				// One immediate retry handles transient SQLite contention without
				// proceeding destructively while recovery state is still stale.
				firstErr := quarantinePersistErr
				if retryErr := s.saveAttachment(cloneAttachment(attachment)); retryErr != nil {
					quarantinePersistErr = errors.Join(firstErr, retryErr)
				} else {
					quarantinePersistErr = nil
				}
			}
			quarantinePersisted = quarantinePersistErr == nil
		}
		if rowSaved && !quarantinePersisted {
			retainDegraded(ebpfFilter)
			if preDetachModeErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("forcing block-all before attach rollback: %w", preDetachModeErr))
			}
			enterTerminal(fmt.Errorf("persisting block-all recovery policy before detach: %w", quarantinePersistErr))
			ownedState.finishSetup(false)
			resp = nil
			retErr = errors.Join(retErr, errors.Join(cleanupErrs...))
			return
		}
		var detachErr error
		if ebpfFilter != nil {
			detachErr = ebpfFilter.Detach()
		}
		if detachErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("detaching eBPF filter during attach rollback: %w", detachErr))
			if preDetachModeErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("forcing block-all before failed attach rollback detach: %w", preDetachModeErr))
			}
			retainDegraded(ebpfFilter)
			if !quarantinePersisted {
				if err := s.saveAttachment(cloneAttachment(ownedState.info)); err != nil {
					if quarantinePersistErr != nil {
						cleanupErrs = append(cleanupErrs, fmt.Errorf("preparing durable block-all rollback state: %w", quarantinePersistErr))
					}
					enterTerminal(fmt.Errorf("persisting degraded block-all attachment: %w", err))
				} else {
					rowSaved = true
					quarantinePersisted = true
				}
			}
			// Keep target registration, port ownership, TTL inventory, and any
			// valid watch. A restart can re-adopt the surviving pins and retry
			// cleanup; nothing becomes unowned or silently fail-open.
			ownedState.finishSetup(false)
			if notifyCP {
				if cpClient := s.cpClient.Load(); cpClient != nil {
					cpClient.SendUnsubscribed(&apiv1.Unsubscribed{Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR, Error: "control plane subscription failed"})
				}
			}
			resp = nil
			retErr = errors.Join(retErr, errors.Join(cleanupErrs...))
			return
		}

		// Detach proved the staged kernel resources are gone, but ownership is
		// retained until durable row deletion also succeeds.
		if rowSaved {
			if err := s.deleteAttachment(id); err != nil {
				s.logger.Error().Err(err).Str("id", id).Msg("error deleting attachment from store during attach rollback")
				cleanupErrs = append(cleanupErrs, fmt.Errorf("deleting attachment during rollback: %w", err))
				ttls.purge()
				retainDegraded(nil)
				if !quarantinePersisted {
					if saveErr := s.saveAttachment(cloneAttachment(ownedState.info)); saveErr != nil {
						if quarantinePersistErr != nil {
							cleanupErrs = append(cleanupErrs, fmt.Errorf("preparing durable block-all rollback state: %w", quarantinePersistErr))
						}
						enterTerminal(fmt.Errorf("persisting cleanup-needed block-all attachment: %w", saveErr))
					} else {
						quarantinePersisted = true
					}
				}
				ownedState.finishSetup(false)
				resp = nil
				retErr = errors.Join(retErr, errors.Join(cleanupErrs...))
				return
			}
		}

		// Both destructive steps succeeded; release every reservation.
		ttls.purge()
		s.mu.Lock()
		if ownedState != nil && s.attachments[id] == ownedState {
			ownedState.finishSetup(false)
			if ownedState.watch.valid() {
				switch attachType {
				case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
					s.watcher.UnwatchInterface(ownedState.watch)
				case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
					s.watcher.UnwatchCgroup(ownedState.watch)
				}
			}
			delete(s.attachments, id)
		}
		if s.targetIndex[target] == id {
			delete(s.targetIndex, target)
		}
		s.releasePort(port)
		s.mu.Unlock()
		if notifyCP {
			if cpClient := s.cpClient.Load(); cpClient != nil {
				cpClient.SendUnsubscribed(&apiv1.Unsubscribed{Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR, Error: "control plane subscription failed"})
			}
		}
		resp = nil
		retErr = errors.Join(retErr, errors.Join(cleanupErrs...))
	}()

	expectedIdentity, err := s.targetIdentity(attachType, target)
	if err != nil {
		return nil, fmt.Errorf("resolving target identity before filter attachment: %w", err)
	}

	// Every staged fresh filter begins fail-closed. It is transitioned to the
	// no-CP initial mode only at the final commit; a CP ack applies its desired
	// mode itself. Thus even combined SetMode+Detach rollback failures cannot
	// leave newly-created enforcement effective DISABLED.
	ebpfFilter, err = s.newFilter(s.pinDirFor(id), target, attachType, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL, direction, s.maxRuleEntries)
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
	dnsSink, err = s.newDNSFilterSink(id, ebpfFilter)
	if err != nil {
		return nil, fmt.Errorf("initializing DNS exact-tier ownership: %w", err)
	}
	dnsServer = NewDNSServer(id, dnsAddr, s.defaultDNSUpstream, s.logger, dnsSink, proxyFunc, dnsSink.LimitCeilings())
	if err := s.bindDNSServer(dnsServer); err != nil {
		return nil, fmt.Errorf("binding DNS server: %w", err)
	}
	if err := s.serveDNSServer(dnsServer); err != nil {
		return nil, fmt.Errorf("starting DNS server: %w", err)
	}
	bootstrapCIDR, err := dnsBootstrapCIDR(dnsAddr)
	if err != nil {
		return nil, fmt.Errorf("preparing DNS bootstrap route: %w", err)
	}
	if err := ttls.addSystem(ebpfFilter, bootstrapCIDR, listAllow); err != nil {
		return nil, fmt.Errorf("installing protected DNS bootstrap route %s: %w", bootstrapCIDR, err)
	}

	// Persist only after the enforcing resources (filter + DNS) exist: a
	// crash before this point leaves no store row, so restore never
	// resurrects an attachment that was never enforcing.
	if err := s.saveAttachment(attachment); err != nil {
		return nil, fmt.Errorf("saving attachment: %w", err)
	}
	rowSaved = true

	state := &attachmentState{info: attachment, dns: dnsServer, dnsSink: dnsSink, filter: ebpfFilter, ttls: ttls, setupDone: make(chan struct{})}
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, fmt.Errorf("daemon is stopping")
	}
	if existingID, ok := s.targetIndex[target]; ok && existingID != id {
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
		token, watchErr = s.watchTarget(attachType, target, expectedIdentity)
	}
	if token.valid() && watchErr == nil {
		state.watch = token
	} else if token.valid() {
		// Watch registration can publish a token and then fail its exact
		// identity recheck. Remove that generation before Server.mu is released
		// and never publish it on the state, so its queued removal callback
		// cannot race rollback ownership.
		switch attachType {
		case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
			s.watcher.UnwatchInterface(token)
		case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
			s.watcher.UnwatchCgroup(token)
		}
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

	var subscribedAck *apiv1.SubscribedAck
	attachmentCP := s.cpClient.Load()
	if cpClient := attachmentCP; cpClient != nil {
		sub := subscribedFromAttachment(attachment)

		// s.mu is NOT held here: SubscribeAndWait can block for the full
		// subscribe_ack_timeout.
		var err error
		subscribedAck, err = cpClient.subscribeForAttachAndWait(ctx, sub)
		if err != nil {
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
	registered.reconcileMu.Lock()
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		registered.reconcileMu.Unlock()
		return nil, fmt.Errorf("daemon is stopping")
	}
	if s.attachments[id] != registered {
		s.mu.Unlock()
		registered.reconcileMu.Unlock()
		return nil, fmt.Errorf("attachment was detached during setup: %s", id)
	}
	if err := dnsServerSetupError(dnsServer); err != nil {
		s.mu.Unlock()
		registered.reconcileMu.Unlock()
		return nil, fmt.Errorf("DNS listener exited during attachment setup: %w", err)
	}
	if attachmentCP == nil {
		if err := ebpfFilter.SetMode(filter.ModeDisabled); err != nil {
			s.mu.Unlock()
			registered.reconcileMu.Unlock()
			return nil, fmt.Errorf("committing initial disabled filter mode: %w", err)
		}
	}
	// From here ownership is committed even while a validated ack is being
	// applied. A runtime apply failure is quarantined in-place; it must never
	// fall back into destructive setup rollback after changing policy.
	committed = true
	registered.setupCommitted.Store(true)
	s.mu.Unlock()
	if subscribedAck != nil {
		if err := attachmentCP.applySubscribedAck(id, subscribedAck); err != nil {
			quarantineErr := s.quarantineAttachment(id, registered)
			registered.finishSetup(true)
			registered.reconcileMu.Unlock()
			attachmentCP.SendUnsubscribed(&apiv1.Unsubscribed{Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR, Error: "initial control-plane policy failed to apply"})
			return nil, errors.Join(fmt.Errorf("applying initial control-plane policy: %w", err), quarantineErr)
		}
	}
	registered.finishSetup(true)
	registered.reconcileMu.Unlock()
	s.startDNSLifecycleWatch(id, registered)

	return &apiv1.AttachResponse{
		Id:         id,
		DnsAddress: dnsAddr,
	}, nil
}

// quarantineAttachment retains an already-owned attachment but forces its
// effective and persisted recovery policy to BLOCK_ALL. Any inability to do
// both is terminal: new work is refused until an operator restarts after the
// underlying map/store failure is resolved.
func (s *Server) quarantineAttachment(id string, expected *attachmentState) error {
	s.mu.Lock()
	if expected == nil || s.attachments[id] != expected {
		s.mu.Unlock()
		return fmt.Errorf("attachment ownership changed during quarantine")
	}
	expected.mutationsClosed = true
	expected.info.Mode = apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String()
	row := cloneAttachment(expected.info)
	s.mu.Unlock()

	expected.mutationMu.Lock()
	defer expected.mutationMu.Unlock()
	var quarantineErrs []error
	if expected.filter == nil {
		quarantineErrs = append(quarantineErrs, fmt.Errorf("attachment filter is unavailable"))
	} else if err := expected.filter.SetMode(filter.ModeBlockAll); err != nil {
		quarantineErrs = append(quarantineErrs, fmt.Errorf("forcing attachment block-all: %w", err))
	}
	if err := s.saveAttachment(row); err != nil {
		quarantineErrs = append(quarantineErrs, fmt.Errorf("persisting attachment block-all: %w", err))
	}
	if len(quarantineErrs) != 0 {
		s.enterTerminal(errors.Join(quarantineErrs...))
	}
	return errors.Join(quarantineErrs...)
}

// cleanupAttachmentState is the single live-process teardown state machine.
// The caller owns state.reconcileMu. It closes mutation admission first,
// stops DNS, drains every already-admitted filter/stats/TTL operation, then
// establishes BLOCK_ALL + a durable cleanup tombstone before Detach. Target,
// port, and row ownership are released only after both Detach and row deletion
// have succeeded. Every intermediate error leaves the exact state retryable.
func (s *Server) cleanupAttachmentState(id string, state *attachmentState, subscriptionErr error) error {
	s.mu.Lock()
	if s.attachments[id] != state {
		s.mu.Unlock()
		return fmt.Errorf("attachment not found: %s", id)
	}
	alreadyCleanup := state.cleanupNeeded || state.info.CleanupNeeded
	state.mutationsClosed = true
	state.cleanupNeeded = true
	state.needsResync = false
	state.info.Mode = apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String()
	state.info.CleanupNeeded = true
	if !state.info.PinPathKnown {
		state.info.PinDir = s.pinDirFor(id)
		state.info.PinPathKnown = true
	}
	row := cloneAttachment(state.info)
	watch := state.watch
	state.watch = watchToken{}
	attachType := parseAttachmentType(state.info.Type)
	port := extractPort(state.info.DnsAddress)
	target := state.info.Target
	s.mu.Unlock()

	state.finishSetup(false)
	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.cancelSubscription(id, subscriptionErr)
	}
	if watch.valid() {
		switch attachType {
		case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
			s.watcher.UnwatchInterface(watch)
		case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
			s.watcher.UnwatchCgroup(watch)
		}
	}

	var cleanupErrs []error
	if state.dns != nil {
		// Stop waits for every handler/listener to finish even when it reports a
		// cached shutdown error, so cleanup can safely continue and surface that
		// error after filter/row convergence.
		if err := state.dns.Stop(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("stopping DNS server during cleanup: %w", err))
		}
	}

	state.mutationMu.Lock()
	defer state.mutationMu.Unlock()

	var modeErr error
	if !alreadyCleanup && state.filter != nil {
		modeErr = state.filter.SetMode(filter.ModeBlockAll)
		if modeErr != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("forcing attachment block-all before cleanup: %w", modeErr))
		}
	}
	if err := s.saveAttachment(row); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("persisting block-all cleanup tombstone: %w", err))
		s.enterTerminal(errors.Join(cleanupErrs...))
		return errors.Join(cleanupErrs...)
	}

	if state.filter != nil {
		if err := state.filter.Detach(); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("detaching eBPF filter: %w", err))
			if modeErr != nil {
				s.enterTerminal(errors.Join(cleanupErrs...))
			}
			return errors.Join(cleanupErrs...)
		}
		s.mu.Lock()
		if s.attachments[id] == state {
			state.filter = nil
		}
		s.mu.Unlock()
	}
	state.ttls.purge()

	if err := s.deleteAttachment(id); err != nil {
		cleanupErrs = append(cleanupErrs, fmt.Errorf("deleting attachment from store: %w", err))
		return errors.Join(cleanupErrs...)
	}

	s.mu.Lock()
	if s.attachments[id] != state {
		s.mu.Unlock()
		return errors.Join(append(cleanupErrs, fmt.Errorf("attachment ownership changed during cleanup: %s", id))...)
	}
	delete(s.attachments, id)
	if s.targetIndex[target] == id {
		delete(s.targetIndex, target)
	}
	if port > 0 {
		s.releasePort(port)
	}
	s.mu.Unlock()
	return errors.Join(cleanupErrs...)
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
	s.mu.RLock()
	stopping := s.stopping
	cleanupNeeded := state.cleanupNeeded
	live := s.attachments[req.Id] == state
	s.mu.RUnlock()
	if !live {
		return nil, fmt.Errorf("attachment not found: %s", req.Id)
	}
	if stopping && !cleanupNeeded {
		return nil, fmt.Errorf("daemon is stopping")
	}
	cleanupErr := s.cleanupAttachmentState(req.Id, state, fmt.Errorf("attachment detached"))
	s.mu.RLock()
	_, retained := s.attachments[req.Id]
	s.mu.RUnlock()
	if cleanupErr != nil && retained {
		return nil, cleanupErr
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
	if cleanupErr != nil {
		return nil, cleanupErr
	}

	return &emptypb.Empty{}, nil
}

func (s *Server) List(ctx context.Context, req *apiv1.ListRequest) (*apiv1.ListResponse, error) {
	attachments, nextToken, total, err := s.store.ListAttachments(int(req.PageSize), req.PageToken)
	if err != nil {
		return nil, fmt.Errorf("listing attachments: %w", err)
	}

	statsByID := make(map[string]attachmentStatsSnapshot, len(attachments))
	for _, a := range attachments {
		if stats, ok := s.readAttachmentStats(a.ID); ok {
			statsByID[a.ID] = stats
		}
	}

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
		if stats, ok := statsByID[a.ID]; ok {
			info.PacketsAllowed = stats.packetsAllowed
			info.PacketsBlocked = stats.packetsBlocked
			info.DnsQueriesAllowed = stats.dnsAllowed
			info.DnsQueriesBlocked = stats.dnsBlocked
			info.DnsQueriesErrors = stats.dnsErrors
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
		if state.cleanupNeeded || state.mutationsClosed {
			continue
		}
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
		if state.cleanupNeeded || state.mutationsClosed || !state.needsResync {
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
	state := s.attachments[id]
	if state != nil && (state.cleanupNeeded || state.mutationsClosed) {
		return nil
	}
	return state
}

func (s *Server) attachmentStateStillLive(id string, expected *attachmentState) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.attachments[id]
	return !s.stopping && expected != nil && state == expected && !state.cleanupNeeded && !state.mutationsClosed
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
	return !s.stopping && state == expected && state != nil && !state.cleanupNeeded && !state.mutationsClosed && state.needsResync
}

// clearRestoreResync marks an authoritative restore ack complete only if the
// same attachmentState is still live. A detach/replacement race therefore
// cannot clear a newer state's flag or resurrect removed bookkeeping.
func (s *Server) clearRestoreResync(id string, expected *attachmentState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.attachments[id]
	if s.stopping || state != expected || state == nil || state.cleanupNeeded || state.mutationsClosed || !state.needsResync {
		return false
	}
	state.needsResync = false
	return true
}

func (s *Server) GetAttachmentStats() []*apiv1.AttachmentStats {
	s.mu.RLock()
	ids := make([]string, 0, len(s.attachments))
	for id, state := range s.attachments {
		if !state.cleanupNeeded && !state.mutationsClosed {
			ids = append(ids, id)
		}
	}
	s.mu.RUnlock()
	sort.Strings(ids)

	stats := make([]*apiv1.AttachmentStats, 0, len(ids))
	for _, id := range ids {
		snapshot, ok := s.readAttachmentStats(id)
		if !ok {
			continue
		}
		stats = append(stats, &apiv1.AttachmentStats{
			Id:                    id,
			PacketsAllowed:        snapshot.packetsAllowed,
			PacketsBlocked:        snapshot.packetsBlocked,
			DnsQueriesAllowed:     snapshot.dnsAllowed,
			DnsQueriesBlocked:     snapshot.dnsBlocked,
			DnsQueriesErrors:      snapshot.dnsErrors,
			MapFullDrops:          snapshot.mapFullDrops,
			DnsExactIpv4Entries:   snapshot.dnsExactIPv4Entries,
			DnsExactIpv4Capacity:  snapshot.dnsExactIPv4Capacity,
			DnsExactIpv4HighWater: snapshot.dnsExactIPv4HighWater,
			DnsExactIpv6Entries:   snapshot.dnsExactIPv6Entries,
			DnsExactIpv6Capacity:  snapshot.dnsExactIPv6Capacity,
			DnsExactIpv6HighWater: snapshot.dnsExactIPv6HighWater,
			DnsLruEvictions:       snapshot.dnsLRUEvictions,
			DnsAdmissionFailures:  snapshot.dnsAdmissionFailures,
			DnsBudgetThrottles:    snapshot.dnsBudgetThrottles,
		})
	}
	return stats
}

type attachmentStatsSnapshot struct {
	packetsAllowed, packetsBlocked                                   uint64
	dnsAllowed, dnsBlocked                                           uint64
	dnsErrors, mapFullDrops                                          uint64
	dnsExactIPv4Entries, dnsExactIPv4Capacity, dnsExactIPv4HighWater uint32
	dnsExactIPv6Entries, dnsExactIPv6Capacity, dnsExactIPv6HighWater uint32
	dnsLRUEvictions, dnsAdmissionFailures, dnsBudgetThrottles        uint64
}

func (s *Server) readAttachmentStats(id string) (attachmentStatsSnapshot, bool) {
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return attachmentStatsSnapshot{}, false
	}
	defer done()

	var snapshot attachmentStatsSnapshot
	if state.filter != nil {
		if stats, err := state.filter.GetStats(); err == nil {
			snapshot.packetsAllowed = stats.Allowed
			snapshot.packetsBlocked = stats.Blocked
		}
	}
	if state.dns != nil {
		snapshot.dnsAllowed, snapshot.dnsBlocked, snapshot.dnsErrors = state.dns.Stats()
	}
	if state.ttls != nil {
		snapshot.mapFullDrops = state.ttls.mapFullCount()
	}
	if state.dnsSink != nil {
		snapshot.mapFullDrops += state.dnsSink.CapacityDropCount()
		ownership := state.dnsSink.OwnershipStats()
		snapshot.dnsExactIPv4Entries = ownership.occupancy.IPv4Entries
		snapshot.dnsExactIPv4Capacity = ownership.occupancy.IPv4Capacity
		snapshot.dnsExactIPv4HighWater = ownership.highWater4
		snapshot.dnsExactIPv6Entries = ownership.occupancy.IPv6Entries
		snapshot.dnsExactIPv6Capacity = ownership.occupancy.IPv6Capacity
		snapshot.dnsExactIPv6HighWater = ownership.highWater6
		snapshot.dnsLRUEvictions = ownership.lruEvictions
		snapshot.dnsAdmissionFailures = state.dnsSink.AdmissionFailureCount()
		snapshot.dnsBudgetThrottles = state.dnsSink.BudgetThrottleCount()
	}
	return snapshot, true
}

func (s *Server) DaemonID() string {
	return s.daemonID
}

func (s *Server) Hostname() string {
	return s.hostname
}

func (s *Server) SetDnsMode(id string, mode apiv1.DnsMode) error {
	if err := validateDNSMode(mode); err != nil {
		return err
	}
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	err = s.setDNSModeAdmitted(id, state, mode)
	return s.finishDNSMutation(state, done, err)
}

func (s *Server) setDNSModeAdmitted(id string, state *attachmentState, mode apiv1.DnsMode) error {
	if state.dns != nil {
		if err := state.dns.SetMode(mode); err != nil {
			return err
		}
	}

	s.mu.Lock()
	if s.attachments[id] != state {
		s.mu.Unlock()
		return fmt.Errorf("attachment changed while setting DNS mode: %s", id)
	}
	state.info.DnsMode = mode.String()
	attachment := cloneAttachment(state.info)
	s.mu.Unlock()

	if err := s.saveAttachment(attachment); err != nil {
		return fmt.Errorf("saving DNS mode: %w", err)
	}
	return nil
}

func (s *Server) AllowDomain(id string, domain string, includeSubdomains bool) error {
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	var mutationErr error
	if state.dns != nil {
		mutationErr = state.dns.AllowDomain(domain, includeSubdomains)
	}
	return s.finishDNSMutation(state, done, mutationErr)
}

func (s *Server) DenyDomain(id string, domain string, includeSubdomains bool) error {
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	var mutationErr error
	if state.dns != nil {
		mutationErr = state.dns.DenyDomain(domain, includeSubdomains)
	}
	return s.finishDNSMutation(state, done, mutationErr)
}

func (s *Server) RemoveDomain(id string, domain string) error {
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	var mutationErr error
	if state.dns != nil {
		mutationErr = state.dns.RemoveDomain(domain)
	}
	return s.finishDNSMutation(state, done, mutationErr)
}

func (s *Server) ReplaceDNSRules(id string, mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry, upstreamOverride ...[]string) error {
	if err := validateDNSMode(mode); err != nil {
		return err
	}
	if len(upstreamOverride) > 1 {
		return fmt.Errorf("at most one DNS upstream server list may be supplied")
	}
	var upstreamServers []string
	if len(upstreamOverride) == 1 {
		upstreamServers = upstreamOverride[0]
	}
	ceilings, err := s.dnsLimitCeilingsForAttachment(id)
	if err != nil {
		return err
	}
	churnCeiling, err := s.dnsChurnCeilingForAttachment(id)
	if err != nil {
		return err
	}
	prepared, err := prepareDNSRules(mode, allowDomains, denyDomains, upstreamServers,
		s.defaultDNSUpstream, ceilings, dnsAdmissionLimitOverrides{}, churnCeiling, 0)
	if err != nil {
		return err
	}
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	err = s.replaceDNSPreparedAdmitted(id, state, prepared)
	return s.finishDNSMutation(state, done, err)
}

func (s *Server) replaceDNSRulesAdmitted(id string, state *attachmentState, mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry, upstreamServers []string) error {
	ceilings := s.dnsAdmissionCeilings
	churnCeiling := s.dnsChurnCeiling
	if state != nil && state.dns != nil {
		ceilings = state.dns.limitCeilings
		churnCeiling = state.dns.churnCeiling
	}
	prepared, err := prepareDNSRules(mode, allowDomains, denyDomains, upstreamServers,
		s.defaultDNSUpstream, ceilings, dnsAdmissionLimitOverrides{}, churnCeiling, 0)
	if err != nil {
		return err
	}
	return s.replaceDNSPreparedAdmitted(id, state, prepared)
}

func (s *Server) dnsLimitCeilingsForAttachment(id string) (dnsAdmissionLimits, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.attachments[id]
	if state == nil || state.cleanupNeeded || state.mutationsClosed {
		return dnsAdmissionLimits{}, fmt.Errorf("attachment not found or unavailable: %s", id)
	}
	if state.dns == nil {
		return s.dnsAdmissionCeilings, nil
	}
	return state.dns.limitCeilings, nil
}

func (s *Server) dnsChurnCeilingForAttachment(id string) (dnsChurnLimits, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.attachments[id]
	if state == nil || state.cleanupNeeded || state.mutationsClosed {
		return dnsChurnLimits{}, fmt.Errorf("attachment not found or unavailable: %s", id)
	}
	if state.dns == nil {
		return s.dnsChurnCeiling, nil
	}
	return state.dns.churnCeiling, nil
}

func (s *Server) replaceDNSPreparedAdmitted(id string, state *attachmentState, prepared *preparedDNSRules) error {
	if state.dns != nil {
		if err := state.dns.applyPreparedRules(prepared); err != nil {
			return err
		}
	}

	s.mu.Lock()
	if s.attachments[id] != state {
		s.mu.Unlock()
		return fmt.Errorf("attachment changed while replacing DNS rules: %s", id)
	}
	state.info.DnsMode = prepared.mode.String()
	attachment := cloneAttachment(state.info)
	s.mu.Unlock()

	if err := s.saveAttachment(attachment); err != nil {
		return fmt.Errorf("saving DNS rules: %w", err)
	}
	return nil
}

func (s *Server) finishDNSMutation(state *attachmentState, done func(), mutationErr error) error {
	done()
	if mutationErr == nil || !errors.Is(mutationErr, filter.ErrDNSAllowRollback) || state == nil || state.dnsSink == nil {
		return mutationErr
	}
	return errors.Join(mutationErr, state.dnsSink.QuarantineAmbiguity(mutationErr))
}

func (s *Server) ClearRules(id string) error {
	ebpfFilter, reg, done, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	defer done()

	// Clearing goes through the TTL registry and delta-removes every ordinary
	// control-plane LPM entry. It deliberately never invokes Filter.ClearRules:
	// the system-owned DNS bootstrap route must remain reachable, while failed
	// removals stay tracked for a later retry instead of being forgotten. DNS
	// exact ownership is independent and changes only with DNS policy/TTL.
	return reg.clear(ebpfFilter)
}

func (s *Server) SetFilterMode(id string, mode apiv1.PolicyMode) error {
	if err := validatePolicyMode(mode); err != nil {
		return err
	}
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	defer done()
	return s.setFilterModeAdmitted(id, state, mode)
}

func (s *Server) setFilterModeAdmitted(id string, state *attachmentState, mode apiv1.PolicyMode) error {
	if state.filter != nil {
		if err := state.filter.SetMode(apiModeToFilterMode(mode)); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.attachments[id] != state {
		s.mu.Unlock()
		return fmt.Errorf("attachment changed while setting filter mode: %s", id)
	}
	state.info.Mode = mode.String()
	attachment := cloneAttachment(state.info)
	s.mu.Unlock()

	if err := s.saveAttachment(attachment); err != nil {
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
	ebpfFilter, reg, done, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	defer done()
	return reg.addCP(ebpfFilter, cidr, listAllow, ttl, s.now())
}

// DenyCIDR adds the CIDR to the attachment's denylist. TTL semantics match
// AllowCIDR.
func (s *Server) DenyCIDR(id string, cidr *net.IPNet, ttl time.Duration) error {
	ebpfFilter, reg, done, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	defer done()
	return reg.addCP(ebpfFilter, cidr, listDeny, ttl, s.now())
}

func (s *Server) RemoveAllowedCIDR(id string, cidr *net.IPNet) error {
	ebpfFilter, reg, done, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	defer done()
	return reg.remove(ebpfFilter, cidr, listAllow)
}

func (s *Server) RemoveDeniedCIDR(id string, cidr *net.IPNet) error {
	ebpfFilter, reg, done, err := s.filterAndRegistry(id)
	if err != nil {
		return err
	}
	defer done()
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
// This CIDR-only operation does not mutate DNS exact ownership. A full
// BulkUpdate follows it with authoritative DNS reconciliation, which remaps
// still-authorized owners and promptly removes blocked/provisional exact keys.
// Per-CIDR failures (e.g. map-full) are aggregated, not aborting the rest of
// the reconcile.
func (s *Server) ReconcileCIDRs(id string, mode apiv1.PolicyMode, allow, deny []parsedCIDR) error {
	if err := validatePolicyMode(mode); err != nil {
		return err
	}
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return err
	}
	defer done()
	return s.reconcileCIDRsAdmitted(id, state, mode, allow, deny)
}

func (s *Server) reconcileCIDRsAdmitted(id string, state *attachmentState, mode apiv1.PolicyMode, allow, deny []parsedCIDR) error {
	ebpfFilter, reg := state.filter, state.ttls
	if ebpfFilter == nil {
		return fmt.Errorf("attachment %s filter is unavailable", id)
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
	modeErr := s.setFilterModeAdmitted(id, state, mode)
	secondErr := reg.reconcileCP(ebpfFilter, second, secondSet, s.now())
	return errors.Join(firstErr, modeErr, secondErr)
}

func validatePolicyMode(mode apiv1.PolicyMode) error {
	switch mode {
	case apiv1.PolicyMode_POLICY_MODE_DISABLED,
		apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL,
		apiv1.PolicyMode_POLICY_MODE_DENYLIST:
		return nil
	default:
		return fmt.Errorf("invalid policy mode: %d", mode)
	}
}

func validateDNSMode(mode apiv1.DnsMode) error {
	switch mode {
	case apiv1.DnsMode_DNS_MODE_DISABLED,
		apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		apiv1.DnsMode_DNS_MODE_DENYLIST,
		apiv1.DnsMode_DNS_MODE_PROXY:
		return nil
	default:
		return fmt.Errorf("invalid DNS mode: %d", mode)
	}
}

// filterAndRegistry snapshots an attachment's filter and TTL registry under
// s.mu. Callers then operate under the registry's own lock only, so s.mu is
// never held across filter syscalls.
func (s *Server) filterAndRegistry(id string) (filter.Filter, *ttlRegistry, func(), error) {
	state, done, err := s.beginAttachmentMutation(id)
	if err != nil {
		return nil, nil, nil, err
	}
	if state.filter == nil {
		done()
		return nil, nil, nil, fmt.Errorf("attachment %s filter is unavailable", id)
	}
	return state.filter, state.ttls, done, nil
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
