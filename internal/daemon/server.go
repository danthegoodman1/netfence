package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
}

type attachmentState struct {
	info   *store.Attachment
	dns    *DNSServer
	filter filter.Filter
	// ttls tracks expiry deadlines for this attachment's TTL'd CIDR entries
	// and serializes its CIDR-rule mutations. See ttlRegistry.
	ttls *ttlRegistry
}

func NewServer(cfg *config.Config, st *store.Store, logger zerolog.Logger, version string) (*Server, error) {
	hostname, _ := os.Hostname()

	daemonID := cfg.DataDir
	if daemonID == "" {
		daemonID = uuid.Must(uuid.NewV7()).String()
	} else {
		daemonID = fmt.Sprintf("netfenced-%s", hostname)
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
		port := extractPort(existing[i].DnsAddress)
		if port > 0 {
			s.portPool[port] = true
		}
	}

	return s, nil
}

func (s *Server) SetControlPlaneClient(cp *ControlPlaneClient) {
	s.cpClient.Store(cp)
}

func (s *Server) Start() error {
	s.mu.Lock()
	var toRemove []string
	for id, state := range s.attachments {
		attachType := parseAttachmentType(state.info.Type)
		mode := parsePolicyMode(state.info.Mode)
		direction := parseTcDirection(state.info.Direction)

		ebpfFilter, err := createFilter(state.info.Target, attachType, mode, direction, s.maxRuleEntries)
		if err != nil {
			s.logger.Warn().Err(err).
				Str("id", id).
				Str("target", state.info.Target).
				Msg("failed to restore filter, target may be gone")
			toRemove = append(toRemove, id)
			continue
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
				ebpfFilter.Close()
			}
			toRemove = append(toRemove, id)
			continue
		}

		switch attachType {
		case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
			s.watcher.WatchInterface(state.info.Target)
		case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
			if err := s.watcher.WatchCgroup(state.info.Target); err != nil {
				s.logger.Warn().Err(err).
					Str("id", id).
					Str("target", state.info.Target).
					Msg("failed to watch cgroup on restore")
				if err := dnsServer.Stop(); err != nil {
					s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server after restore watch failure")
				}
				if ebpfFilter != nil {
					if err := ebpfFilter.Close(); err != nil {
						s.logger.Warn().Err(err).Str("id", id).Msg("error closing filter after restore watch failure")
					}
				}
				toRemove = append(toRemove, id)
				continue
			}
		}
		state.filter = ebpfFilter
		state.dns = dnsServer

		s.logger.Info().
			Str("id", id).
			Str("target", state.info.Target).
			Str("type", attachType.String()).
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
	s.mu.Unlock()

	if err := s.watcher.Start(); err != nil {
		return fmt.Errorf("starting target watcher: %w", err)
	}

	s.janitorWG.Add(1)
	go s.runTTLJanitor()

	return nil
}

func (s *Server) Stop() {
	// Stop the janitor before closing filters so a sweep never races with
	// wholesale filter teardown.
	s.janitorStopOnce.Do(func() { close(s.janitorStop) })
	s.janitorWG.Wait()

	s.watcher.Stop()

	s.mu.Lock()
	attachments := make([]*attachmentState, 0, len(s.attachments))
	for _, state := range s.attachments {
		attachments = append(attachments, state)
	}
	s.mu.Unlock()

	for _, state := range attachments {
		if state.dns != nil {
			state.dns.Stop()
		}
		if state.filter != nil {
			state.filter.Close()
		}
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

func (s *Server) handleTargetRemoved(target string) {
	s.mu.Lock()
	id, ok := s.targetIndex[target]
	if !ok {
		s.mu.Unlock()
		return
	}

	state, ok := s.attachments[id]
	if !ok {
		s.mu.Unlock()
		return
	}

	port := extractPort(state.info.DnsAddress)
	if port > 0 {
		s.releasePort(port)
	}

	switch parseAttachmentType(state.info.Type) {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.UnwatchInterface(target)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		s.watcher.UnwatchCgroup(target)
	}

	delete(s.attachments, id)
	delete(s.targetIndex, target)
	s.mu.Unlock()

	// Drop TTL bookkeeping so an in-flight janitor sweep does not keep
	// retrying removals against the filter we are about to close.
	state.ttls.purge()

	if state.dns != nil {
		if err := state.dns.Stop(); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server")
		}
	}

	if state.filter != nil {
		if err := state.filter.Close(); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Msg("error closing eBPF filter")
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

	if err := s.store.SaveAttachment(attachment); err != nil {
		s.mu.Lock()
		s.releasePort(port)
		s.mu.Unlock()
		return nil, fmt.Errorf("saving attachment: %w", err)
	}

	ebpfFilter, err := createFilter(target, attachType, mode, direction, s.maxRuleEntries)
	if err != nil {
		s.mu.Lock()
		s.releasePort(port)
		s.mu.Unlock()
		s.store.DeleteAttachment(id)
		return nil, fmt.Errorf("creating eBPF filter: %w", err)
	}

	var proxyFunc DnsProxyFunc
	if cpClient := s.cpClient.Load(); cpClient != nil {
		proxyFunc = cpClient.MakeProxyFunc(id)
	}
	ttls := newTTLRegistry()
	sink := s.newDNSFilterSink(id, ebpfFilter, ttls)
	dnsServer := NewDNSServer(id, dnsAddr, s.cfg.DNS.Upstream, s.logger, sink, proxyFunc)
	if err := dnsServer.Start(); err != nil {
		if ebpfFilter != nil {
			ebpfFilter.Close()
		}
		s.mu.Lock()
		s.releasePort(port)
		s.mu.Unlock()
		s.store.DeleteAttachment(id)
		return nil, fmt.Errorf("starting DNS server: %w", err)
	}

	s.mu.Lock()
	if existingID, ok := s.targetIndex[target]; ok {
		s.mu.Unlock()
		dnsServer.Stop()
		if ebpfFilter != nil {
			ebpfFilter.Close()
		}
		s.mu.Lock()
		s.releasePort(port)
		s.mu.Unlock()
		s.store.DeleteAttachment(id)
		return nil, fmt.Errorf("target already attached: %s (%s)", target, existingID)
	}
	s.attachments[id] = &attachmentState{info: attachment, dns: dnsServer, filter: ebpfFilter, ttls: ttls}
	s.targetIndex[target] = id
	s.mu.Unlock()

	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.WatchInterface(target)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		if err := s.watcher.WatchCgroup(target); err != nil {
			s.logger.Error().Err(err).Str("target", target).Msg("failed to watch cgroup")
			s.cleanupAttachment(id, target, attachType, port, dnsServer, ebpfFilter, false)
			return nil, fmt.Errorf("watching cgroup: %w", err)
		}
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

	cpClient := s.cpClient.Load()

	if cpClient != nil {
		sub := &apiv1.Subscribed{
			Id:          id,
			Target:      target,
			Type:        attachType,
			Mode:        mode,
			DnsMode:     apiv1.DnsMode_DNS_MODE_DISABLED,
			DnsAddress:  dnsAddr,
			Metadata:    req.Metadata,
			TcDirection: direction,
		}

		_, err := cpClient.SubscribeAndWait(ctx, sub)
		if err != nil {
			s.logger.Error().Err(err).Str("id", id).Msg("control plane subscription failed, detaching")
			s.cleanupAttachment(id, target, attachType, port, dnsServer, ebpfFilter, true)
			return nil, fmt.Errorf("control plane subscription failed: %w", err)
		}
	}

	return &apiv1.AttachResponse{
		Id:         id,
		DnsAddress: dnsAddr,
	}, nil
}

func (s *Server) Detach(ctx context.Context, req *apiv1.DetachRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	state, ok := s.attachments[req.Id]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("attachment not found: %s", req.Id)
	}

	port := extractPort(state.info.DnsAddress)
	if port > 0 {
		s.releasePort(port)
	}

	switch parseAttachmentType(state.info.Type) {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.UnwatchInterface(state.info.Target)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		s.watcher.UnwatchCgroup(state.info.Target)
	}

	delete(s.attachments, req.Id)
	delete(s.targetIndex, state.info.Target)
	s.mu.Unlock()

	// Drop TTL bookkeeping so an in-flight janitor sweep does not keep
	// retrying removals against the filter we are about to close.
	state.ttls.purge()

	if state.dns != nil {
		if err := state.dns.Stop(); err != nil {
			s.logger.Warn().Err(err).Str("id", req.Id).Msg("error stopping DNS server")
		}
	}

	if state.filter != nil {
		if err := state.filter.Close(); err != nil {
			s.logger.Warn().Err(err).Str("id", req.Id).Msg("error closing eBPF filter")
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

func (s *Server) cleanupAttachment(id, target string, attachType apiv1.AttachmentType, port int, dnsServer *DNSServer, ebpfFilter filter.Filter, notifyControlPlane bool) {
	s.mu.Lock()
	// Check if attachment still exists - it may have already been cleaned up
	// by the target watcher if the interface/cgroup was removed while we were
	// waiting for SubscribedAck
	state, exists := s.attachments[id]
	if !exists {
		s.mu.Unlock()
		return
	}

	s.releasePort(port)
	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.UnwatchInterface(target)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		s.watcher.UnwatchCgroup(target)
	}
	delete(s.attachments, id)
	delete(s.targetIndex, target)
	s.mu.Unlock()

	state.ttls.purge()

	if dnsServer != nil {
		dnsServer.Stop()
	}
	if ebpfFilter != nil {
		ebpfFilter.Close()
	}
	s.store.DeleteAttachment(id)

	if notifyControlPlane {
		if cpClient := s.cpClient.Load(); cpClient != nil {
			cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
				Id:     id,
				Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR,
				Error:  "control plane subscription failed",
			})
		}
	}
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

func parseAttachmentType(s string) apiv1.AttachmentType {
	if v, ok := apiv1.AttachmentType_value[s]; ok {
		return apiv1.AttachmentType(v)
	}
	return apiv1.AttachmentType_ATTACHMENT_TYPE_UNSPECIFIED
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
