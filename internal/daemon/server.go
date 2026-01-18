package daemon

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
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
}

type attachmentState struct {
	info           *store.Attachment
	dns            *DNSServer
	packetsAllowed uint64
	packetsBlocked uint64
}

func NewServer(cfg *config.Config, st *store.Store, logger zerolog.Logger, version string) (*Server, error) {
	hostname, _ := os.Hostname()

	daemonID := cfg.DataDir
	if daemonID == "" {
		daemonID = uuid.Must(uuid.NewV7()).String()
	} else {
		daemonID = fmt.Sprintf("netfenced-%s", hostname)
	}

	s := &Server{
		cfg:         cfg,
		store:       st,
		logger:      logger.With().Str("component", "daemon").Logger(),
		daemonID:    daemonID,
		hostname:    hostname,
		version:     version,
		portPool:    make(map[int]bool),
		attachments: make(map[string]*attachmentState),
		targetIndex: make(map[string]string),
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
		s.attachments[existing[i].ID] = &attachmentState{info: &existing[i]}
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
	s.mu.RLock()
	for _, state := range s.attachments {
		switch parseAttachmentType(state.info.Type) {
		case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
			s.watcher.WatchInterface(state.info.Target)
		case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
			if err := s.watcher.WatchCgroup(state.info.Target); err != nil {
				s.logger.Warn().Err(err).
					Str("id", state.info.ID).
					Str("target", state.info.Target).
					Msg("failed to watch cgroup, may already be removed")
			}
		}
	}
	s.mu.RUnlock()

	if err := s.watcher.Start(); err != nil {
		return fmt.Errorf("starting target watcher: %w", err)
	}

	return nil
}

func (s *Server) Stop() {
	s.watcher.Stop()
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

	if state.dns != nil {
		if err := state.dns.Stop(); err != nil {
			s.logger.Warn().Err(err).Str("id", id).Msg("error stopping DNS server")
		}
	}

	if err := s.store.DeleteAttachment(id); err != nil {
		s.logger.Error().Err(err).Str("id", id).Msg("error deleting attachment from store")
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

	s.mu.Lock()
	defer s.mu.Unlock()

	port, err := s.allocatePort()
	if err != nil {
		return nil, err
	}

	id := uuid.Must(uuid.NewV7()).String()
	dnsAddr := fmt.Sprintf("%s:%d", s.cfg.DNS.ListenAddr, port)

	mode := req.Mode
	if mode == apiv1.PolicyMode_POLICY_MODE_UNSPECIFIED {
		mode = apiv1.PolicyMode_POLICY_MODE_DISABLED
	}

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

	if err := s.store.SaveAttachment(attachment); err != nil {
		s.releasePort(port)
		return nil, fmt.Errorf("saving attachment: %w", err)
	}

	// Start DNS server for this attachment
	// TODO: Pass actual filter once eBPF integration is complete
	var proxyFunc DnsProxyFunc
	if cpClient := s.cpClient.Load(); cpClient != nil {
		proxyFunc = cpClient.MakeProxyFunc(id)
	}
	dnsServer := NewDNSServer(id, dnsAddr, s.cfg.DNS.Upstream, s.logger, nil, proxyFunc)
	if err := dnsServer.Start(); err != nil {
		s.releasePort(port)
		s.store.DeleteAttachment(id)
		return nil, fmt.Errorf("starting DNS server: %w", err)
	}

	s.attachments[id] = &attachmentState{info: attachment, dns: dnsServer}
	s.targetIndex[target] = id

	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		s.watcher.WatchInterface(target)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		if err := s.watcher.WatchCgroup(target); err != nil {
			s.logger.Warn().Err(err).Str("target", target).Msg("failed to watch cgroup")
		}
	}

	s.logger.Info().
		Str("id", id).
		Str("target", target).
		Str("type", attachType.String()).
		Str("dns_address", dnsAddr).
		Msg("attached filter")

	if cpClient := s.cpClient.Load(); cpClient != nil {
		cpClient.SendSubscribed(&apiv1.Subscribed{
			Id:         id,
			Target:     target,
			Type:       attachType,
			Mode:       mode,
			DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED,
			DnsAddress: dnsAddr,
			Metadata:   req.Metadata,
		})
	}

	return &apiv1.AttachResponse{
		Id:         id,
		DnsAddress: dnsAddr,
	}, nil
}

func (s *Server) Detach(ctx context.Context, req *apiv1.DetachRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.attachments[req.Id]
	if !ok {
		return nil, fmt.Errorf("attachment not found: %s", req.Id)
	}

	if state.dns != nil {
		if err := state.dns.Stop(); err != nil {
			s.logger.Warn().Err(err).Str("id", req.Id).Msg("error stopping DNS server")
		}
	}

	if err := s.store.DeleteAttachment(req.Id); err != nil {
		return nil, fmt.Errorf("deleting attachment: %w", err)
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

	s.mu.RLock()
	defer s.mu.RUnlock()

	var infos []*apiv1.AttachmentInfo
	for _, a := range attachments {
		state := s.attachments[a.ID]
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
		if state != nil {
			info.PacketsAllowed = state.packetsAllowed
			info.PacketsBlocked = state.packetsBlocked
			if state.dns != nil {
				info.DnsQueriesAllowed, info.DnsQueriesBlocked = state.dns.Stats()
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
		attachments = append(attachments, &apiv1.Attachment{
			Id:       a.ID,
			Target:   a.Target,
			Type:     parseAttachmentType(a.Type),
			Mode:     parsePolicyMode(a.Mode),
			DnsMode:  parseDnsMode(a.DnsMode),
			Metadata: a.Metadata,
		})
	}
	return attachments
}

func (s *Server) GetAttachmentStats() []*apiv1.AttachmentStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats []*apiv1.AttachmentStats
	for id, state := range s.attachments {
		stat := &apiv1.AttachmentStats{
			Id:             id,
			PacketsAllowed: state.packetsAllowed,
			PacketsBlocked: state.packetsBlocked,
		}
		if state.dns != nil {
			stat.DnsQueriesAllowed, stat.DnsQueriesBlocked = state.dns.Stats()
		}
		stats = append(stats, stat)
	}
	return stats
}

func (s *Server) DaemonID() string {
	return s.daemonID
}

func (s *Server) Hostname() string {
	return s.hostname
}

func (s *Server) SetDnsMode(id string, mode apiv1.DnsMode) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.attachments[id]
	if !ok {
		return fmt.Errorf("attachment not found: %s", id)
	}
	if state.dns != nil {
		state.dns.SetMode(mode)
	}
	return nil
}

func (s *Server) AllowDomain(id string, domain string, includeSubdomains bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.attachments[id]
	if !ok {
		return fmt.Errorf("attachment not found: %s", id)
	}
	if state.dns != nil {
		state.dns.AllowDomain(domain, includeSubdomains)
	}
	return nil
}

func (s *Server) DenyDomain(id string, domain string, includeSubdomains bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.attachments[id]
	if !ok {
		return fmt.Errorf("attachment not found: %s", id)
	}
	if state.dns != nil {
		state.dns.DenyDomain(domain, includeSubdomains)
	}
	return nil
}

func (s *Server) RemoveDomain(id string, domain string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.attachments[id]
	if !ok {
		return fmt.Errorf("attachment not found: %s", id)
	}
	if state.dns != nil {
		state.dns.RemoveDomain(domain)
	}
	return nil
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
	var port int
	fmt.Sscanf(addr, "%*[^:]:%d", &port)
	return port
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
