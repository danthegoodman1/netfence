package daemon

import (
	"context"
	"fmt"
	"os"
	"sync"
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

	cpClient *ControlPlaneClient
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
	}

	for port := cfg.DNS.PortMin; port <= cfg.DNS.PortMax; port++ {
		s.portPool[port] = false
	}

	existing, err := st.GetAllAttachments()
	if err != nil {
		return nil, fmt.Errorf("loading existing attachments: %w", err)
	}
	for i := range existing {
		s.attachments[existing[i].ID] = &attachmentState{info: &existing[i]}
		port := extractPort(existing[i].DnsAddress)
		if port > 0 {
			s.portPool[port] = true
		}
	}

	return s, nil
}

func (s *Server) SetControlPlaneClient(cp *ControlPlaneClient) {
	s.cpClient = cp
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
	if s.cpClient != nil {
		proxyFunc = s.cpClient.MakeProxyFunc(id)
	}
	dnsServer := NewDNSServer(id, dnsAddr, s.cfg.DNS.Upstream, s.logger, nil, proxyFunc)
	if err := dnsServer.Start(); err != nil {
		s.releasePort(port)
		s.store.DeleteAttachment(id)
		return nil, fmt.Errorf("starting DNS server: %w", err)
	}

	s.attachments[id] = &attachmentState{info: attachment, dns: dnsServer}

	s.logger.Info().
		Str("id", id).
		Str("target", target).
		Str("type", attachType.String()).
		Str("dns_address", dnsAddr).
		Msg("attached filter")

	if s.cpClient != nil {
		s.cpClient.SendSubscribed(&apiv1.Subscribed{
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

	delete(s.attachments, req.Id)

	s.logger.Info().
		Str("id", req.Id).
		Str("target", state.info.Target).
		Msg("detached filter")

	if s.cpClient != nil {
		s.cpClient.SendUnsubscribed(&apiv1.Unsubscribed{
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
	if s.cpClient != nil {
		cpState = s.cpClient.State()
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
