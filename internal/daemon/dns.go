package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// DnsProxyFunc is called when DNS_MODE_PROXY is enabled to get a decision from the control plane
type DnsProxyFunc func(ctx context.Context, domain, queryType string) (DnsProxyDecision, error)

const defaultDNSTTLSeconds uint32 = 300

const dnsExchangeTimeout = 5 * time.Second

// A query holds the policy generation read lease through WriteMsg so a rule
// replacement cannot remove its exact admission before the answer is handed
// to the workload. Bound TCP reads/writes so a stalled local client cannot
// indefinitely delay policy reconciliation or attachment teardown.
const dnsClientIOTimeout = 5 * time.Second

const maxDNSUpstreams = 8

type DnsProxyDecision struct {
	Allow       bool
	AddToFilter bool
	IPs         []string
	TTLSeconds  uint32
}

type dnsStopState struct {
	done chan struct{}
	err  error
}

// DNSServer is a per-attachment DNS server that filters queries and populates
// the IP filter via its DNSFilterSink (which bounds each entry's lifetime;
// resolved-IP dedup and expiry live behind the sink, not here).
type DNSServer struct {
	attachmentID    string
	listenAddr      string
	defaultUpstream string
	logger          zerolog.Logger
	sink            DNSFilterSink
	proxyFunc       DnsProxyFunc

	mu             sync.RWMutex
	mode           apiv1.DnsMode
	allowedDomains map[string]bool // domain -> includeSubdomains
	deniedDomains  map[string]bool // domain -> includeSubdomains
	upstreams      []string
	generation     uint64
	limits         dnsAdmissionLimits
	limitCeilings  dnsAdmissionLimits
	churnLimits    dnsChurnLimits
	churnCeiling   dnsChurnLimits

	serverMu      sync.Mutex
	udp           *dns.Server
	tcp           *dns.Server
	udpConn       net.PacketConn
	tcpLn         net.Listener
	running       bool
	stopRequested bool
	stopping      bool
	stopState     *dnsStopState
	serveDone     chan struct{}
	startResult   chan error
	fatalErr      error
	shutdownOnce  sync.Once
	shutdownErr   error
	queryCtx      context.Context
	cancelQueries context.CancelFunc

	queriesAllowed atomic.Uint64
	queriesBlocked atomic.Uint64
	queriesErrors  atomic.Uint64
}

func NewDNSServer(attachmentID, listenAddr, upstream string, logger zerolog.Logger, sink DNSFilterSink, proxyFunc DnsProxyFunc, limitCeilings ...dnsAdmissionLimits) *DNSServer {
	upstreams, err := normalizeUpstreamServers(nil, upstream)
	if err != nil {
		// Production validates the daemon-global fallback before constructing
		// attachments. Keep invalid direct-test values fail-closed at query time.
		upstreams = []string{upstream}
	}
	ceilings := resolveDNSAdmissionCeilings(0, dnsAdmissionLimitOverrides{})
	churnCeiling := resolveDNSChurnCeiling(0, 0)
	if len(limitCeilings) != 0 {
		ceilings = limitCeilings[0]
	}
	if concrete, ok := sink.(*dnsFilterSink); ok {
		churnCeiling = concrete.ChurnCeiling()
	}
	server := &DNSServer{
		attachmentID:    attachmentID,
		listenAddr:      listenAddr,
		defaultUpstream: upstream,
		logger:          logger.With().Str("component", "dns").Str("addr", listenAddr).Logger(),
		sink:            sink,
		proxyFunc:       proxyFunc,
		mode:            apiv1.DnsMode_DNS_MODE_DISABLED,
		allowedDomains:  make(map[string]bool),
		deniedDomains:   make(map[string]bool),
		upstreams:       upstreams,
		generation:      1,
		limits:          ceilings,
		limitCeilings:   ceilings,
		churnLimits:     churnCeiling,
		churnCeiling:    churnCeiling,
	}
	if concrete, ok := sink.(*dnsFilterSink); ok {
		concrete.bindDNS(server)
	}
	return server
}

// Bind reserves both UDP and TCP on the same concrete address without serving
// queries. Attachment setup uses this split phase so listener feasibility is
// known before a protected bootstrap rule mutates an adopted pinned map.
func (s *DNSServer) Bind() error {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()

	if s.udpConn != nil || s.tcpLn != nil || s.running || s.stopping {
		return fmt.Errorf("DNS server already bound or started")
	}
	// Every accepted Bind begins a wholly new lifecycle. The previous Stop has
	// closed its lifecycle-local completion before making the object bindable.
	s.shutdownOnce = sync.Once{}
	s.shutdownErr = nil
	s.stopRequested = false
	s.fatalErr = nil
	s.serveDone = nil
	s.startResult = nil
	s.stopState = &dnsStopState{done: make(chan struct{})}

	udpConn, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("binding UDP DNS listener: %w", err)
	}
	// Binding UDP first lets :0 tests pick a port; TCP is then bound to the
	// exact same concrete address and port. A TCP bind failure closes UDP, so
	// an attachment can never expose a half-started resolver.
	tcpLn, err := net.Listen("tcp", udpConn.LocalAddr().String())
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("binding TCP DNS listener: %w", err)
	}

	s.udpConn = udpConn
	s.tcpLn = tcpLn
	return nil
}

type dnsServeEvent struct {
	network string
	started bool
	err     error
}

// Serve activates listeners previously reserved by Bind. Unexpected death of
// either protocol is supervised for the full lifetime: the sibling is shut
// down, fatalErr is published, and serveDone closes only after both exit.
func (s *DNSServer) Serve() error {
	s.serverMu.Lock()
	if s.udpConn == nil || s.tcpLn == nil {
		s.serverMu.Unlock()
		return fmt.Errorf("DNS server is not bound")
	}
	if s.running {
		s.serverMu.Unlock()
		return fmt.Errorf("DNS server already started")
	}
	events := make(chan dnsServeEvent, 4)
	s.startResult = make(chan error, 1)
	s.serveDone = make(chan struct{})
	s.stopRequested = false
	s.fatalErr = nil
	s.running = true
	s.queryCtx, s.cancelQueries = context.WithCancel(context.Background())
	s.udp = &dns.Server{
		PacketConn:   &dnsWriteDeadlinePacketConn{PacketConn: s.udpConn, timeout: dnsClientIOTimeout},
		Handler:      dns.HandlerFunc(s.handleDNS),
		ReadTimeout:  dnsClientIOTimeout,
		WriteTimeout: dnsClientIOTimeout,
		NotifyStartedFunc: func() {
			events <- dnsServeEvent{network: "udp", started: true}
		},
	}
	s.tcp = &dns.Server{
		Listener:     &dnsWriteDeadlineListener{Listener: s.tcpLn, timeout: dnsClientIOTimeout},
		Handler:      dns.HandlerFunc(s.handleDNS),
		ReadTimeout:  dnsClientIOTimeout,
		WriteTimeout: dnsClientIOTimeout,
		NotifyStartedFunc: func() {
			events <- dnsServeEvent{network: "tcp", started: true}
		},
	}
	udp, tcp := s.udp, s.tcp
	udpAddr, tcpAddr := s.udpConn.LocalAddr().String(), s.tcpLn.Addr().String()
	startResult, serveDone := s.startResult, s.serveDone
	s.serverMu.Unlock()

	go s.supervise(udp, tcp, events, startResult, serveDone)
	go func() {
		err := udp.ActivateAndServe()
		events <- dnsServeEvent{network: "udp", err: err}
	}()
	go func() {
		err := tcp.ActivateAndServe()
		events <- dnsServeEvent{network: "tcp", err: err}
	}()

	if err := <-startResult; err != nil {
		<-serveDone
		return err
	}
	s.logger.Info().Str("udp", udpAddr).Str("tcp", tcpAddr).Msg("started DNS server")
	return nil
}

type dnsWriteDeadlinePacketConn struct {
	net.PacketConn
	timeout time.Duration
	mu      sync.Mutex
}

func (c *dnsWriteDeadlinePacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	// UDP handlers share one PacketConn. Serialize the connection-wide
	// deadline with its write so another response cannot extend or clear the
	// bound while this response holds a DNS policy read lease.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(payload, addr)
}

type dnsWriteDeadlineListener struct {
	net.Listener
	timeout time.Duration
}

func (l *dnsWriteDeadlineListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &dnsWriteDeadlineConn{Conn: conn, timeout: l.timeout}, nil
}

type dnsWriteDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *dnsWriteDeadlineConn) Write(payload []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(payload)
}

func (s *DNSServer) Start() error {
	if err := s.Bind(); err != nil {
		return err
	}
	if err := s.Serve(); err != nil {
		_ = s.Stop()
		return err
	}
	return nil
}

func (s *DNSServer) supervise(udp, tcp *dns.Server, events <-chan dnsServeEvent, startResult chan<- error, serveDone chan<- struct{}) {
	started := make(map[string]bool, 2)
	exited := 0
	startReported := false
	fatal := false
	for exited < 2 {
		event := <-events
		if event.started {
			started[event.network] = true
			s.logger.Debug().Str("network", event.network).Msg("DNS listener started")
			if len(started) == 2 && !startReported {
				startResult <- nil
				startReported = true
			}
			continue
		}
		exited++
		s.serverMu.Lock()
		expected := s.stopRequested
		if !expected && !fatal {
			fatal = true
			if event.err == nil {
				event.err = fmt.Errorf("listener exited without error")
			}
			s.fatalErr = fmt.Errorf("%s DNS listener stopped unexpectedly: %w", event.network, event.err)
			s.logger.Error().Err(s.fatalErr).Str("network", event.network).Msg("DNS resolver failed; shutting down both protocols")
		}
		fatalErr := s.fatalErr
		cancelQueries := s.cancelQueries
		s.serverMu.Unlock()
		if fatal {
			if cancelQueries != nil {
				cancelQueries()
			}
			if !startReported {
				startResult <- fatalErr
				startReported = true
			}
			s.shutdownBound(udp, tcp)
		}
	}
	if !startReported {
		startResult <- fmt.Errorf("DNS listeners stopped before readiness")
	}
	s.serverMu.Lock()
	s.running = false
	s.serverMu.Unlock()
	close(serveDone)
}

func (s *DNSServer) shutdownBound(udp, tcp *dns.Server) error {
	s.shutdownOnce.Do(func() {
		var errs []error
		if udp != nil {
			if err := udp.Shutdown(); err != nil {
				errs = append(errs, fmt.Errorf("shutting down UDP DNS server: %w", err))
			}
		}
		if tcp != nil {
			if err := tcp.Shutdown(); err != nil {
				errs = append(errs, fmt.Errorf("shutting down TCP DNS server: %w", err))
			}
		}
		s.serverMu.Lock()
		udpConn, tcpLn := s.udpConn, s.tcpLn
		s.serverMu.Unlock()
		if udpConn != nil {
			if err := udpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("closing UDP DNS listener: %w", err))
			}
		}
		if tcpLn != nil {
			if err := tcpLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("closing TCP DNS listener: %w", err))
			}
		}
		s.shutdownErr = errors.Join(errs...)
	})
	return s.shutdownErr
}

func (s *DNSServer) Stop() error {
	s.serverMu.Lock()
	if s.stopping {
		state := s.stopState
		s.serverMu.Unlock()
		if state != nil {
			<-state.done
			return state.err
		}
		return nil
	}
	if s.udpConn == nil && s.tcpLn == nil {
		state := s.stopState
		s.serverMu.Unlock()
		if state != nil {
			return state.err
		}
		return nil
	}
	s.stopping = true
	s.stopRequested = true
	if s.cancelQueries != nil {
		s.cancelQueries()
	}
	udp, tcp := s.udp, s.tcp
	serveDone := s.serveDone
	state := s.stopState
	s.serverMu.Unlock()

	err := s.shutdownBound(udp, tcp)
	// A non-nil completion belongs to this exact Serve lifecycle. Always wait
	// for it, even if the supervisor has already flipped running after an
	// unexpected listener exit, before publishing the object as bindable.
	if serveDone != nil {
		<-serveDone
	}

	s.serverMu.Lock()
	if state != nil {
		state.err = err
	}
	s.udp, s.tcp, s.udpConn, s.tcpLn = nil, nil, nil, nil
	s.running = false
	s.queryCtx, s.cancelQueries = nil, nil
	if state != nil {
		close(state.done)
	}
	// Publish bindability only after the old lifecycle's completion and error
	// are immutable and visible to every concurrent Stop waiter.
	s.stopping = false
	s.serverMu.Unlock()
	return err
}

// Done closes when both protocol serve loops exit. Err is non-nil only for an
// unexpected listener failure, never for an ordinary Stop.
func (s *DNSServer) Done() <-chan struct{} {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	return s.serveDone
}

func (s *DNSServer) Err() error {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	return s.fatalErr
}

type preparedDNSRules struct {
	mode           apiv1.DnsMode
	allowedDomains map[string]bool
	deniedDomains  map[string]bool
	policyDomains  map[string]struct{}
	upstreams      []string
	limits         dnsAdmissionLimits
	churn          dnsChurnLimits
}

func prepareDNSRules(mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry, upstreamServers []string, fallback string, ceilings dnsAdmissionLimits, overrides dnsAdmissionLimitOverrides, churnCeiling dnsChurnLimits, maxChurnUnits uint32) (*preparedDNSRules, error) {
	if err := validateDNSMode(mode); err != nil {
		return nil, err
	}
	upstreams, err := normalizeUpstreamServers(upstreamServers, fallback)
	if err != nil {
		return nil, err
	}
	limits, err := ceilings.resolve(overrides)
	if err != nil {
		return nil, err
	}
	churn, err := churnCeiling.resolve(maxChurnUnits)
	if err != nil {
		return nil, err
	}
	prepared := &preparedDNSRules{
		mode:           mode,
		allowedDomains: make(map[string]bool, len(allowDomains)),
		deniedDomains:  make(map[string]bool, len(denyDomains)),
		policyDomains:  make(map[string]struct{}, len(allowDomains)+len(denyDomains)),
		upstreams:      upstreams,
		limits:         limits,
		churn:          churn,
	}
	if err := addPreparedDomains(prepared.allowedDomains, prepared.policyDomains, allowDomains, "allow"); err != nil {
		return nil, err
	}
	if err := addPreparedDomains(prepared.deniedDomains, prepared.policyDomains, denyDomains, "deny"); err != nil {
		return nil, err
	}
	if uint64(len(prepared.policyDomains)) > uint64(limits.maxTrackedDomains) {
		return nil, fmt.Errorf("DNS policy contains %d unique domains, total tracked-domain limit is %d", len(prepared.policyDomains), limits.maxTrackedDomains)
	}
	return prepared, nil
}

func addPreparedDomains(dst map[string]bool, all map[string]struct{}, entries []*apiv1.DomainEntry, list string) error {
	for i, entry := range entries {
		if entry == nil {
			return fmt.Errorf("DNS %s domain entry %d is nil", list, i)
		}
		normalized, err := validateAndNormalizeDomain(entry.Domain)
		if err != nil {
			return fmt.Errorf("invalid DNS %s domain %d: %w", list, i, err)
		}
		if _, duplicate := dst[normalized]; duplicate {
			return fmt.Errorf("duplicate canonical DNS %s domain %q", list, normalized)
		}
		dst[normalized] = entry.IncludeSubdomains
		all[normalized] = struct{}{}
	}
	return nil
}

func dnsLimitOverridesFromProto(cfg *apiv1.DnsConfig) dnsAdmissionLimitOverrides {
	if cfg == nil {
		return dnsAdmissionLimitOverrides{}
	}
	return dnsAdmissionLimitOverrides{
		maxIPsPerFamily:       cfg.MaxIpsPerFamily,
		maxIPsPerResponse:     cfg.MaxIpsPerResponse,
		maxIPsPerPolicyDomain: cfg.MaxIpsPerPolicyDomain,
		maxTrackedDomains:     cfg.MaxTrackedDomains,
		maxOwnershipEdges:     cfg.MaxOwnershipEdges,
	}
}

func (s *DNSServer) prepareConfig(cfg *apiv1.DnsConfig) (*preparedDNSRules, error) {
	if cfg == nil {
		cfg = &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_DISABLED}
	}
	return prepareDNSRules(cfg.Mode, cfg.AllowDomains, cfg.DenyDomains, cfg.UpstreamServers,
		s.defaultUpstream, s.limitCeilings, dnsLimitOverridesFromProto(cfg), s.churnCeiling, cfg.MaxChurnUnits)
}

func (s *DNSServer) applyPreparedRules(prepared *preparedDNSRules) error {
	if prepared == nil {
		return fmt.Errorf("prepared DNS rules are nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sink != nil {
		if err := s.sink.ValidateLimits(prepared.limits); err != nil {
			return err
		}
		resolver := ownershipResolver(prepared.mode, prepared.allowedDomains, prepared.deniedDomains)
		if err := s.sink.ReconcilePolicy(prepared.limits, prepared.churn, prepared.policyDomains, resolver, true); err != nil {
			return errors.Join(err, s.sink.FailClosedIfAmbiguous(err))
		}
	}
	s.mode = prepared.mode
	s.allowedDomains = cloneDomainRules(prepared.allowedDomains)
	s.deniedDomains = cloneDomainRules(prepared.deniedDomains)
	s.upstreams = append([]string(nil), prepared.upstreams...)
	s.limits = prepared.limits
	s.churnLimits = prepared.churn
	s.generation++
	s.logger.Debug().Str("mode", prepared.mode.String()).Uint64("generation", s.generation).Msg("DNS rules replaced")
	return nil
}

func (s *DNSServer) preflightPreparedRules(prepared *preparedDNSRules) error {
	if prepared == nil {
		return fmt.Errorf("prepared DNS rules are nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sink == nil {
		return nil
	}
	resolver := ownershipResolver(prepared.mode, prepared.allowedDomains, prepared.deniedDomains)
	return s.sink.PreflightPolicy(prepared.limits, prepared.churn, prepared.policyDomains, resolver, true)
}

func cloneDomainRules(rules map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(rules))
	for domain, subdomains := range rules {
		clone[domain] = subdomains
	}
	return clone
}

func (s *DNSServer) currentConfigLocked() *apiv1.DnsConfig {
	cfg := &apiv1.DnsConfig{
		Mode:                  s.mode,
		UpstreamServers:       append([]string(nil), s.upstreams...),
		MaxIpsPerFamily:       s.limits.maxIPsPerFamily,
		MaxIpsPerResponse:     s.limits.maxIPsPerResponse,
		MaxIpsPerPolicyDomain: s.limits.maxIPsPerPolicyDomain,
		MaxTrackedDomains:     s.limits.maxTrackedDomains,
		MaxOwnershipEdges:     s.limits.maxOwnershipEdges,
		MaxChurnUnits:         s.churnLimits.maxUnits,
	}
	for domain, include := range s.allowedDomains {
		cfg.AllowDomains = append(cfg.AllowDomains, &apiv1.DomainEntry{Domain: domain, IncludeSubdomains: include})
	}
	for domain, include := range s.deniedDomains {
		cfg.DenyDomains = append(cfg.DenyDomains, &apiv1.DomainEntry{Domain: domain, IncludeSubdomains: include})
	}
	sort.Slice(cfg.AllowDomains, func(i, j int) bool { return cfg.AllowDomains[i].Domain < cfg.AllowDomains[j].Domain })
	sort.Slice(cfg.DenyDomains, func(i, j int) bool { return cfg.DenyDomains[i].Domain < cfg.DenyDomains[j].Domain })
	return cfg
}

func (s *DNSServer) mutateConfig(mut func(*apiv1.DnsConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.currentConfigLocked()
	if err := mut(cfg); err != nil {
		return err
	}
	prepared, err := s.prepareConfig(cfg)
	if err != nil {
		return err
	}
	if s.sink != nil {
		resolver := ownershipResolver(prepared.mode, prepared.allowedDomains, prepared.deniedDomains)
		if err := s.sink.ReconcilePolicy(prepared.limits, prepared.churn, prepared.policyDomains, resolver, false); err != nil {
			return errors.Join(err, s.sink.FailClosedIfAmbiguous(err))
		}
	}
	s.mode = prepared.mode
	s.allowedDomains = prepared.allowedDomains
	s.deniedDomains = prepared.deniedDomains
	s.upstreams = prepared.upstreams
	s.limits = prepared.limits
	s.churnLimits = prepared.churn
	s.generation++
	return nil
}

func (s *DNSServer) SetMode(mode apiv1.DnsMode) error {
	return s.mutateConfig(func(cfg *apiv1.DnsConfig) error {
		cfg.Mode = mode
		return nil
	})
}

// setModeForRestore holds a restored filtering resolver in empty ALLOWLIST
// without treating that local safety posture as authoritative reconciliation;
// in particular it preserves provisional exact keys until the CP ack arrives.
func (s *DNSServer) setModeForRestore(mode apiv1.DnsMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.generation++
}

func (s *DNSServer) AllowDomain(domain string, includeSubdomains bool) error {
	normalized, err := validateAndNormalizeDomain(domain)
	if err != nil {
		return err
	}
	return s.mutateConfig(func(cfg *apiv1.DnsConfig) error {
		cfg.AllowDomains = upsertDomainEntry(cfg.AllowDomains, normalized, includeSubdomains)
		return nil
	})
}

func (s *DNSServer) DenyDomain(domain string, includeSubdomains bool) error {
	normalized, err := validateAndNormalizeDomain(domain)
	if err != nil {
		return err
	}
	return s.mutateConfig(func(cfg *apiv1.DnsConfig) error {
		cfg.DenyDomains = upsertDomainEntry(cfg.DenyDomains, normalized, includeSubdomains)
		return nil
	})
}

func upsertDomainEntry(entries []*apiv1.DomainEntry, normalized string, includeSubdomains bool) []*apiv1.DomainEntry {
	for _, entry := range entries {
		if entry.Domain == normalized {
			entry.Domain = normalized
			entry.IncludeSubdomains = includeSubdomains
			return entries
		}
	}
	return append(entries, &apiv1.DomainEntry{Domain: normalized, IncludeSubdomains: includeSubdomains})
}

func (s *DNSServer) RemoveDomain(domain string) error {
	normalized, err := validateAndNormalizeDomain(domain)
	if err != nil {
		return err
	}
	return s.mutateConfig(func(cfg *apiv1.DnsConfig) error {
		cfg.AllowDomains = removeDomainEntry(cfg.AllowDomains, normalized)
		cfg.DenyDomains = removeDomainEntry(cfg.DenyDomains, normalized)
		return nil
	})
}

func removeDomainEntry(entries []*apiv1.DomainEntry, normalized string) []*apiv1.DomainEntry {
	result := entries[:0]
	for _, entry := range entries {
		if entry.Domain != normalized {
			result = append(result, entry)
		}
	}
	return result
}

func (s *DNSServer) ReplaceRules(mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry, upstreamOverride ...[]string) error {
	if len(upstreamOverride) > 1 {
		return fmt.Errorf("at most one upstream server list may be supplied")
	}
	var upstreamServers []string
	if len(upstreamOverride) == 1 {
		upstreamServers = upstreamOverride[0]
	}
	prepared, err := prepareDNSRules(mode, allowDomains, denyDomains, upstreamServers,
		s.defaultUpstream, s.limitCeilings, dnsAdmissionLimitOverrides{}, s.churnCeiling, 0)
	if err != nil {
		return err
	}
	return s.applyPreparedRules(prepared)
}

func (s *DNSServer) Stats() (allowed, blocked, queryErrors uint64) {
	return s.queriesAllowed.Load(), s.queriesBlocked.Load(), s.queriesErrors.Load()
}

type dnsQuerySnapshot struct {
	generation  uint64
	mode        apiv1.DnsMode
	queryDomain string
	owner       dnsPolicyOwner
	upstreams   []string
	shouldAdmit bool
	proxyFunc   DnsProxyFunc
	blocked     bool
}

func (s dnsQuerySnapshot) canonicalAdmission(records []dnsAdmissionRecord) dnsCanonicalAdmissionRequest {
	return dnsCanonicalAdmissionRequest{
		queryDomain: dnsCanonicalDomain(s.queryDomain),
		owner: dnsCanonicalPolicyOwner{
			kind:   s.owner.kind,
			domain: dnsCanonicalDomain(s.owner.domain),
		},
		records: records,
	}
}

type dnsPolicyDecision struct {
	mode          apiv1.DnsMode
	owner         dnsPolicyOwner
	shouldResolve bool
	shouldAdmit   bool
	blocked       bool
}

// queryDecisionLocked is the single DNS policy decision table. Snapshot and
// response-time revalidation both call it while holding s.mu, so a new mode
// cannot accidentally update one branch without the other.
func (s *DNSServer) queryDecisionLocked(domain string) (dnsPolicyDecision, error) {
	decision := dnsPolicyDecision{mode: s.mode}
	switch s.mode {
	case apiv1.DnsMode_DNS_MODE_DISABLED:
		decision.shouldResolve = true
	case apiv1.DnsMode_DNS_MODE_ALLOWLIST:
		match, owner := evaluateCanonicalDomainRules(domain, s.allowedDomains, s.deniedDomains)
		if match != domainDecisionAllow {
			decision.blocked = true
			break
		}
		decision.owner = dnsPolicyOwner{kind: dnsOwnerRule, domain: owner}
		decision.shouldResolve, decision.shouldAdmit = true, true
	case apiv1.DnsMode_DNS_MODE_DENYLIST:
		match, owner := evaluateCanonicalDomainRules(domain, s.allowedDomains, s.deniedDomains)
		if match == domainDecisionDeny {
			decision.blocked = true
			break
		}
		if match == domainDecisionAllow {
			decision.owner = dnsPolicyOwner{kind: dnsOwnerRule, domain: owner}
		} else {
			decision.owner = dnsPolicyOwner{kind: dnsOwnerDenylistDefault, domain: domain}
		}
		decision.shouldResolve, decision.shouldAdmit = true, true
	case apiv1.DnsMode_DNS_MODE_PROXY:
		decision.owner = dnsPolicyOwner{kind: dnsOwnerProxy, domain: domain}
		decision.shouldResolve = true
	default:
		return dnsPolicyDecision{}, fmt.Errorf("invalid DNS mode %d", s.mode)
	}
	return decision, nil
}

func (s *DNSServer) snapshotQuery(domain string) (dnsQuerySnapshot, bool, error) {
	normalized, err := validateAndNormalizeDomain(domain)
	if err != nil {
		return dnsQuerySnapshot{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	decision, err := s.queryDecisionLocked(normalized)
	if err != nil {
		return dnsQuerySnapshot{}, false, err
	}
	snapshot := dnsQuerySnapshot{
		generation:  s.generation,
		mode:        decision.mode,
		queryDomain: normalized,
		owner:       decision.owner,
		upstreams:   append([]string(nil), s.upstreams...),
		shouldAdmit: decision.shouldAdmit,
		proxyFunc:   s.proxyFunc,
		blocked:     decision.blocked,
	}
	return snapshot, decision.shouldResolve, nil
}

func (s *DNSServer) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}

	q := req.Question[0]
	domain := q.Name
	s.serverMu.Lock()
	queryCtx := s.queryCtx
	s.serverMu.Unlock()
	if queryCtx == nil {
		queryCtx = context.Background()
	}

	snapshot, shouldResolve, err := s.snapshotQuery(domain)
	if err != nil {
		s.logger.Debug().Err(err).Str("domain", domain).Msg("invalid DNS query domain")
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}

	if snapshot.mode == apiv1.DnsMode_DNS_MODE_PROXY {
		if snapshot.proxyFunc == nil {
			s.logger.Warn().Str("domain", domain).Msg("DNS proxy unavailable")
			s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
			return
		}
		queryType := dns.TypeToString[q.Qtype]
		// The control plane and local ownership graph must decide policy for
		// the same identity. Hand off the wire-canonical, lowercase FQDN while
		// preserving the original question name in the eventual DNS response.
		decision, err := snapshot.proxyFunc(queryCtx, dns.Fqdn(snapshot.queryDomain), queryType)
		if err != nil {
			s.logger.Error().Err(err).Str("domain", domain).Msg("control plane query failed")
			s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
			return
		}
		if !decision.Allow {
			snapshot.blocked = true
			s.logger.Debug().Str("domain", domain).Msg("DNS query blocked by control plane")
			s.writeIfCurrent(w, req, refusedResponse(req), snapshot, dnsOutcomeBlocked)
			return
		}
		shouldResolve = true
		snapshot.shouldAdmit = decision.AddToFilter
		if len(decision.IPs) > 0 {
			resp, err := s.proxyResponse(req, domain, decision.IPs, decision.TTLSeconds)
			if err != nil {
				s.logger.Error().Err(err).Str("domain", domain).Msg("invalid proxy override response")
				s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
				return
			}
			s.admitAndWrite(w, req, resp, snapshot, dnsOutcomeAllowed)
			return
		}
	}

	if !shouldResolve {
		s.logger.Debug().Str("domain", domain).Msg("DNS query blocked")
		s.writeIfCurrent(w, req, refusedResponse(req), snapshot, dnsOutcomeBlocked)
		return
	}

	resp, err := exchangeUpstreams(queryCtx, req, snapshot.upstreams)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("upstream DNS query failed")
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	resp = sanitizeAddressHints(resp, snapshot.mode)

	outcome := dnsOutcomeAllowed
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		outcome = dnsOutcomeError
	}
	s.admitAndWrite(w, req, resp, snapshot, outcome)
}

func (s *DNSServer) writeIfCurrent(w dns.ResponseWriter, req, resp *dns.Msg, snapshot dnsQuerySnapshot, outcome dnsOutcome) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.queryStillCurrentLocked(snapshot) {
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	s.writeOutcome(w, req, resp, outcome)
}

func (s *DNSServer) queryStillCurrentLocked(snapshot dnsQuerySnapshot) bool {
	if s.generation != snapshot.generation || s.mode != snapshot.mode {
		return false
	}
	decision, err := s.queryDecisionLocked(snapshot.queryDomain)
	if err != nil {
		return false
	}
	// Proxy allow/deny is external to the local policy generation. Revalidate
	// only that the query still belongs to the same proxy owner.
	if snapshot.mode == apiv1.DnsMode_DNS_MODE_PROXY {
		return snapshot.owner == decision.owner
	}
	return snapshot.owner == decision.owner && snapshot.blocked == decision.blocked &&
		snapshot.shouldAdmit == decision.shouldAdmit
}

// admitAndWrite is the linearization point for a filtered DNS response. The
// attachment barrier is acquired before the DNS policy read lease; generation
// and winning owner are revalidated; the entire response address set is one
// exact-tier transaction; and the lease remains held through the bounded
// WriteMsg. ReplaceRules therefore cannot remove admission before the workload
// receives the answer.
func (s *DNSServer) admitAndWrite(w dns.ResponseWriter, req, resp *dns.Msg, snapshot dnsQuerySnapshot, outcome dnsOutcome) {
	records, err := dnsAdmissionRecords(resp)
	if err != nil {
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	if !snapshot.shouldAdmit || len(records) == 0 {
		s.mu.RLock()
		if !s.queryStillCurrentLocked(snapshot) {
			s.mu.RUnlock()
			s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
			return
		}
		// DISABLED is the explicit pass-through exception. Every filtering
		// mode must prove address-bearing answers admitted; in particular a
		// PROXY decision with add_to_filter=false is not such proof.
		if len(records) != 0 && snapshot.mode != apiv1.DnsMode_DNS_MODE_DISABLED && !snapshot.shouldAdmit {
			s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
			s.mu.RUnlock()
			return
		}
		s.writeOutcome(w, req, resp, outcome)
		s.mu.RUnlock()
		return
	}
	if s.sink == nil {
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	done, err := s.sink.BeginAdmission()
	if err != nil {
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	s.mu.RLock()
	if !s.queryStillCurrentLocked(snapshot) {
		s.mu.RUnlock()
		done()
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	err = s.sink.AdmitCanonicalResponse(snapshot.canonicalAdmission(records))
	var failClosedErr error
	if err != nil {
		failClosedErr = s.sink.FailClosedIfAmbiguous(err)
		s.mu.RUnlock()
		done()
		if errors.Is(err, filter.ErrDNSAllowRollback) {
			failClosedErr = errors.Join(failClosedErr, s.sink.QuarantineAmbiguity(err))
		}
		admissionErr := errors.Join(err, failClosedErr)
		if isDNSAdmissionPressure(err) && !errors.Is(err, filter.ErrDNSAllowRollback) {
			// The production sink owns the rate-limited capacity warning and
			// cumulative counter. Keep per-query diagnostics below Warn so
			// sustained resolver pressure cannot bypass that limiter.
			s.logger.Debug().Err(admissionErr).Str("domain", snapshot.queryDomain).Msg("DNS response rejected by bounded admission pressure")
		} else {
			s.logger.Warn().Err(admissionErr).Str("domain", snapshot.queryDomain).Msg("DNS response admission failed")
		}
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	s.writeOutcome(w, req, resp, outcome)
	s.mu.RUnlock()
	done()
}

func dnsAdmissionRecords(resp *dns.Msg) ([]dnsAdmissionRecord, error) {
	var records []dnsAdmissionRecord
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			switch value := rr.(type) {
			case *dns.A:
				if normalizeIP(value.A) == nil {
					return nil, fmt.Errorf("invalid A address in DNS response")
				}
				records = append(records, dnsAdmissionRecord{ip: value.A, ttl: time.Duration(value.Hdr.Ttl) * time.Second})
			case *dns.AAAA:
				if normalizeIP(value.AAAA) == nil {
					return nil, fmt.Errorf("invalid AAAA address in DNS response")
				}
				records = append(records, dnsAdmissionRecord{ip: value.AAAA, ttl: time.Duration(value.Hdr.Ttl) * time.Second})
			}
		}
	}
	return records, nil
}

// addIPToFilter is retained as an internal test/benchmark helper. Production
// query handling always uses admitAndWrite so a complete response is one
// transaction and policy generation is revalidated before mutation.
func (s *DNSServer) addIPToFilter(domain string, ip net.IP, _ int, ttlSeconds uint32) error {
	if s.sink == nil {
		return nil
	}
	if ttlSeconds == 0 {
		ttlSeconds = defaultDNSTTLSeconds
	}
	done, err := s.sink.BeginAdmission()
	if err != nil {
		return err
	}
	defer done()
	normalized, err := validateAndNormalizeDomain(domain)
	if err != nil {
		return err
	}
	canonical := dnsCanonicalDomain(normalized)
	return s.sink.AdmitCanonicalResponse(dnsCanonicalAdmissionRequest{
		queryDomain: canonical,
		owner:       dnsCanonicalPolicyOwner{kind: dnsOwnerRule, domain: canonical},
		records:     []dnsAdmissionRecord{{ip: ip, ttl: time.Duration(ttlSeconds) * time.Second}},
	})
}

type dnsOutcome uint8

const (
	dnsOutcomeAllowed dnsOutcome = iota
	dnsOutcomeBlocked
	dnsOutcomeError
)

// writeOutcome is the only query-counter mutation point. A response-write
// failure is an internal error, and every query increments exactly one bucket.
func (s *DNSServer) writeOutcome(w dns.ResponseWriter, req, resp *dns.Msg, outcome dnsOutcome) {
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		limit := uint16(dns.MinMsgSize)
		if opt := req.IsEdns0(); opt != nil && opt.UDPSize() > limit {
			limit = opt.UDPSize()
		}
		// The upstream may return a message larger than the workload advertised.
		// miekg/dns does not truncate automatically in WriteMsg, so do it here;
		// TC prompts the workload to retry this same per-attachment listener over TCP.
		resp = resp.Copy()
		resp.Truncate(int(limit))
	}
	if err := w.WriteMsg(resp); err != nil {
		s.queriesErrors.Add(1)
		s.logger.Error().Err(err).Msg("failed to write DNS response")
		return
	}
	switch outcome {
	case dnsOutcomeAllowed:
		s.queriesAllowed.Add(1)
	case dnsOutcomeBlocked:
		s.queriesBlocked.Add(1)
	case dnsOutcomeError:
		s.queriesErrors.Add(1)
	}
}

func refusedResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeRefused)
	return resp
}

func servFailResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	return resp
}

// exchangeUpstreams performs deterministic ordered failover. Each upstream is
// tried over UDP first; a truncated response is retried against that same
// upstream over TCP. A failed TCP retry never leaks the truncated UDP answer.
func exchangeUpstreams(ctx context.Context, req *dns.Msg, upstreams []string) (*dns.Msg, error) {
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("no DNS upstreams configured")
	}
	var errs []error
	for _, upstream := range upstreams {
		udpClient := &dns.Client{Net: "udp", Timeout: dnsExchangeTimeout}
		resp, err := exchangeDNSContext(ctx, udpClient, req.Copy(), upstream)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s UDP: %w", upstream, err))
			continue
		}
		if !resp.Truncated {
			if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
				errs = append(errs, fmt.Errorf("%s UDP returned %s", upstream, dns.RcodeToString[resp.Rcode]))
				continue
			}
			return resp, nil
		}
		tcpClient := &dns.Client{Net: "tcp", Timeout: dnsExchangeTimeout}
		resp, err = exchangeDNSContext(ctx, tcpClient, req.Copy(), upstream)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s TCP retry after truncated UDP: %w", upstream, err))
			continue
		}
		if resp.Truncated {
			errs = append(errs, fmt.Errorf("%s TCP response was truncated", upstream))
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			errs = append(errs, fmt.Errorf("%s TCP returned %s", upstream, dns.RcodeToString[resp.Rcode]))
			continue
		}
		return resp, nil
	}
	return nil, errors.Join(errs...)
}

// exchangeDNSContext augments miekg/dns's deadline support with immediate
// cancellation. ExchangeWithConnContext applies context deadlines, but a
// context cancelled after a blocking read begins does not itself wake that
// read; closing this query-local socket does.
func exchangeDNSContext(ctx context.Context, client *dns.Client, req *dns.Msg, upstream string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, upstream)
	if err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	resp, _, exchangeErr := client.ExchangeWithConnContext(ctx, req, conn)
	stopCancel()
	_ = conn.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return resp, exchangeErr
}

// sanitizeAddressHints always copies the response before applying policy so a
// shared upstream message is never mutated. Disabled mode is exact pass-through;
// filtering modes remove ipv4hint/ipv6hint from both SVCB and HTTPS records.
func sanitizeAddressHints(resp *dns.Msg, mode apiv1.DnsMode) *dns.Msg {
	copy := resp.Copy()
	if mode == apiv1.DnsMode_DNS_MODE_DISABLED {
		return copy
	}
	for _, section := range [][]dns.RR{copy.Answer, copy.Ns, copy.Extra} {
		for _, rr := range section {
			switch value := rr.(type) {
			case *dns.SVCB:
				value.Value = withoutAddressHints(value.Value)
			case *dns.HTTPS:
				value.Value = withoutAddressHints(value.Value)
			}
		}
	}
	return copy
}

func withoutAddressHints(values []dns.SVCBKeyValue) []dns.SVCBKeyValue {
	filtered := make([]dns.SVCBKeyValue, 0, len(values))
	for _, value := range values {
		switch value := value.(type) {
		case *dns.SVCBIPv4Hint, *dns.SVCBIPv6Hint:
			continue
		case *dns.SVCBMandatory:
			// A mandatory parameter naming a removed hint makes the entire RR
			// unusable. Keep the declaration internally consistent while
			// preserving every unrelated mandatory key in its original order.
			codes := make([]dns.SVCBKey, 0, len(value.Code))
			for _, code := range value.Code {
				if code != dns.SVCB_IPV4HINT && code != dns.SVCB_IPV6HINT {
					codes = append(codes, code)
				}
			}
			if len(codes) != 0 {
				filtered = append(filtered, &dns.SVCBMandatory{Code: codes})
			}
		default:
			filtered = append(filtered, value)
		}
	}
	return filtered
}

type domainDecision uint8

const (
	domainDecisionNone domainDecision = iota
	domainDecisionAllow
	domainDecisionDeny
)

func (s *DNSServer) evaluateDomainLocked(domain string) domainDecision {
	decision, _ := evaluateDomainRules(domain, s.allowedDomains, s.deniedDomains)
	return decision
}

// evaluateDomainRules returns both the decision and the normalized winning
// rule domain. Search is most-specific first and deny wins at equal
// specificity, matching the resolver's historical precedence contract.
func evaluateDomainRules(domain string, allowedDomains, deniedDomains map[string]bool) (domainDecision, string) {
	canonical, err := validateAndNormalizeDomain(domain)
	if err != nil {
		return domainDecisionNone, ""
	}
	return evaluateCanonicalDomainRules(canonical, allowedDomains, deniedDomains)
}

// evaluateCanonicalDomainRules evaluates a wire-canonical domain against
// wire-canonical policy keys. Keeping this internal split avoids re-packing a
// query after snapshotQuery has already validated and canonicalized it.
func evaluateCanonicalDomainRules(domain string, allowedDomains, deniedDomains map[string]bool) (domainDecision, string) {
	for candidate := domain; candidate != ""; {
		exact := candidate == domain
		allow := false
		deny := false
		if includeSubdomains, ok := allowedDomains[candidate]; ok && (exact || includeSubdomains) {
			allow = true
		}
		if includeSubdomains, ok := deniedDomains[candidate]; ok && (exact || includeSubdomains) {
			deny = true
		}
		if deny {
			return domainDecisionDeny, candidate
		}
		if allow {
			return domainDecisionAllow, candidate
		}
		if candidate == "." {
			break
		}
		next, end := dns.NextLabel(candidate, 0)
		if end {
			// The DNS root is the parent of every top-level label. A configured
			// root rule with include_subdomains=true must therefore participate
			// after the TLD, while a root query remains an exact match above.
			candidate = "."
			continue
		}
		candidate = candidate[next:]
	}
	return domainDecisionNone, ""
}

func ownershipResolver(mode apiv1.DnsMode, allowedDomains, deniedDomains map[string]bool) dnsOwnershipResolver {
	return func(query string) (dnsPolicyOwner, bool) {
		decision, owner := evaluateCanonicalDomainRules(query, allowedDomains, deniedDomains)
		switch mode {
		case apiv1.DnsMode_DNS_MODE_ALLOWLIST:
			if decision == domainDecisionAllow {
				return dnsPolicyOwner{kind: dnsOwnerRule, domain: owner}, true
			}
		case apiv1.DnsMode_DNS_MODE_DENYLIST:
			if decision == domainDecisionDeny {
				return dnsPolicyOwner{}, false
			}
			if decision == domainDecisionAllow {
				return dnsPolicyOwner{kind: dnsOwnerRule, domain: owner}, true
			}
			return dnsPolicyOwner{kind: dnsOwnerDenylistDefault, domain: query}, true
		}
		return dnsPolicyOwner{}, false
	}
}

func (s *DNSServer) proxyResponse(req *dns.Msg, domain string, ips []string, ttlSeconds uint32) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	if ttlSeconds == 0 {
		ttlSeconds = defaultDNSTTLSeconds
	}
	qType := uint16(0)
	if len(req.Question) > 0 {
		qType = req.Question[0].Qtype
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid proxy override IP %q", ipStr)
		}

		if ip4 := ip.To4(); ip4 != nil {
			if qType != dns.TypeA && qType != dns.TypeANY {
				continue
			}
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttlSeconds},
				A:   ip4,
			}
			resp.Answer = append(resp.Answer, rr)

		} else {
			if qType != dns.TypeAAAA && qType != dns.TypeANY {
				continue
			}
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttlSeconds},
				AAAA: ip,
			}
			resp.Answer = append(resp.Answer, rr)

		}
	}
	return resp, nil
}

// normalizeUpstreamServers validates, canonicalizes, and ordered-deduplicates
// upstream endpoints. Empty per-attachment state uses the daemon-global
// fallback. IPv6 literals must use bracketed host:port form. The capacity
// limit applies to unique canonical endpoints, not duplicate spellings.
func normalizeUpstreamServers(values []string, fallback string) ([]string, error) {
	if len(values) == 0 {
		values = []string{fallback}
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized, err := normalizeUpstreamServer(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
		if len(result) > maxDNSUpstreams {
			return nil, fmt.Errorf("too many unique DNS upstreams: got at least %d, maximum is %d", len(result), maxDNSUpstreams)
		}
	}
	return result, nil
}

func normalizeUpstreamServer(value string) (string, error) {
	value = strings.TrimSpace(value)
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("invalid DNS upstream %q (expected host:port; bracket IPv6 literals): %w", value, err)
	}
	if host == "" {
		return "", fmt.Errorf("invalid DNS upstream %q: host is empty", value)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid DNS upstream %q: port must be an integer in 1-65535", value)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsUnspecified() {
			return "", fmt.Errorf("invalid DNS upstream %q: wildcard address is not routable", value)
		}
		host = addr.String()
	} else {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if _, ok := dns.IsDomainName(host); !ok || host == "" {
			return "", fmt.Errorf("invalid DNS upstream %q: host is neither an IP literal nor a DNS hostname", value)
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// resolveConcreteDNSListenIP resolves dns.listen_addr once at daemon startup.
// Numeric IPv4/IPv6 literals are preferred; hostnames are accepted and choose
// a deterministic IPv4-first address. Wildcards are rejected because an
// attachment cannot use 0.0.0.0/:: as a resolver destination or bootstrap
// host route. Scoped IPv6 listeners are rejected because a zone is meaningful
// in the daemon namespace but cannot be encoded in an attachment policy CIDR.
func resolveConcreteDNSListenIP(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("listen address is empty")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsUnspecified() {
			return "", fmt.Errorf("wildcard address %s is not a usable workload resolver endpoint", addr)
		}
		if addr.Zone() != "" {
			return "", fmt.Errorf("scoped IPv6 address %s cannot be represented as a filter host route", addr)
		}
		return addr.Unmap().String(), nil
	}
	hostname := strings.TrimSuffix(strings.ToLower(host), ".")
	if _, ok := dns.IsDomainName(hostname); !ok || hostname == "" {
		return "", fmt.Errorf("%q is neither an IP literal nor a DNS hostname", host)
	}
	resolved, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("looking up hostname %q: %w", hostname, err)
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	seen := make(map[netip.Addr]struct{}, len(resolved))
	for _, ip := range resolved {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		addresses = append(addresses, addr)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("hostname %q resolved to no usable IP addresses", hostname)
	}
	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].Is4() != addresses[j].Is4() {
			return addresses[i].Is4()
		}
		return addresses[i].Less(addresses[j])
	})
	return addresses[0].String(), nil
}

func dnsBootstrapCIDR(dnsAddress string) (*net.IPNet, error) {
	_, cidr, err := canonicalDNSListenerAddress(dnsAddress, resolveConcreteDNSListenIP)
	return cidr, err
}

// canonicalDNSListenerAddress resolves the host exactly once and derives both
// the bind/advertised endpoint and protected host route from that same result.
func canonicalDNSListenerAddress(dnsAddress string, resolve func(string) (string, error)) (string, *net.IPNet, error) {
	host, port, err := net.SplitHostPort(dnsAddress)
	if err != nil {
		return "", nil, fmt.Errorf("invalid DNS listener address %q: %w", dnsAddress, err)
	}
	concrete, err := resolve(host)
	if err != nil {
		return "", nil, err
	}
	ip := net.ParseIP(concrete)
	if ip4 := ip.To4(); ip4 != nil {
		return net.JoinHostPort(ip4.String(), port), &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	ip = ip.To16()
	if ip == nil {
		return "", nil, fmt.Errorf("DNS listener %q did not resolve to an IP", dnsAddress)
	}
	return net.JoinHostPort(ip.String(), port), &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func validateAndNormalizeDomain(domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain is empty")
	}
	// Validate the original presentation before adding a root separator. This
	// rejects malformed input such as "example.." instead of laundering it
	// into a different valid key. Leading/trailing spaces are label bytes, not
	// UI whitespace, and are intentionally preserved for wire canonicalization.
	if _, ok := dns.IsDomainName(domain); !ok {
		return "", fmt.Errorf("%q is not a valid DNS domain", domain)
	}

	// Policy configuration and unpacked DNS questions may spell the same wire
	// label bytes differently (for example \046 vs \., \092 vs \\, or \032 vs
	// \ ). Round-trip through the uncompressed wire form so every equivalent
	// spelling converges on the exact same policy and ownership key.
	const maxDNSNameWireBytes = 255
	wire := make([]byte, maxDNSNameWireBytes)
	packed, err := dns.PackDomainName(dns.Fqdn(domain), wire, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid DNS domain: %w", domain, err)
	}
	if packed > len(wire) {
		return "", fmt.Errorf("%q is not a valid DNS domain: wire form uses %d bytes, maximum is %d", domain, packed, len(wire))
	}
	canonical, unpacked, err := dns.UnpackDomainName(wire[:packed], 0)
	if err != nil {
		return "", fmt.Errorf("canonicalizing DNS domain %q: %w", domain, err)
	}
	if unpacked != packed {
		return "", fmt.Errorf("canonicalizing DNS domain %q consumed %d of %d wire bytes", domain, unpacked, packed)
	}
	canonical = dns.CanonicalName(canonical)
	if canonical == "." {
		return canonical, nil
	}
	// UnpackDomainName always returns an FQDN and escapes any literal label
	// dots, so the final byte is the one true root separator.
	return canonical[:len(canonical)-1], nil
}

var errDNSProxyUnavailable = errors.New("DNS proxy unavailable")
