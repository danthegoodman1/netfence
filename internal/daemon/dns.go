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

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// DnsProxyFunc is called when DNS_MODE_PROXY is enabled to get a decision from the control plane
type DnsProxyFunc func(ctx context.Context, domain, queryType string) (DnsProxyDecision, error)

const defaultDNSTTLSeconds uint32 = 300

const dnsExchangeTimeout = 5 * time.Second

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

func NewDNSServer(attachmentID, listenAddr, upstream string, logger zerolog.Logger, sink DNSFilterSink, proxyFunc DnsProxyFunc) *DNSServer {
	upstreams, err := normalizeUpstreamServers(nil, upstream)
	if err != nil {
		// Production validates the daemon-global fallback before constructing
		// attachments. Keep invalid direct-test values fail-closed at query time.
		upstreams = []string{upstream}
	}
	return &DNSServer{
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
	}
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
		PacketConn: s.udpConn,
		Handler:    dns.HandlerFunc(s.handleDNS),
		NotifyStartedFunc: func() {
			events <- dnsServeEvent{network: "udp", started: true}
		},
	}
	s.tcp = &dns.Server{
		Listener: s.tcpLn,
		Handler:  dns.HandlerFunc(s.handleDNS),
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

func (s *DNSServer) SetMode(mode apiv1.DnsMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.logger.Debug().Str("mode", mode.String()).Msg("DNS mode changed")
}

func (s *DNSServer) AllowDomain(domain string, includeSubdomains bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized := normalizeDomain(domain)
	s.allowedDomains[normalized] = includeSubdomains
	s.logger.Debug().Str("domain", domain).Bool("subdomains", includeSubdomains).Msg("domain added to allowlist")
}

func (s *DNSServer) DenyDomain(domain string, includeSubdomains bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized := normalizeDomain(domain)
	s.deniedDomains[normalized] = includeSubdomains
	s.logger.Debug().Str("domain", domain).Bool("subdomains", includeSubdomains).Msg("domain added to denylist")
}

func (s *DNSServer) RemoveDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalized := normalizeDomain(domain)
	delete(s.allowedDomains, normalized)
	delete(s.deniedDomains, normalized)
	s.logger.Debug().Str("domain", domain).Msg("domain removed from rules")
}

func (s *DNSServer) ReplaceRules(mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry, upstreamOverride ...[]string) error {
	if len(upstreamOverride) > 1 {
		return fmt.Errorf("at most one upstream server list may be supplied")
	}
	var upstreamServers []string
	if len(upstreamOverride) == 1 {
		upstreamServers = upstreamOverride[0]
	}
	upstreams, err := normalizeUpstreamServers(upstreamServers, s.defaultUpstream)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mode = mode
	s.allowedDomains = make(map[string]bool, len(allowDomains))
	s.deniedDomains = make(map[string]bool, len(denyDomains))
	for _, entry := range allowDomains {
		if entry == nil {
			continue
		}
		s.allowedDomains[normalizeDomain(entry.Domain)] = entry.IncludeSubdomains
	}
	for _, entry := range denyDomains {
		if entry == nil {
			continue
		}
		s.deniedDomains[normalizeDomain(entry.Domain)] = entry.IncludeSubdomains
	}
	s.upstreams = upstreams
	s.logger.Debug().Str("mode", mode.String()).Msg("DNS rules replaced")
	return nil
}

func (s *DNSServer) Stats() (allowed, blocked, queryErrors uint64) {
	return s.queriesAllowed.Load(), s.queriesBlocked.Load(), s.queriesErrors.Load()
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

	s.mu.RLock()
	mode := s.mode
	upstreams := append([]string(nil), s.upstreams...)
	shouldResolve := false
	shouldAddToFilter := false

	switch mode {
	case apiv1.DnsMode_DNS_MODE_DISABLED:
		s.mu.RUnlock()
		shouldResolve = true

	case apiv1.DnsMode_DNS_MODE_ALLOWLIST:
		decision := s.evaluateDomainLocked(domain)
		s.mu.RUnlock()
		if decision == domainDecisionAllow {
			shouldResolve = true
			shouldAddToFilter = true
		}

	case apiv1.DnsMode_DNS_MODE_DENYLIST:
		decision := s.evaluateDomainLocked(domain)
		s.mu.RUnlock()
		if decision != domainDecisionDeny {
			shouldResolve = true
			shouldAddToFilter = true
		}

	case apiv1.DnsMode_DNS_MODE_PROXY:
		proxyFunc := s.proxyFunc
		s.mu.RUnlock()
		if proxyFunc == nil {
			s.logger.Warn().Str("domain", domain).Msg("DNS proxy unavailable")
			s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
			return
		}
		queryType := dns.TypeToString[q.Qtype]
		decision, err := proxyFunc(queryCtx, domain, queryType)
		if err != nil {
			s.logger.Error().Err(err).Str("domain", domain).Msg("control plane query failed")
			s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
			return
		}
		if !decision.Allow {
			s.logger.Debug().Str("domain", domain).Msg("DNS query blocked by control plane")
			s.writeOutcome(w, req, refusedResponse(req), dnsOutcomeBlocked)
			return
		}
		shouldResolve = true
		shouldAddToFilter = decision.AddToFilter
		if len(decision.IPs) > 0 {
			resp, err := s.proxyResponse(req, domain, decision.IPs, decision.AddToFilter, decision.TTLSeconds)
			if err != nil {
				s.logger.Error().Err(err).Str("domain", domain).Msg("proxy override admission failed")
				s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
				return
			}
			s.writeOutcome(w, req, resp, dnsOutcomeAllowed)
			return
		}

	default:
		s.mu.RUnlock()
	}

	if !shouldResolve {
		s.logger.Debug().Str("domain", domain).Msg("DNS query blocked")
		s.writeOutcome(w, req, refusedResponse(req), dnsOutcomeBlocked)
		return
	}

	resp, err := exchangeUpstreams(queryCtx, req, upstreams)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("upstream DNS query failed")
		s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
		return
	}
	resp = sanitizeAddressHints(resp, mode)

	if shouldAddToFilter && s.sink != nil && resp.Rcode == dns.RcodeSuccess {
		for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
			for _, rr := range section {
				switch a := rr.(type) {
				case *dns.A:
					if err := s.addIPToFilter(domain, a.A, 32, a.Hdr.Ttl); err != nil {
						s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
						return
					}
				case *dns.AAAA:
					if err := s.addIPToFilter(domain, a.AAAA, 128, a.Hdr.Ttl); err != nil {
						s.writeOutcome(w, req, servFailResponse(req), dnsOutcomeError)
						return
					}
				}
			}
		}
	}

	outcome := dnsOutcomeAllowed
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		outcome = dnsOutcomeError
	}
	s.writeOutcome(w, req, resp, outcome)
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
	domain = normalizeDomain(domain)
	for candidate := domain; candidate != ""; {
		exact := candidate == domain
		allow := false
		deny := false
		if includeSubdomains, ok := s.allowedDomains[candidate]; ok && (exact || includeSubdomains) {
			allow = true
		}
		if includeSubdomains, ok := s.deniedDomains[candidate]; ok && (exact || includeSubdomains) {
			deny = true
		}
		if deny {
			return domainDecisionDeny
		}
		if allow {
			return domainDecisionAllow
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			break
		}
		candidate = candidate[dot+1:]
	}
	return domainDecisionNone
}

func (s *DNSServer) proxyResponse(req *dns.Msg, domain string, ips []string, addToFilter bool, ttlSeconds uint32) (*dns.Msg, error) {
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

			if addToFilter {
				if err := s.addIPToFilter(domain, ip4, 32, ttlSeconds); err != nil {
					return nil, err
				}
			}
		} else {
			if qType != dns.TypeAAAA && qType != dns.TypeANY {
				continue
			}
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttlSeconds},
				AAAA: ip,
			}
			resp.Answer = append(resp.Answer, rr)

			if addToFilter {
				if err := s.addIPToFilter(domain, ip, 128, ttlSeconds); err != nil {
					return nil, err
				}
			}
		}
	}
	return resp, nil
}

// addIPToFilter forwards a resolved IP to the filter sink with the record's
// TTL. The sink owns dedup (repeated resolutions of a tracked IP cost no
// kernel syscall), the minimum-TTL floor, and expiry via the TTL janitor —
// so unlike the old unbounded ipCache there is no per-DNS-server cache to
// grow without bound. Errors are logged by the sink (rate-limited for
// map-full), so only a debug line is emitted here.
func (s *DNSServer) addIPToFilter(domain string, ip net.IP, bits int, ttlSeconds uint32) error {
	if s.sink == nil {
		return nil
	}
	if ttlSeconds == 0 {
		ttlSeconds = defaultDNSTTLSeconds
	}
	ip = normalizeIP(ip)
	if ip == nil {
		return fmt.Errorf("invalid resolved IP")
	}

	cidr := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	if err := s.sink.AllowIPWithTTL(cidr, time.Duration(ttlSeconds)*time.Second); err != nil {
		s.logger.Debug().Err(err).Str("domain", domain).Str("ip", ip.String()).Msg("failed to add IP to filter")
		return err
	}
	s.logger.Debug().Str("domain", domain).Str("ip", ip.String()).Msg("added IP to filter")
	return nil
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

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

var errDNSProxyUnavailable = errors.New("DNS proxy unavailable")
