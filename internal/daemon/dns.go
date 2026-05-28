package daemon

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// IPAllower is the interface for adding IPs to a filter
type IPAllower interface {
	AllowIP(cidr *net.IPNet) error
}

// DnsProxyFunc is called when DNS_MODE_PROXY is enabled to get a decision from the control plane
type DnsProxyFunc func(domain, queryType string) (DnsProxyDecision, error)

const defaultDNSTTLSeconds uint32 = 300

type DnsProxyDecision struct {
	Allow       bool
	AddToFilter bool
	IPs         []string
	TTLSeconds  uint32
}

// DNSServer is a per-attachment DNS server that filters queries and populates the IP filter
type DNSServer struct {
	attachmentID string
	listenAddr   string
	upstream     string
	logger       zerolog.Logger
	filter       IPAllower
	proxyFunc    DnsProxyFunc

	mu             sync.RWMutex
	mode           apiv1.DnsMode
	allowedDomains map[string]bool // domain -> includeSubdomains
	deniedDomains  map[string]bool // domain -> includeSubdomains
	ipCache        map[string]time.Time

	serverMu sync.Mutex
	server   *dns.Server
	conn     net.PacketConn

	queriesAllowed atomic.Uint64
	queriesBlocked atomic.Uint64
}

func NewDNSServer(attachmentID, listenAddr, upstream string, logger zerolog.Logger, filter IPAllower, proxyFunc DnsProxyFunc) *DNSServer {
	return &DNSServer{
		attachmentID:   attachmentID,
		listenAddr:     listenAddr,
		upstream:       upstream,
		logger:         logger.With().Str("component", "dns").Str("addr", listenAddr).Logger(),
		filter:         filter,
		proxyFunc:      proxyFunc,
		mode:           apiv1.DnsMode_DNS_MODE_DISABLED,
		allowedDomains: make(map[string]bool),
		deniedDomains:  make(map[string]bool),
		ipCache:        make(map[string]time.Time),
	}
}

func (s *DNSServer) Start() error {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()

	if s.server != nil {
		return fmt.Errorf("DNS server already started")
	}

	conn, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		return err
	}

	ready := make(chan struct{})
	s.conn = conn
	s.server = &dns.Server{
		PacketConn: conn,
		Handler:    dns.HandlerFunc(s.handleDNS),
		NotifyStartedFunc: func() {
			close(ready)
		},
	}

	go func() {
		s.logger.Info().Msg("starting DNS server")
		if err := s.server.ActivateAndServe(); err != nil {
			s.logger.Error().Err(err).Msg("DNS server error")
		}
	}()

	<-ready
	return nil
}

func (s *DNSServer) Stop() error {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()

	if s.server != nil {
		if err := s.server.Shutdown(); err != nil {
			return err
		}
		s.server = nil
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	return nil
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

func (s *DNSServer) ReplaceRules(mode apiv1.DnsMode, allowDomains, denyDomains []*apiv1.DomainEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mode = mode
	s.allowedDomains = make(map[string]bool, len(allowDomains))
	s.deniedDomains = make(map[string]bool, len(denyDomains))
	s.ipCache = make(map[string]time.Time)
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
	s.logger.Debug().Str("mode", mode.String()).Msg("DNS rules replaced")
}

func (s *DNSServer) ClearDynamicCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipCache = make(map[string]time.Time)
}

func (s *DNSServer) Stats() (allowed, blocked uint64) {
	return s.queriesAllowed.Load(), s.queriesBlocked.Load()
}

func (s *DNSServer) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		s.sendRefused(w, req)
		return
	}

	q := req.Question[0]
	domain := q.Name

	s.mu.RLock()
	mode := s.mode

	shouldResolve := false
	shouldAddToFilter := false

	switch mode {
	case apiv1.DnsMode_DNS_MODE_DISABLED:
		s.mu.RUnlock()
		// Forward all, don't add to filter
		shouldResolve = true
		shouldAddToFilter = false

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
			s.queriesBlocked.Add(1)
			s.logger.Warn().Str("domain", domain).Msg("DNS proxy unavailable")
			s.sendServFail(w, req)
			return
		}
		queryType := dns.TypeToString[q.Qtype]
		decision, err := proxyFunc(domain, queryType)
		if err != nil {
			s.queriesBlocked.Add(1)
			s.logger.Error().Err(err).Str("domain", domain).Msg("control plane query failed")
			s.sendServFail(w, req)
			return
		}
		if !decision.Allow {
			s.queriesBlocked.Add(1)
			s.logger.Debug().Str("domain", domain).Msg("DNS query blocked by control plane")
			s.sendRefused(w, req)
			return
		}
		shouldResolve = true
		shouldAddToFilter = decision.AddToFilter
		if len(decision.IPs) > 0 {
			s.queriesAllowed.Add(1)
			s.sendProxyResponse(w, req, domain, decision.IPs, decision.AddToFilter, decision.TTLSeconds)
			return
		}

	default:
		s.mu.RUnlock()
	}

	if !shouldResolve {
		s.queriesBlocked.Add(1)
		s.logger.Debug().Str("domain", domain).Msg("DNS query blocked")
		s.sendRefused(w, req)
		return
	}

	s.queriesAllowed.Add(1)

	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.Exchange(req, s.upstream)
	if err != nil {
		s.logger.Error().Err(err).Str("domain", domain).Msg("upstream DNS query failed")
		s.sendServFail(w, req)
		return
	}

	if shouldAddToFilter && s.filter != nil {
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				s.addIPToFilter(domain, a.A, 32, a.Hdr.Ttl)
			case *dns.AAAA:
				s.addIPToFilter(domain, a.AAAA, 128, a.Hdr.Ttl)
			}
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to write DNS response")
	}
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

func (s *DNSServer) sendRefused(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeRefused)
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to write REFUSED response")
	}
}

func (s *DNSServer) sendServFail(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to write SERVFAIL response")
	}
}

func (s *DNSServer) sendProxyResponse(w dns.ResponseWriter, req *dns.Msg, domain string, ips []string, addToFilter bool, ttlSeconds uint32) {
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
			continue
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
				s.addIPToFilter(domain, ip4, 32, ttlSeconds)
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
				s.addIPToFilter(domain, ip, 128, ttlSeconds)
			}
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to write proxy response")
	}
}

func (s *DNSServer) addIPToFilter(domain string, ip net.IP, bits int, ttlSeconds uint32) {
	if s.filter == nil {
		return
	}
	if ttlSeconds == 0 {
		ttlSeconds = defaultDNSTTLSeconds
	}
	ip = normalizeIP(ip)
	if ip == nil {
		return
	}
	key := ip.String()
	now := time.Now()

	s.mu.RLock()
	expiresAt, cached := s.ipCache[key]
	s.mu.RUnlock()
	if cached && now.Before(expiresAt) {
		return
	}

	cidr := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	if err := s.filter.AllowIP(cidr); err != nil {
		s.logger.Warn().Err(err).Str("ip", key).Msg("failed to add IP to filter")
		return
	}

	s.mu.Lock()
	s.ipCache[key] = now.Add(time.Duration(ttlSeconds) * time.Second)
	s.mu.Unlock()
	s.logger.Debug().Str("domain", domain).Str("ip", key).Msg("added IP to filter")
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
