package daemon

import (
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
type DnsProxyFunc func(domain, queryType string) (allow, addToFilter bool, ips []string, err error)

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

	s.conn = conn
	s.server = &dns.Server{
		PacketConn: conn,
		Handler:    dns.HandlerFunc(s.handleDNS),
	}

	go func() {
		s.logger.Info().Msg("starting DNS server")
		if err := s.server.ActivateAndServe(); err != nil {
			s.logger.Error().Err(err).Msg("DNS server error")
		}
	}()

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
	allowed := s.isDomainAllowed(domain)
	denied := s.isDomainDenied(domain)
	s.mu.RUnlock()

	shouldResolve := false
	shouldAddToFilter := false

	switch mode {
	case apiv1.DnsMode_DNS_MODE_DISABLED:
		// Forward all, don't add to filter
		shouldResolve = true
		shouldAddToFilter = false

	case apiv1.DnsMode_DNS_MODE_ALLOWLIST:
		// Only resolve allowed domains, add to filter
		if allowed {
			shouldResolve = true
			shouldAddToFilter = true
		}

	case apiv1.DnsMode_DNS_MODE_DENYLIST:
		// Resolve all except denied, add to filter
		if !denied {
			shouldResolve = true
			shouldAddToFilter = true
		}

	case apiv1.DnsMode_DNS_MODE_PROXY:
		if s.proxyFunc != nil {
			queryType := dns.TypeToString[q.Qtype]
			allow, addToFilter, ips, err := s.proxyFunc(domain, queryType)
			if err != nil {
				s.logger.Error().Err(err).Str("domain", domain).Msg("control plane query failed")
				s.sendServFail(w, req)
				return
			}
			if !allow {
				s.queriesBlocked.Add(1)
				s.logger.Debug().Str("domain", domain).Msg("DNS query blocked by control plane")
				s.sendRefused(w, req)
				return
			}
			shouldResolve = true
			shouldAddToFilter = addToFilter
			// If control plane provided IPs, return them directly
			if len(ips) > 0 {
				s.queriesAllowed.Add(1)
				s.sendProxyResponse(w, req, domain, ips, addToFilter)
				return
			}
		} else {
			// No proxy function, fall back to allowing
			shouldResolve = true
			shouldAddToFilter = false
		}
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
				cidr := &net.IPNet{IP: a.A, Mask: net.CIDRMask(32, 32)}
				if err := s.filter.AllowIP(cidr); err != nil {
					s.logger.Warn().Err(err).Str("ip", a.A.String()).Msg("failed to add IPv4 to filter")
				} else {
					s.logger.Debug().Str("domain", domain).Str("ip", a.A.String()).Msg("added IPv4 to filter")
				}
			case *dns.AAAA:
				cidr := &net.IPNet{IP: a.AAAA, Mask: net.CIDRMask(128, 128)}
				if err := s.filter.AllowIP(cidr); err != nil {
					s.logger.Warn().Err(err).Str("ip", a.AAAA.String()).Msg("failed to add IPv6 to filter")
				} else {
					s.logger.Debug().Str("domain", domain).Str("ip", a.AAAA.String()).Msg("added IPv6 to filter")
				}
			}
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to write DNS response")
	}
}

func (s *DNSServer) isDomainAllowed(domain string) bool {
	domain = normalizeDomain(domain)

	// Check exact match
	if _, ok := s.allowedDomains[domain]; ok {
		return true
	}

	// Check if any parent domain allows subdomains
	for d := domain; strings.Contains(d, "."); {
		parts := strings.SplitN(d, ".", 2)
		if len(parts) != 2 {
			break
		}
		parent := parts[1]
		if includesSubs, ok := s.allowedDomains[parent]; ok && includesSubs {
			return true
		}
		d = parent
	}

	return false
}

func (s *DNSServer) isDomainDenied(domain string) bool {
	domain = normalizeDomain(domain)

	// Check exact match
	if _, ok := s.deniedDomains[domain]; ok {
		return true
	}

	// Check if any parent domain denies subdomains
	for d := domain; strings.Contains(d, "."); {
		parts := strings.SplitN(d, ".", 2)
		if len(parts) != 2 {
			break
		}
		parent := parts[1]
		if includesSubs, ok := s.deniedDomains[parent]; ok && includesSubs {
			return true
		}
		d = parent
	}

	return false
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

func (s *DNSServer) sendProxyResponse(w dns.ResponseWriter, req *dns.Msg, domain string, ips []string, addToFilter bool) {
	resp := new(dns.Msg)
	resp.SetReply(req)

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		if ip4 := ip.To4(); ip4 != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip4,
			}
			resp.Answer = append(resp.Answer, rr)

			if addToFilter && s.filter != nil {
				cidr := &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
				if err := s.filter.AllowIP(cidr); err != nil {
					s.logger.Warn().Err(err).Str("ip", ipStr).Msg("failed to add IPv4 to filter")
				}
			}
		} else {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: ip,
			}
			resp.Answer = append(resp.Answer, rr)

			if addToFilter && s.filter != nil {
				cidr := &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				if err := s.filter.AllowIP(cidr); err != nil {
					s.logger.Warn().Err(err).Str("ip", ipStr).Msg("failed to add IPv6 to filter")
				}
			}
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to write proxy response")
	}
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}
