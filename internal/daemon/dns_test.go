package daemon

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type recordingIPAllower struct {
	mu    sync.Mutex
	cidrs []string
}

func (r *recordingIPAllower) AllowIP(cidr *net.IPNet) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cidrs = append(r.cidrs, cidr.String())
	return nil
}

func (r *recordingIPAllower) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cidrs)
}

func (r *recordingIPAllower) entries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cidrs...)
}

type captureDNSWriter struct {
	msg *dns.Msg
}

func (w *captureDNSWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *captureDNSWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *captureDNSWriter) Close() error                { return nil }
func (w *captureDNSWriter) TsigStatus() error           { return nil }
func (w *captureDNSWriter) TsigTimersOnly(bool)         {}
func (w *captureDNSWriter) Hijack()                     {}
func (w *captureDNSWriter) Write([]byte) (int, error)   { return 0, errors.New("not implemented") }
func (w *captureDNSWriter) WriteMsg(msg *dns.Msg) error { w.msg = msg; return nil }
func dnsQuery(domain string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	return msg
}
func queryServer(s *DNSServer, domain string, qtype uint16) *dns.Msg {
	writer := &captureDNSWriter{}
	s.handleDNS(writer, dnsQuery(domain, qtype))
	return writer.msg
}

func startTestUpstream(t testing.TB) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: conn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			for _, q := range req.Question {
				switch q.Qtype {
				case dns.TypeA:
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("203.0.113.10").To4(),
					})
				case dns.TypeAAAA:
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: net.ParseIP("2001:db8::10"),
					})
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return conn.LocalAddr().String()
}

func TestDNSServerDomainPolicySemantics(t *testing.T) {
	upstream := startTestUpstream(t)
	filter := &recordingIPAllower{}
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), filter, nil)
	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{
			{Domain: "Example.COM.", IncludeSubdomains: true},
			{Domain: "allowed.bad.example.com", IncludeSubdomains: true},
			{Domain: "tie.example.com"},
			{Domain: "nosubs.other.com"},
		},
		[]*apiv1.DomainEntry{
			{Domain: "bad.example.com", IncludeSubdomains: true},
			{Domain: "tie.example.com"},
		},
	)

	tests := []struct {
		name   string
		domain string
		want   domainDecision
	}{
		{name: "case and trailing dot normalize", domain: "WWW.EXAMPLE.COM.", want: domainDecisionAllow},
		{name: "more specific deny beats parent allow", domain: "deep.bad.example.com", want: domainDecisionDeny},
		{name: "more specific allow beats parent deny", domain: "deep.allowed.bad.example.com", want: domainDecisionAllow},
		{name: "deny wins exact tie", domain: "tie.example.com", want: domainDecisionDeny},
		{name: "exact allow without subdomains", domain: "nosubs.other.com", want: domainDecisionAllow},
		{name: "subdomain excluded without includeSubdomains", domain: "child.nosubs.other.com", want: domainDecisionNone},
		{name: "unknown", domain: "unknown.test", want: domainDecisionNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.mu.RLock()
			got := server.evaluateDomainLocked(tt.domain)
			server.mu.RUnlock()
			assert.Equal(t, tt.want, got)
		})
	}

	resp := queryServer(server, "unknown.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)

	resp = queryServer(server, "www.example.com", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Equal(t, []string{"203.0.113.10/32"}, filter.entries())

	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DENYLIST, nil, []*apiv1.DomainEntry{{Domain: "blocked.test", IncludeSubdomains: true}})
	resp = queryServer(server, "blocked.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)

	resp = queryServer(server, "unknown.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

func TestDNSServerProxyFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		proxyFunc DnsProxyFunc
	}{
		{name: "nil proxy", proxyFunc: nil},
		{name: "proxy error", proxyFunc: func(string, string) (DnsProxyDecision, error) {
			return DnsProxyDecision{}, errors.New("control plane down")
		}},
		{name: "disconnected control plane proxy", proxyFunc: NewControlPlaneClient("", nil, zerolog.Nop(), nil, 0).MakeProxyFunc("att-1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &recordingIPAllower{}
			server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), filter, tt.proxyFunc)
			server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

			resp := queryServer(server, "example.com", dns.TypeA)
			require.NotNil(t, resp)
			assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
			assert.Zero(t, filter.calls())
			_, blocked := server.Stats()
			assert.Equal(t, uint64(1), blocked)
		})
	}
}

func TestDNSServerProxyExplicitDenyRefuses(t *testing.T) {
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, func(string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{Allow: false}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

	resp := queryServer(server, "blocked.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
}

func TestDNSServerProxyResponseHonorsTTLQueryTypeAndFiltering(t *testing.T) {
	filter := &recordingIPAllower{}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), filter, func(string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{
			Allow:       true,
			AddToFilter: true,
			IPs:         []string{"198.51.100.10", "2001:db8::1", "not-an-ip"},
			TTLSeconds:  42,
		}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

	resp := queryServer(server, "example.com", dns.TypeA)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, uint32(42), a.Hdr.Ttl)
	assert.Equal(t, "198.51.100.10", a.A.String())
	assert.Equal(t, []string{"198.51.100.10/32"}, filter.entries())

	resp = queryServer(server, "example.com", dns.TypeAAAA)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	require.True(t, ok)
	assert.Equal(t, uint32(42), aaaa.Hdr.Ttl)
	assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	assert.Equal(t, []string{"198.51.100.10/32", "2001:db8::1/128"}, filter.entries())

	noFilter := &recordingIPAllower{}
	server = NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), noFilter, func(string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{Allow: true, AddToFilter: false, IPs: []string{"198.51.100.11"}}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

	resp = queryServer(server, "example.com", dns.TypeA)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, uint32(defaultDNSTTLSeconds), resp.Answer[0].Header().Ttl)
	assert.Zero(t, noFilter.calls())
}

func TestDNSServerDynamicFilterCacheExpiresByTTL(t *testing.T) {
	filter := &recordingIPAllower{}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), filter, nil)

	ip := net.ParseIP("203.0.113.77")
	server.addIPToFilter("example.com", ip, 32, 60)
	server.addIPToFilter("example.com", ip, 32, 60)
	assert.Equal(t, 1, filter.calls())

	server.mu.Lock()
	server.ipCache["203.0.113.77"] = time.Now().Add(-time.Second)
	server.mu.Unlock()
	server.addIPToFilter("example.com", ip, 32, 60)
	assert.Equal(t, 2, filter.calls())
}

func TestDNSServerStopClosesSocketAndAllowsRebind(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())

	server := NewDNSServer("att-1", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	require.NoError(t, server.Start())
	require.NoError(t, server.Stop())
	require.NoError(t, server.Stop())

	server = NewDNSServer("att-2", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	require.NoError(t, server.Start())
	require.NoError(t, server.Stop())
}
