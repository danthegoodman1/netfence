package daemon

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type benchmarkIPAllower struct {
	calls atomic.Uint64
}

func (b *benchmarkIPAllower) AllowIP(*net.IPNet) error {
	b.calls.Add(1)
	return nil
}

func BenchmarkDNSAddIPToFilterCached(b *testing.B) {
	filter := &recordingIPAllower{}
	server := NewDNSServer("bench", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), filter, nil)
	ip := net.ParseIP("203.0.113.8")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.addIPToFilter("example.com", ip, 32, 300)
	}
	b.StopTimer()
	if calls := filter.calls(); calls != 1 {
		b.Fatalf("expected exactly one AllowIP call, got %d", calls)
	}
}

func BenchmarkDNSProxyQueryCold(b *testing.B) {
	benchmarkDNSProxyQuery(b, true)
}

func BenchmarkDNSProxyQueryWarm(b *testing.B) {
	benchmarkDNSProxyQuery(b, false)
}

func BenchmarkDNSAllowlistQueryCold(b *testing.B) {
	benchmarkDNSAllowlistQuery(b, true)
}

func BenchmarkDNSAllowlistQueryWarm(b *testing.B) {
	benchmarkDNSAllowlistQuery(b, false)
}

func BenchmarkDNSEvaluateDomainExact(b *testing.B) {
	server := benchmarkDNSServer()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		server.mu.RLock()
		_ = server.evaluateDomainLocked("exact.example.com.")
		server.mu.RUnlock()
	}
}

func BenchmarkDNSEvaluateDomainSubdomain(b *testing.B) {
	server := benchmarkDNSServer()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		server.mu.RLock()
		_ = server.evaluateDomainLocked("a.b.c.service.example.com.")
		server.mu.RUnlock()
	}
}

func BenchmarkDNSEvaluateDomainDeepMiss(b *testing.B) {
	server := benchmarkDNSServer()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		server.mu.RLock()
		_ = server.evaluateDomainLocked("a.b.c.d.e.f.g.miss.test.")
		server.mu.RUnlock()
	}
}

func benchmarkDNSServer() *DNSServer {
	server := NewDNSServer("bench", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, nil)
	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{
			{Domain: "exact.example.com"},
			{Domain: "service.example.com", IncludeSubdomains: true},
			{Domain: "example.org", IncludeSubdomains: true},
		},
		[]*apiv1.DomainEntry{
			{Domain: "blocked.service.example.com", IncludeSubdomains: true},
		},
	)
	return server
}

func benchmarkDNSProxyQuery(b *testing.B, cold bool) {
	filter := &benchmarkIPAllower{}
	addr := freeUDPAddress(b)
	server := NewDNSServer("bench", addr, "127.0.0.1:1", zerolog.Nop(), filter, func(string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{
			Allow:       true,
			AddToFilter: true,
			IPs:         []string{"198.51.100.10"},
			TTLSeconds:  300,
		}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)
	startBenchmarkDNSServer(b, server)

	benchmarkDNSLookup(b, server, addr, cold)
}

func benchmarkDNSAllowlistQuery(b *testing.B, cold bool) {
	filter := &benchmarkIPAllower{}
	addr := freeUDPAddress(b)
	server := NewDNSServer("bench", addr, startTestUpstream(b), zerolog.Nop(), filter, nil)
	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST, []*apiv1.DomainEntry{{Domain: "example.com"}}, nil)
	startBenchmarkDNSServer(b, server)

	benchmarkDNSLookup(b, server, addr, cold)
}

func benchmarkDNSLookup(b *testing.B, server *DNSServer, addr string, cold bool) {
	client := &dns.Client{Timeout: 2 * time.Second}
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	if !cold {
		resp, _, err := client.Exchange(request.Copy(), addr)
		if err != nil {
			b.Fatal(err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			b.Fatalf("warmup rcode = %s", dns.RcodeToString[resp.Rcode])
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if cold {
			server.ClearDynamicCache()
		}
		resp, _, err := client.Exchange(request.Copy(), addr)
		if err != nil {
			b.Fatal(err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			b.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
		}
	}
}

func startBenchmarkDNSServer(b *testing.B, server *DNSServer) {
	b.Helper()
	if err := server.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = server.Stop()
	})
}

func freeUDPAddress(b *testing.B) string {
	b.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		b.Fatal(err)
	}
	return addr
}
