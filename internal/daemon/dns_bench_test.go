package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// BenchmarkDNSAddIPToFilterCached measures the repeated-resolution path
// through the real registry-backed sink: the first add writes to the filter,
// subsequent adds for the tracked IP only refresh the deadline (no filter
// call).
func BenchmarkDNSAddIPToFilterCached(b *testing.B) {
	_, _, _, ff, dnsServer := newTestServerWithAttachment(b)
	ip := net.ParseIP("203.0.113.8")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dnsServer.addIPToFilter("example.com", ip, 32, 300)
	}
	b.StopTimer()
	if calls := ff.allowCallCount(); calls != 1 {
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

// benchmarkRegistrySink builds the real registry-backed sink (as the daemon
// wires per attachment) so the benchmarks exercise the true resolved-IP
// path: cold resets the registry each iteration (filter write-through),
// warm keeps the entry tracked (deadline refresh only, no filter call).
func benchmarkRegistrySink(b *testing.B) (DNSFilterSink, *ttlRegistry) {
	srv, _, id, ff, _ := newTestServerWithAttachment(b)
	reg := newTTLRegistry()
	return srv.newDNSFilterSink(id, ff, reg), reg
}

func benchmarkDNSProxyQuery(b *testing.B, cold bool) {
	sink, reg := benchmarkRegistrySink(b)
	addr := freeUDPAddress(b)
	server := NewDNSServer("bench", addr, "127.0.0.1:1", zerolog.Nop(), sink, func(string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{
			Allow:       true,
			AddToFilter: true,
			IPs:         []string{"198.51.100.10"},
			TTLSeconds:  300,
		}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)
	startBenchmarkDNSServer(b, server)

	benchmarkDNSLookup(b, addr, cold, reg.purge)
}

func benchmarkDNSAllowlistQuery(b *testing.B, cold bool) {
	sink, reg := benchmarkRegistrySink(b)
	addr := freeUDPAddress(b)
	server := NewDNSServer("bench", addr, startTestUpstream(b), zerolog.Nop(), sink, nil)
	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST, []*apiv1.DomainEntry{{Domain: "example.com"}}, nil)
	startBenchmarkDNSServer(b, server)

	benchmarkDNSLookup(b, addr, cold, reg.purge)
}

func benchmarkDNSLookup(b *testing.B, addr string, cold bool, reset func()) {
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
			reset()
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
