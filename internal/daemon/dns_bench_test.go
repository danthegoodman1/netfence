package daemon

import (
	"net"
	"testing"

	"github.com/rs/zerolog"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

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
