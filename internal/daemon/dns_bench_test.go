package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// BenchmarkDNSAddIPToFilterCached is a diagnostic for the internal single-record
// test helper through the real ownership sink and attachment mutation barrier.
// Production queries traverse the same barrier but use whole-response admission
// in admitAndWrite; those paths have separate end-to-end benchmarks below. The
// first helper add writes to the filter, while subsequent adds refresh ownership
// without another filter call.
func BenchmarkDNSAddIPToFilterCached(b *testing.B) {
	_, _, _, ff, dnsServer := newTestServerWithAttachment(b)
	ip := net.ParseIP("203.0.113.8")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dnsServer.addIPToFilter("example.com", ip, 32, 300)
	}
	b.StopTimer()
	if _, calls := ff.dnsSnapshot(); calls != 1 {
		b.Fatalf("expected exactly one AddDNSAllowedIPs call, got %d", calls)
	}
}

// BenchmarkDNSOwnershipNearCapacityWarmRefresh guards the hot-path invariant:
// refreshing an existing owner/IP edge is O(response size), not O(total
// working-set/ownership graph). The 4095 unrelated entries are populated
// outside the timed section.
func BenchmarkDNSOwnershipNearCapacityWarmRefresh(b *testing.B) {
	now := time.Now()
	manager := populatedDNSOwnershipManager(b, 4095, now)
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "large.example"}
	request := dnsAdmissionRequest{
		queryDomain: "large.example",
		owner:       owner,
		records:     []dnsAdmissionRecord{{ip: net.IPv4(10, 0, 0, 1), ttl: time.Hour}},
	}
	canonical, err := canonicalizeDNSAdmissionRequest(request)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := manager.admitCanonical(canonical); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDNSOwnershipColdAdmission isolates the manager's one-address cold
// transaction. The benchmark-owned graph and fake exact map are reset without
// reconstruction between iterations; query-path synchronization is measured
// separately by the end-to-end cold benchmarks below.
func BenchmarkDNSOwnershipColdAdmission(b *testing.B) {
	ff := &fakeFilter{}
	manager, err := newDNSOwnershipManager(ff,
		dnsAdmissionLimits{4096, 64, 1024, 1024, 8192}, time.Minute, time.Now)
	if err != nil {
		b.Fatal(err)
	}
	request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
		queryDomain: "example.com",
		owner:       dnsPolicyOwner{kind: dnsOwnerProxy, domain: "example.com"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("198.51.100.10"), ttl: 5 * time.Minute}},
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clear(manager.entries)
		manager.normalIPv4, manager.normalIPv6, manager.edgeCount = 0, 0, 0
		clear(manager.queryRefs)
		clear(manager.ownerIPRefs)
		ff.resetDNSAllowedForBenchmark()
		if err := manager.admitCanonical(request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDNSOwnershipNearCapacityNoopExpiry(b *testing.B) {
	now := time.Now()
	manager := populatedDNSOwnershipManager(b, 4095, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := manager.expire(now); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if calls := manager.filter.(*fakeFilter).dnsRemoveCallCount(); calls != 0 {
		b.Fatalf("no-op expiry attempted %d exact-map removals", calls)
	}
}

func populatedDNSOwnershipManager(tb testing.TB, entries int, now time.Time) *dnsOwnershipManager {
	tb.Helper()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{4096, 64, 4096, 64, 4096}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, func() time.Time { return now })
	if err != nil {
		tb.Fatal(err)
	}
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "large.example"}
	edge := dnsOwnershipKey{query: "large.example", owner: owner}
	for i := 1; i <= entries; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To4()
		addr, _ := canonicalDNSAddr(ip)
		manager.entries[addr] = dnsOwnedIP{addr: addr, owners: newDNSOwnerEdgeSet(edge, now.Add(time.Hour))}
	}
	manager.rebuildOwnershipIndexes()
	return manager
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

// benchmarkRegistrySink reuses the real sink and DNS server installed in the
// attachment state. BeginAdmission deliberately rejects an uninstalled sink
// or a server other than the one currently bound to that sink, so constructing
// a parallel benchmark-only pair would measure fail-closed stale identity
// rejection instead of admission.
func benchmarkRegistrySink(b *testing.B) (*DNSServer, *fakeFilter, func()) {
	_, _, _, ff, server := newTestServerWithAttachment(b)
	sink, ok := server.sink.(*dnsFilterSink)
	if !ok {
		b.Fatalf("benchmark DNS sink has type %T, want *dnsFilterSink", server.sink)
	}
	server.listenAddr = freeDNSListenAddress(b)
	return server, ff, func() {
		if err := resetBenchmarkDNSOwnership(sink, ff); err != nil {
			b.Fatal(err)
		}
	}
}

// resetBenchmarkDNSOwnership restores only the mutable userspace graph and the
// fake exact-map snapshot needed for a cold insertion. It preserves configured
// policy domains, limits, map backing storage, and cumulative mutation counts.
//
// A DNS client may receive its UDP packet before the serving goroutine returns
// from WriteMsg and releases admission. Taking the real attachment barrier (and
// then the DNS policy lock, in production lock order) makes these direct clears
// wait for that prior handler and any other exact-state mutation to finish.
// The reset remains inside the timed cold-query loop, conservatively charging
// its small synchronization and clear cost to the result.
func resetBenchmarkDNSOwnership(sink *dnsFilterSink, ff *fakeFilter) error {
	done, err := sink.BeginAdmission()
	if err != nil {
		return err
	}
	defer done()

	sink.dns.mu.Lock()
	defer sink.dns.mu.Unlock()

	manager := sink.manager
	clear(manager.entries)
	manager.normalIPv4 = 0
	manager.normalIPv6 = 0
	manager.edgeCount = 0
	clear(manager.queryRefs)
	clear(manager.ownerIPRefs)
	ff.resetDNSAllowedForBenchmark()
	return nil
}

func TestResetBenchmarkDNSOwnershipWaitsForInFlightAdmission(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	sink, ok := dnsServer.sink.(*dnsFilterSink)
	if !ok {
		t.Fatalf("benchmark DNS sink has type %T, want *dnsFilterSink", dnsServer.sink)
	}
	sink.manager.policyDomains["example.com"] = struct{}{}
	if err := dnsServer.addIPToFilter("example.com", net.ParseIP("192.0.2.80"), 32, 60); err != nil {
		t.Fatalf("seeding DNS ownership: %v", err)
	}
	dnsAllowed, addCalls := ff.dnsSnapshot()
	if len(sink.manager.entries) != 1 || sink.manager.normalIPv4 != 1 ||
		sink.manager.normalIPv6 != 0 || sink.manager.edgeCount != 1 ||
		len(sink.manager.queryRefs) != 1 || len(sink.manager.ownerIPRefs) != 1 ||
		len(dnsAllowed) != 1 || addCalls != 1 {
		t.Fatalf("benchmark seed is incomplete: manager=%+v exact=%v add_calls=%d", sink.manager, dnsAllowed, addCalls)
	}

	// Model the short post-WriteMsg window in which the client has received
	// its UDP response but the handler still owns its admission lease and DNS
	// policy read lock.
	leaseDone, err := sink.BeginAdmission()
	if err != nil {
		t.Fatalf("holding prior admission lease: %v", err)
	}
	dnsServer.mu.RLock()

	resetQueued := make(chan struct{})
	server.mutationAdmissionHook = func(hookID string, _ *attachmentState) {
		if hookID == id {
			close(resetQueued)
		}
	}
	resetDone := make(chan error, 1)
	go func() {
		resetDone <- resetBenchmarkDNSOwnership(sink, ff)
	}()
	<-resetQueued
	select {
	case err := <-resetDone:
		t.Fatalf("benchmark reset crossed an in-flight admission: %v", err)
	default:
	}
	dnsAllowed, addCalls = ff.dnsSnapshot()
	if len(sink.manager.entries) != 1 || sink.manager.normalIPv4 != 1 ||
		sink.manager.normalIPv6 != 0 || sink.manager.edgeCount != 1 ||
		len(sink.manager.queryRefs) != 1 || len(sink.manager.ownerIPRefs) != 1 ||
		len(dnsAllowed) != 1 || addCalls != 1 {
		t.Fatalf("queued benchmark reset mutated live admission state: manager=%+v exact=%v add_calls=%d", sink.manager, dnsAllowed, addCalls)
	}

	dnsServer.mu.RUnlock()
	leaseDone()
	if err := <-resetDone; err != nil {
		t.Fatalf("benchmark reset failed: %v", err)
	}
	server.mutationAdmissionHook = nil

	if len(sink.manager.entries) != 0 || sink.manager.normalIPv4 != 0 ||
		sink.manager.normalIPv6 != 0 || sink.manager.edgeCount != 0 ||
		len(sink.manager.queryRefs) != 0 || len(sink.manager.ownerIPRefs) != 0 {
		t.Fatalf("benchmark reset left ownership state: %+v", sink.manager)
	}
	if _, ok := sink.manager.policyDomains["example.com"]; !ok {
		t.Fatal("benchmark reset removed configured policy domains")
	}
	dnsAllowed, addCalls = ff.dnsSnapshot()
	if len(dnsAllowed) != 0 || addCalls != 1 {
		t.Fatalf("benchmark reset exact state = %v, add calls = %d; want empty state and one retained call", dnsAllowed, addCalls)
	}
}

func benchmarkDNSProxyQuery(b *testing.B, cold bool) {
	server, ff, reset := benchmarkRegistrySink(b)
	server.proxyFunc = func(context.Context, string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{
			Allow:       true,
			AddToFilter: true,
			IPs:         []string{"198.51.100.10"},
			TTLSeconds:  300,
		}, nil
	}
	if err := server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY); err != nil {
		b.Fatal(err)
	}
	startBenchmarkDNSServer(b, server)

	benchmarkDNSLookup(b, server.listenAddr, cold, reset, ff)
}

func benchmarkDNSAllowlistQuery(b *testing.B, cold bool) {
	server, ff, reset := benchmarkRegistrySink(b)
	if err := server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "example.com"}}, nil, []string{startTestUpstream(b)}); err != nil {
		b.Fatal(err)
	}
	startBenchmarkDNSServer(b, server)

	benchmarkDNSLookup(b, server.listenAddr, cold, reset, ff)
}

func benchmarkDNSLookup(b *testing.B, addr string, cold bool, reset func(), ff *fakeFilter) {
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
	var resetElapsed time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if cold {
			// Keep the benchmark timer running so per-iteration StopTimer /
			// StartTimer bookkeeping cannot destroy UDP scheduler locality.
			// Account for the synchronized fixture reset separately below:
			// it includes any tail of the prior handler after the client has
			// received its packet, but is not part of this query's Exchange.
			resetStarted := time.Now()
			reset()
			resetElapsed += time.Since(resetStarted)
		}
		resp, _, err := client.Exchange(request.Copy(), addr)
		if err != nil {
			b.Fatal(err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			b.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
		}
	}
	b.StopTimer()
	elapsed := b.Elapsed()
	if cold {
		if b.N <= 0 || resetElapsed < 0 || resetElapsed >= elapsed {
			b.Fatalf("invalid benchmark timing: iterations=%d elapsed=%s fixture reset=%s", b.N, elapsed, resetElapsed)
		}
		iterations := float64(b.N)
		b.ReportMetric(float64((elapsed-resetElapsed).Nanoseconds())/iterations, "ns/op")
		b.ReportMetric(float64(resetElapsed.Nanoseconds())/iterations, "fixture-reset-ns/op")
		b.ReportMetric(float64(elapsed.Nanoseconds())/iterations, "raw-total-ns/op")
	}
	dnsAllowed, addCalls := ff.dnsSnapshot()
	expectedAdds := 1
	if cold {
		expectedAdds = b.N
	}
	if addCalls != expectedAdds {
		b.Fatalf("expected %d exact-map adds, got %d", expectedAdds, addCalls)
	}
	if len(dnsAllowed) != 1 {
		b.Fatalf("expected one final exact key, got %v", dnsAllowed)
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
