package daemon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	fixedNow := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	manager, err := newDNSOwnershipManagerWithChurn(ff,
		dnsAdmissionLimits{4096, 64, 1024, 1024, 8192},
		dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute}, time.Minute,
		func() time.Time { return fixedNow })
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
		manager.normalIPv4, manager.normalIPv6 = 0, 0
		manager.physicalIPv4, manager.physicalIPv6 = 0, 0
		manager.edgeCount = 0
		manager.trackedDomains = uint64(len(manager.policyDomains))
		clear(manager.queryRefs)
		clear(manager.ownerIPRefs)
		manager.publishStats()
		ff.resetDNSAllowedForBenchmark()
		if err := manager.admitCanonical(request); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	assertDNSOwnershipIndexes(b, manager)
	if len(manager.churnBudget.buckets) != 1 {
		b.Fatalf("fixed-clock cold admissions should coalesce into one churn bucket, got %d", len(manager.churnBudget.buckets))
	}
}

// BenchmarkDNSOwnershipColdNewKeyWorkingSet guards the normal cold-path
// invariant directly: admitting one definitely new key must remain
// response-sized even when 4095 unrelated keys are already tracked. The
// surgical inverse is allocation-free; its measured time is reported
// separately and subtracted from ns/op without per-iteration timer toggles,
// which would otherwise dominate benchmark calibration.
func BenchmarkDNSOwnershipColdNewKeyWorkingSet(b *testing.B) {
	for _, entries := range []int{0, 4095} {
		b.Run(fmt.Sprintf("entries_%d", entries), func(b *testing.B) {
			now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
			manager := populatedDNSOwnershipManager(b, entries, now)
			ff := manager.filter.(*fakeFilter)
			request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
				queryDomain: "incoming.example",
				owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "incoming.example"},
				records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.250"), ttl: time.Hour}},
			})
			if err != nil {
				b.Fatal(err)
			}
			incomingAddr, err := canonicalDNSAddr(request.records[0].ip)
			if err != nil {
				b.Fatal(err)
			}
			incomingEdge := dnsOwnershipKey{
				query: string(request.queryDomain),
				owner: dnsPolicyOwner{kind: request.owner.kind, domain: string(request.owner.domain)},
			}

			b.ReportAllocs()
			var resetElapsed time.Duration
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				outcome, err := manager.admitCanonicalDetailed(request)
				if err != nil {
					b.Fatal(err)
				}
				if !outcome.changed || outcome.committedUnits != 1 {
					b.Fatalf("cold admission outcome = %+v, want one committed physical unit", outcome)
				}
				resetStarted := time.Now()
				removeColdDNSOwnershipBenchmarkAdmission(b, manager, incomingAddr, incomingEdge)
				ff.resetDNSAllowedForBenchmark()
				resetElapsed += time.Since(resetStarted)
			}
			b.StopTimer()
			elapsed := b.Elapsed()
			if b.N <= 0 || resetElapsed < 0 || resetElapsed >= elapsed {
				b.Fatalf("invalid benchmark timing: iterations=%d elapsed=%s fixture reset=%s", b.N, elapsed, resetElapsed)
			}
			iterations := float64(b.N)
			b.ReportMetric(float64((elapsed-resetElapsed).Nanoseconds())/iterations, "ns/op")
			b.ReportMetric(float64(resetElapsed.Nanoseconds())/iterations, "fixture-reset-ns/op")
			b.ReportMetric(float64(elapsed.Nanoseconds())/iterations, "raw-total-ns/op")
			assertDNSOwnershipIndexes(b, manager)
			dnsAllowed, addCalls := ff.dnsSnapshot()
			if len(dnsAllowed) != 0 || addCalls != b.N {
				b.Fatalf("final exact state=%v add calls=%d, want empty and %d", dnsAllowed, addCalls, b.N)
			}
		})
	}
}

// BenchmarkDNSOwnershipPhysicalPressure measures a full exact-map replacement
// at the 4096-key IPv4 capacity. The per-owner, edge, and logical family caps
// are deliberately higher so the measured planner branch is physical LRU
// pressure rather than metadata reclamation.
func BenchmarkDNSOwnershipPhysicalPressure(b *testing.B) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	manager := populatedDNSOwnershipManager(b, 4096, now)
	manager.limits = dnsAdmissionLimits{8192, 64, 8192, 64, 8192}
	manager.capacity.IPv4Capacity = 4096
	manager.capacity.IPv6Capacity = 8192
	manager.publishStats()
	ff := manager.filter.(*fakeFilter)
	baseline := cloneDNSOwnedEntries(manager.entries)
	request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
		queryDomain: "large.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "large.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.250"), ttl: time.Hour}},
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outcome, err := manager.admitCanonicalDetailed(request)
		if err != nil {
			b.Fatal(err)
		}
		if outcome.committedUnits != 2 || manager.physicalIPv4 != 4096 {
			b.Fatalf("physical-pressure outcome = %+v occupancy=%d, want two units and 4096 keys", outcome, manager.physicalIPv4)
		}
		b.StopTimer()
		restoreDNSOwnershipBenchmarkBaseline(manager, baseline, now)
		ff.resetDNSAllowedForBenchmark()
		b.StartTimer()
	}
	b.StopTimer()
	assertDNSOwnershipIndexes(b, manager)
}

// BenchmarkDNSOwnershipExhaustedBudgetPhysicalMiss verifies that the
// response-sized guaranteed-add precheck rejects a new physical key at
// capacity without cloning or sorting the 4096-key ownership graph.
func BenchmarkDNSOwnershipExhaustedBudgetPhysicalMiss(b *testing.B) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	manager := populatedDNSOwnershipManager(b, 4096, now)
	manager.limits = dnsAdmissionLimits{4096, 64, 8192, 64, 8192}
	manager.churnLimits.maxUnits = 1
	manager.churnBudget = newDNSChurnBudget(dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute})
	reservation, err := manager.churnBudget.reserve(now, math.MaxUint32, 1)
	if err != nil {
		b.Fatal(err)
	}
	manager.churnBudget.commit(reservation)
	request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
		queryDomain: "large.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "large.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.250"), ttl: time.Hour}},
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.admitCanonicalDetailed(request)
		if !errors.Is(err, errDNSAdmissionBudget) {
			b.Fatalf("physical miss error = %v, want rolling-budget rejection", err)
		}
	}
}

// BenchmarkDNSOwnershipMaxEdgePressure64AddressResponse exercises a realizable
// bounded metadata shape: 64 distinct queries authorized by one wildcard rule
// own each of 128 physical keys (8192 edges). A 65th query over 64 existing
// keys must reclaim 64 zero-physical-collateral edges. The final transaction is
// intentionally zero churn units.
func BenchmarkDNSOwnershipMaxEdgePressure64AddressResponse(b *testing.B) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	limits := dnsAdmissionLimits{128, 64, 128, 65, 8192}
	churn := dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute}
	manager, err := newDNSOwnershipManagerWithChurn(nil, limits, churn, time.Second, func() time.Time { return now })
	if err != nil {
		b.Fatal(err)
	}
	sharedOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "wildcard.example"}
	manager.policyDomains[sharedOwner.domain] = struct{}{}
	const addresses = 128
	const queriesPerAddress = 64
	for i := 0; i < addresses; i++ {
		addr, err := canonicalDNSAddr(benchmarkOwnershipIPv4(i + 1))
		if err != nil {
			b.Fatal(err)
		}
		var owners dnsOwnerEdgeSet
		for j := 0; j < queriesPerAddress; j++ {
			index := i*queriesPerAddress + j
			query := "wildcard.example"
			if j != 0 {
				query = fmt.Sprintf("q-%02d.wildcard.example", j)
			}
			edge := dnsOwnershipKey{
				query: query,
				owner: sharedOwner,
			}
			observed := now.Add(-time.Duration(addresses*queriesPerAddress-index) * time.Nanosecond)
			owners.putMaxObserved(edge, now.Add(time.Hour), observed)
		}
		entry := dnsOwnedIP{addr: addr, owners: owners}
		entry.lastObserved = dnsEntryLastObserved(entry)
		manager.entries[addr] = entry
	}
	manager.lastClock = now
	manager.rebuildOwnershipIndexes()
	assertDNSOwnershipIndexes(b, manager)
	baseline := cloneDNSOwnedEntries(manager.entries)
	records := make([]dnsAdmissionRecord, 0, 64)
	for i := 0; i < 64; i++ {
		records = append(records, dnsAdmissionRecord{ip: benchmarkOwnershipIPv4(i + 1), ttl: time.Hour})
	}
	request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
		queryDomain: "incoming.wildcard.example",
		owner:       sharedOwner,
		records:     records,
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outcome, err := manager.admitCanonicalDetailed(request)
		if err != nil {
			b.Fatal(err)
		}
		if outcome.committedUnits != 0 || manager.edgeCount != 8192 || manager.physicalIPv4 != 128 {
			b.Fatalf("metadata-pressure outcome=%+v edges=%d physical=%d", outcome, manager.edgeCount, manager.physicalIPv4)
		}
		b.StopTimer()
		restoreDNSOwnershipBenchmarkBaseline(manager, baseline, now)
		b.StartTimer()
	}
	b.StopTimer()
	assertDNSOwnershipIndexes(b, manager)
}

// BenchmarkDNSOwnershipSustainedMaxPressureGuard uses a production-realizable
// maximum graph: 32 configured exact queries own 128 IPv4 and 128 IPv6 keys
// (8192 edges). A new wildcard-authorized 64-key query cannot displace any
// configured query domain, so each permitted attempt performs a full failed
// plan while the exhausted case is rejected before projection.
func BenchmarkDNSOwnershipSustainedMaxPressureGuard(b *testing.B) {
	b.Run("permitted_full_plan", func(b *testing.B) {
		manager, request := newDNSMaxGraphWorkGuardBenchmarkFixture(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			manager.workBudget = newDNSChurnBudget(dnsChurnLimits{maxUnits: 8192, window: time.Minute})
			b.StartTimer()
			_, err := manager.admitCanonicalDetailed(request)
			if !errors.Is(err, errDNSAdmissionCapacity) {
				b.Fatalf("full-plan error = %v, want terminal capacity rejection", err)
			}
		}
	})

	b.Run("exhausted_preprojection_rejection", func(b *testing.B) {
		manager, request := newDNSMaxGraphWorkGuardBenchmarkFixture(b)
		for attempt := 1; attempt <= 8; attempt++ {
			_, err := manager.admitCanonicalDetailed(request)
			if !errors.Is(err, errDNSAdmissionCapacity) {
				b.Fatalf("setup plan %d error = %v", attempt, err)
			}
		}
		if manager.workBudget.activeUnits != 8192 {
			b.Fatalf("setup work units = %d, want 8192", manager.workBudget.activeUnits)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := manager.admitCanonicalDetailed(request)
			if !errors.Is(err, errDNSAdmissionWorkBudget) {
				b.Fatalf("exhausted error = %v, want pre-projection work rejection", err)
			}
		}
	})
}

func newDNSMaxGraphWorkGuardBenchmarkFixture(tb testing.TB) (*dnsOwnershipManager, dnsCanonicalAdmissionRequest) {
	tb.Helper()
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	limits := dnsAdmissionLimits{128, 64, 256, 32, 8192}
	churn := dnsChurnLimits{maxUnits: 8192, window: time.Minute}
	manager, err := newDNSOwnershipManagerWithChurn(nil, limits, churn, time.Second, func() time.Time { return now })
	if err != nil {
		tb.Fatal(err)
	}
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "wildcard.example"}
	queries := make([]string, 32)
	queries[0] = owner.domain
	manager.policyDomains[owner.domain] = struct{}{}
	for i := 1; i < len(queries); i++ {
		queries[i] = fmt.Sprintf("q-%02d.wildcard.example", i)
		manager.policyDomains[queries[i]] = struct{}{}
	}
	addresses := make([]netip.Addr, 0, 256)
	for i := 1; i <= 128; i++ {
		addr, err := canonicalDNSAddr(benchmarkOwnershipIPv4(i))
		if err != nil {
			tb.Fatal(err)
		}
		addresses = append(addresses, addr)
	}
	for i := 1; i <= 128; i++ {
		addresses = append(addresses, netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i)))
	}
	for addressIndex, addr := range addresses {
		var owners dnsOwnerEdgeSet
		for queryIndex, query := range queries {
			edge := dnsOwnershipKey{
				query: query,
				owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: query},
			}
			sequence := addressIndex*len(queries) + queryIndex
			observed := now.Add(-time.Duration(len(addresses)*len(queries)-sequence) * time.Nanosecond)
			owners.putMaxObserved(edge, now.Add(time.Hour), observed)
		}
		entry := dnsOwnedIP{addr: addr, owners: owners}
		entry.lastObserved = dnsEntryLastObserved(entry)
		manager.entries[addr] = entry
	}
	manager.lastClock = now
	manager.rebuildOwnershipIndexes()
	if err := validateDNSOwnedState(manager.entries, limits, manager.policyDomains, true); err != nil {
		tb.Fatalf("maximum work fixture is not policy-valid: %v", err)
	}
	if manager.physicalIPv4 != 128 || manager.physicalIPv6 != 128 || manager.edgeCount != 8192 || manager.trackedDomains != 32 {
		tb.Fatalf("maximum work fixture indexes: v4=%d v6=%d edges=%d domains=%d",
			manager.physicalIPv4, manager.physicalIPv6, manager.edgeCount, manager.trackedDomains)
	}
	records := make([]dnsAdmissionRecord, 0, 64)
	for _, addr := range addresses[:64] {
		records = append(records, dnsAdmissionRecord{ip: net.IP(addr.AsSlice()), ttl: time.Hour})
	}
	request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
		queryDomain: "attacker.wildcard.example",
		owner:       owner,
		records:     records,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if manager.workMaxItems != 8544 || manager.slowPlanWorkCost(len(records)) != 1024 {
		tb.Fatalf("maximum work fixture normalization: max=%d cost=%d", manager.workMaxItems, manager.slowPlanWorkCost(len(records)))
	}
	return manager, request
}

func BenchmarkDNSChurnBudgetNearCeiling(b *testing.B) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	limits := dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute}
	budget := newDNSChurnBudget(limits)
	reservation, err := budget.reserve(now, math.MaxUint32, math.MaxUint32-1)
	if err != nil {
		b.Fatal(err)
	}
	budget.commit(reservation)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reservation, err := budget.reserve(now, math.MaxUint32, 0)
		if err != nil {
			b.Fatal(err)
		}
		budget.commit(reservation)
	}
	b.StopTimer()
	if budget.activeUnits != uint64(math.MaxUint32-1) || len(budget.buckets) != 1 {
		b.Fatalf("near-ceiling budget mutated unexpectedly: %+v", budget)
	}
}

var benchmarkDNSStatsSink dnsOwnershipStats

func BenchmarkDNSOwnershipStatsSnapshot(b *testing.B) {
	manager := populatedDNSOwnershipManager(b, 4095, time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkDNSStatsSink = manager.stats()
	}
}

func TestDNSOwnershipStatsAndNearCeilingBudgetAreAllocationFree(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	manager := populatedDNSOwnershipManager(t, 4095, now)
	statsAllocs := testing.AllocsPerRun(1_000, func() {
		benchmarkDNSStatsSink = manager.stats()
	})
	assert.Zero(t, statsAllocs, "published DNS stats snapshots must remain allocation-free")

	limits := dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute}
	budget := newDNSChurnBudget(limits)
	reservation, err := budget.reserve(now, math.MaxUint32, math.MaxUint32-1)
	require.NoError(t, err)
	budget.commit(reservation)
	budgetAllocs := testing.AllocsPerRun(1_000, func() {
		reservation, reserveErr := budget.reserve(now, math.MaxUint32, 0)
		if reserveErr != nil {
			panic(reserveErr)
		}
		budget.commit(reservation)
	})
	assert.Zero(t, budgetAllocs, "near-ceiling zero-unit reserve/commit must remain allocation-free")
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
	manager, err := newDNSOwnershipManagerWithChurn(ff, limits,
		dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute}, time.Second, func() time.Time { return now })
	if err != nil {
		tb.Fatal(err)
	}
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "large.example"}
	edge := dnsOwnershipKey{query: "large.example", owner: owner}
	for i := 1; i <= entries; i++ {
		ip := benchmarkOwnershipIPv4(i)
		addr, _ := canonicalDNSAddr(ip)
		observed := now.Add(-time.Duration(entries-i+1) * time.Nanosecond)
		owners := newDNSOwnerEdgeSet(edge, now.Add(time.Hour))
		owners.observe(edge, observed)
		manager.entries[addr] = dnsOwnedIP{addr: addr, owners: owners, lastObserved: observed}
	}
	manager.lastClock = now
	manager.rebuildOwnershipIndexes()
	return manager
}

func benchmarkOwnershipIPv4(index int) net.IP {
	return net.IPv4(10, byte(index>>16), byte(index>>8), byte(index)).To4()
}

func restoreDNSOwnershipBenchmarkBaseline(manager *dnsOwnershipManager, baseline map[netip.Addr]dnsOwnedIP, now time.Time) {
	manager.entries = cloneDNSOwnedEntries(baseline)
	manager.highWater4 = 0
	manager.highWater6 = 0
	manager.lruEvictions = 0
	manager.rebuildOwnershipIndexes()
	manager.churnBudget = newDNSChurnBudget(dnsChurnLimits{maxUnits: math.MaxUint32, window: manager.churnLimits.window})
	manager.workBudget = newDNSChurnBudget(dnsChurnLimits{maxUnits: manager.workBudget.ceiling, window: manager.workBudget.window})
	manager.lastClock = now
}

// removeColdDNSOwnershipBenchmarkAdmission is the exact incremental inverse of
// one successful new-key fast-path admission. Keeping fixture restoration
// O(response) prevents the stopped-timer work from dominating wall time and
// benchmark calibration at the 4095-entry comparison point.
func removeColdDNSOwnershipBenchmarkAdmission(tb testing.TB, manager *dnsOwnershipManager, addr netip.Addr, edge dnsOwnershipKey) {
	tb.Helper()
	entry, ok := manager.entries[addr]
	if !ok || entry.owners.len() != 1 || entry.owners.inlineKey != edge {
		tb.Fatalf("cold benchmark admission cannot be reversed: addr=%s entry=%+v", addr, entry)
	}
	delete(manager.entries, addr)
	if addr.Is4() {
		manager.normalIPv4--
		manager.physicalIPv4--
	} else {
		manager.normalIPv6--
		manager.physicalIPv6--
	}
	manager.edgeCount--
	if manager.queryRefs[edge.query] == 1 {
		delete(manager.queryRefs, edge.query)
		if _, configured := manager.policyDomains[edge.query]; !configured {
			manager.trackedDomains--
		}
	} else {
		manager.queryRefs[edge.query]--
	}
	refs := manager.ownerIPRefs[edge.owner]
	switch {
	case refs.firstCount != 0 && refs.firstAddr == addr:
		if len(refs.overflow) != 0 || refs.firstCount != 1 {
			tb.Fatalf("cold benchmark incoming address unexpectedly became a shared first owner ref: %+v", refs)
		}
		delete(manager.ownerIPRefs, edge.owner)
	default:
		if refs.overflow[addr] != 1 {
			tb.Fatalf("cold benchmark incoming owner ref count = %d, want 1", refs.overflow[addr])
		}
		delete(refs.overflow, addr)
		manager.ownerIPRefs[edge.owner] = refs
	}
	manager.churnBudget = newDNSChurnBudget(manager.churnLimits)
	manager.publishStats()
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
	daemonServer, _, _, ff, server := newTestServerWithAttachment(b)
	sink, ok := server.sink.(*dnsFilterSink)
	if !ok {
		b.Fatalf("benchmark DNS sink has type %T, want *dnsFilterSink", server.sink)
	}
	fixedNow := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	daemonServer.now = func() time.Time { return fixedNow }
	benchmarkChurn := dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute}
	sink.manager.churnLimits = benchmarkChurn
	sink.manager.churnBudget = newDNSChurnBudget(benchmarkChurn)
	server.churnCeiling = benchmarkChurn
	server.churnLimits = benchmarkChurn
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
	manager.physicalIPv4 = 0
	manager.physicalIPv6 = 0
	manager.edgeCount = 0
	manager.trackedDomains = uint64(len(manager.policyDomains))
	clear(manager.queryRefs)
	clear(manager.ownerIPRefs)
	manager.publishStats()
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
	sink.manager.rebuildOwnershipIndexes()
	if err := dnsServer.addIPToFilter("example.com", net.ParseIP("192.0.2.80"), 32, 60); err != nil {
		t.Fatalf("seeding DNS ownership: %v", err)
	}
	dnsAllowed, addCalls := ff.dnsSnapshot()
	if len(sink.manager.entries) != 1 || sink.manager.normalIPv4 != 1 ||
		sink.manager.normalIPv6 != 0 || sink.manager.physicalIPv4 != 1 || sink.manager.physicalIPv6 != 0 ||
		sink.manager.trackedDomains != 1 || sink.manager.edgeCount != 1 ||
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
		sink.manager.normalIPv6 != 0 || sink.manager.physicalIPv4 != 1 || sink.manager.physicalIPv6 != 0 ||
		sink.manager.trackedDomains != 1 || sink.manager.edgeCount != 1 ||
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
		sink.manager.normalIPv6 != 0 || sink.manager.physicalIPv4 != 0 || sink.manager.physicalIPv6 != 0 ||
		sink.manager.trackedDomains != 1 || sink.manager.edgeCount != 0 ||
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
