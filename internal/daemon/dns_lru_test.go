package daemon

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func newDNSLRUTestManager(t testing.TB, capacity uint32, limits dnsAdmissionLimits, churn dnsChurnLimits, clock *fakeClock) (*dnsOwnershipManager, *fakeFilter) {
	t.Helper()
	ff := &fakeFilter{dnsCapacity4: capacity, dnsCapacity6: capacity}
	manager, err := newDNSOwnershipManagerWithChurn(ff, limits, churn, time.Second, clock.Now)
	require.NoError(t, err)
	return manager, ff
}

func admitDNSLRUTest(t testing.TB, manager *dnsOwnershipManager, query, owner string, ttl time.Duration, ips ...string) error {
	t.Helper()
	records := make([]dnsAdmissionRecord, 0, len(ips))
	for _, raw := range ips {
		records = append(records, dnsAdmissionRecord{ip: net.ParseIP(raw), ttl: ttl})
	}
	return manager.admit(dnsAdmissionRequest{
		queryDomain: query,
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: owner},
		records:     records,
	})
}

func dnsLRUEdgeKeys(entry dnsOwnedIP) []dnsOwnershipKey {
	var keys []dnsOwnershipKey
	entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) { keys = append(keys, edge) })
	return keys
}

func TestDNSOwnershipStatsSnapshotsAreCoherent(t *testing.T) {
	manager, err := newDNSOwnershipManager(nil,
		dnsAdmissionLimits{100_000, 1, 1, 1, 1}, time.Second, time.Now)
	require.NoError(t, err)

	const generations = uint32(50_000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for generation := uint32(1); generation <= generations; generation++ {
			manager.physicalIPv4 = uint64(generation)
			manager.physicalIPv6 = uint64(generation)
			manager.highWater4 = generation
			manager.highWater6 = generation
			manager.lruEvictions = uint64(generation)
			manager.publishStats()
		}
	}()

	for {
		stats := manager.stats()
		generation := stats.occupancy.IPv4Entries
		if stats.occupancy.IPv6Entries != generation || stats.highWater4 != generation ||
			stats.highWater6 != generation || stats.lruEvictions != uint64(generation) {
			t.Fatalf("torn DNS stats snapshot: %+v", stats)
		}
		select {
		case <-done:
			final := manager.stats()
			assert.Equal(t, generations, final.occupancy.IPv4Entries)
			assert.GreaterOrEqual(t, final.highWater4, final.occupancy.IPv4Entries)
			assert.GreaterOrEqual(t, final.highWater6, final.occupancy.IPv6Entries)
			return
		default:
		}
	}
}

func TestDNSOwnershipStatsRetainHighWaterAndCountProvisionalPins(t *testing.T) {
	t.Run("expiry and policy removal", func(t *testing.T) {
		clock := newFakeClock()
		limits := dnsAdmissionLimits{3, 1, 1, 3, 3}
		manager, _ := newDNSLRUTestManager(t, 3, limits, dnsChurnLimits{maxUnits: 8, window: time.Minute}, clock)
		require.NoError(t, admitDNSLRUTest(t, manager, "short.example", "short.example", time.Second, "192.0.2.1"))
		require.NoError(t, admitDNSLRUTest(t, manager, "long.example", "long.example", time.Hour, "192.0.2.2"))
		stats := manager.stats()
		assert.Equal(t, uint32(2), stats.occupancy.IPv4Entries)
		assert.Equal(t, uint32(2), stats.highWater4)

		clock.Advance(2 * time.Second)
		require.NoError(t, manager.expire(clock.Now()))
		stats = manager.stats()
		assert.Equal(t, uint32(1), stats.occupancy.IPv4Entries)
		assert.Equal(t, uint32(2), stats.highWater4)
		assert.Zero(t, stats.lruEvictions)

		require.NoError(t, manager.reconcile(limits, nil, func(string) (dnsPolicyOwner, bool) {
			return dnsPolicyOwner{}, false
		}, true))
		stats = manager.stats()
		assert.Zero(t, stats.occupancy.IPv4Entries)
		assert.Equal(t, uint32(2), stats.highWater4)
		assert.Zero(t, stats.lruEvictions, "expiry and policy removal are not LRU evictions")
	})

	t.Run("restored provisional occupancy", func(t *testing.T) {
		clock := newFakeClock()
		ff := &fakeFilter{
			dnsAllowed:   []string{"192.0.2.10", "2001:db8::10"},
			dnsCapacity4: 3, dnsCapacity6: 3,
		}
		manager, err := newDNSOwnershipManagerWithChurn(ff,
			dnsAdmissionLimits{3, 1, 1, 1, 1}, dnsChurnLimits{maxUnits: 8, window: time.Minute}, time.Second, clock.Now)
		require.NoError(t, err)
		require.NoError(t, manager.seedPinned())
		stats := manager.stats()
		assert.Equal(t, uint32(1), stats.occupancy.IPv4Entries)
		assert.Equal(t, uint32(1), stats.occupancy.IPv6Entries)
		assert.Equal(t, uint32(1), stats.highWater4)
		assert.Equal(t, uint32(1), stats.highWater6)
		assert.Zero(t, stats.lruEvictions)
	})
}

func TestDNSProductionSinkSerializesConcurrentUniqueAdmissionsAndStats(t *testing.T) {
	_, _, _, ff, dnsServer := newTestServerWithAttachment(t)
	sink := dnsServer.sink.(*dnsFilterSink)
	const admissions = 64
	start := make(chan struct{})
	errs := make(chan error, admissions+1)
	statsDone := make(chan struct{})
	var admissionWG, statsWG sync.WaitGroup

	statsWG.Add(1)
	go func() {
		defer statsWG.Done()
		for {
			stats := sink.OwnershipStats()
			if stats.highWater4 < stats.occupancy.IPv4Entries || stats.highWater6 < stats.occupancy.IPv6Entries {
				errs <- errors.New("DNS occupancy exceeded high-water in a concurrent snapshot")
				return
			}
			select {
			case <-statsDone:
				return
			default:
			}
		}
	}()

	for i := 0; i < admissions; i++ {
		admissionWG.Add(1)
		go func(index int) {
			defer admissionWG.Done()
			<-start
			done, err := sink.BeginAdmission()
			if err != nil {
				errs <- err
				return
			}
			dnsServer.mu.RLock()
			err = sink.AdmitResponse(dnsAdmissionRequest{
				queryDomain: "concurrent-" + net.IPv4(0, 0, 0, byte(index+1)).String() + ".example",
				owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "concurrent.example"},
				records:     []dnsAdmissionRecord{{ip: net.IPv4(198, 51, 100, byte(index+1)), ttl: time.Hour}},
			})
			dnsServer.mu.RUnlock()
			done()
			if err != nil {
				errs <- err
			}
		}(i)
	}
	close(start)
	admissionWG.Wait()
	close(statsDone)
	statsWG.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	stats := sink.OwnershipStats()
	assert.Equal(t, uint32(admissions), stats.occupancy.IPv4Entries)
	assert.Equal(t, uint32(admissions), stats.highWater4)
	allowed, _ := ff.dnsSnapshot()
	assert.Len(t, allowed, admissions)
	assertDNSOwnershipIndexes(t, sink.manager)
}

func TestDNSAdmissionProjectsExpiryAndReplacementAtomically(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 2, 2, 4, 4}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 8, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Second, "192.0.2.1"))
	clock.Advance(2 * time.Second)

	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeBudget := append([]dnsChurnBucket(nil), manager.churnBudget.buckets...)
	beforeStats := manager.stats()
	beforeAllowed, _ := ff.dnsSnapshot()
	injected := errors.New("injected exact replacement")
	ff.dnsReplaceErr = injected
	err := admitDNSLRUTest(t, manager, "new.example", "new.example", time.Minute, "192.0.2.2")
	require.ErrorIs(t, err, injected)
	assert.Equal(t, beforeEntries, manager.entries, "failed replacement must not publish projected expiry")
	assert.Equal(t, beforeBudget, manager.churnBudget.buckets, "failed replacement must not prune or consume budget")
	assert.Equal(t, beforeStats, manager.stats(), "failed replacement must not publish LRU/high-water telemetry")
	afterAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)

	ff.dnsReplaceErr = nil
	require.NoError(t, admitDNSLRUTest(t, manager, "new.example", "new.example", time.Minute, "192.0.2.2"))
	allowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.2"}, allowed)
	assert.Equal(t, uint64(0), manager.stats().lruEvictions, "expired removal is free, not an LRU eviction")
	assert.Equal(t, uint64(2), manager.churnBudget.activeUnits, "old admission + one new physical admission")
}

func TestDNSExpiredEdgeReauthorizationKeepsPhysicalKeyAndCostsZero(t *testing.T) {
	clock := newFakeClock()
	manager, ff := newDNSLRUTestManager(t, 1, dnsAdmissionLimits{1, 1, 1, 1, 1}, dnsChurnLimits{maxUnits: 1, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "same.example", "same.example", time.Second, "192.0.2.1"))
	clock.Advance(2 * time.Second)
	outcome, err := manager.admitDetailed(dnsAdmissionRequest{
		queryDomain: "same.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "same.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
	})
	require.NoError(t, err)
	assert.True(t, outcome.changed)
	assert.Zero(t, outcome.committedUnits)
	assert.Zero(t, outcome.resolvedPressure, "same-physical expired reauthorization proves neither pressure class recovered")
	allowed, addCalls := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.1"}, allowed)
	assert.Equal(t, 1, addCalls)
	assert.Equal(t, uint64(1), manager.churnBudget.activeUnits)
	assert.Zero(t, ff.dnsReplaceCalls)
}

func TestDNSExpiredEdgeDifferentOwnerSlowProjectionKeepsPhysicalKeyAndCostsZero(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 1, 1, 1, 1}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 1, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Second, "192.0.2.1"))
	clock.Advance(2 * time.Second)

	outcome, err := manager.admitDetailed(dnsAdmissionRequest{
		queryDomain: "new.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "new.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
	})
	require.NoError(t, err)
	assert.True(t, outcome.changed)
	assert.Zero(t, outcome.committedUnits)
	assert.Equal(t, dnsCapacityPressure|dnsWorkPressure, outcome.resolvedPressure,
		"the permitted slow logical-cap projection proves capacity and work-budget recovery without proving mutation-budget recovery")
	allowed, addCalls := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.1"}, allowed)
	assert.Equal(t, 1, addCalls)
	assert.Zero(t, ff.dnsRemoveCalls)
	assert.Zero(t, ff.dnsReplaceCalls)
	assert.Equal(t, uint64(1), manager.churnBudget.activeUnits)
}

func TestDNSPhysicalLRUPreservedAcrossExpiryAndReconcile(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 2, 4, 8, 8}
	manager, ff := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 10, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.200"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "newer.example", "newer.example", time.Hour, "192.0.2.100"))
	require.NoError(t, admitDNSLRUTest(t, manager, "temporary.example", "temporary.example", time.Second, "192.0.2.100"))
	clock.Advance(2 * time.Second)
	require.NoError(t, manager.expire(clock.Now()))
	require.NoError(t, manager.reconcile(limits, map[string]struct{}{
		"old.example": {}, "newer.example": {}, "incoming.example": {},
	}, func(query string) (dnsPolicyOwner, bool) {
		return dnsPolicyOwner{kind: dnsOwnerRule, domain: query}, true
	}, true))
	require.NoError(t, admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.50"))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.50", "192.0.2.100"}, allowed,
		"resolver LRU must evict older .200 even though canonical tie-order would prefer .100")
	assert.Equal(t, uint64(1), manager.stats().lruEvictions)
}

func TestDNSPhysicalLRUTieAndFamilySelection(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 2, 5, 8, 8}
	manager, ff := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 10, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "v4-two.example", "v4-two.example", time.Hour, "192.0.2.2"))
	require.NoError(t, admitDNSLRUTest(t, manager, "v4-one.example", "v4-one.example", time.Hour, "192.0.2.1"))
	require.NoError(t, admitDNSLRUTest(t, manager, "v6.example", "v6.example", time.Hour, "2001:db8::1"))
	// The two eligible IPv4 keys have the same observation timestamp. The
	// lower canonical address is therefore the deterministic LRU tie winner.
	require.NoError(t, admitDNSLRUTest(t, manager, "v4-three.example", "v4-three.example", time.Hour, "192.0.2.3"))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.2", "192.0.2.3", "2001:db8::1"}, allowed,
		"canonical IPv4 tie-breaking must evict .1 without touching the IPv6 family")
}

func TestDNSDomainGroupLRUAvoidsPartialOlderMemberEviction(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{5, 2, 2, 2, 5}
	manager, ff := newDNSLRUTestManager(t, 5, limits, dnsChurnLimits{maxUnits: 10, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "q1.example", "q1.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q2.example", "q2.example", time.Hour, "192.0.2.3", "192.0.2.4"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q1.example", "q1.example", time.Hour, "192.0.2.2"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q3.example", "q3.example", time.Hour, "192.0.2.5"))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2", "192.0.2.5"}, allowed,
		"equal-collateral q2 is older by its newest member; q1 must not be partially destroyed because its first edge is older")
}

func TestDNSDomainPressurePreservesUnrelatedSharedOwner(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{3, 1, 3, 2, 6}
	manager, ff := newDNSLRUTestManager(t, 3, limits, dnsChurnLimits{maxUnits: 8, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "q1.example", "q1.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q2.example", "q2.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q3.example", "q3.example", time.Hour, "192.0.2.2"))
	shared := manager.entries[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, []dnsOwnershipKey{{query: "q2.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "q2.example"}}}, dnsLRUEdgeKeys(shared))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, allowed)
	assert.Zero(t, manager.stats().lruEvictions)
}

func TestDNSMetadataPressureCanReclaimOldEdgeOnIncomingIP(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 1, 3, 3, 2}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "q1.example", "q1.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q2.example", "q2.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "q3.example", "q3.example", time.Hour, "192.0.2.1"))
	entry := manager.entries[netip.MustParseAddr("192.0.2.1")]
	keys := dnsLRUEdgeKeys(entry)
	assert.Len(t, keys, 2)
	assert.NotContains(t, keys, dnsOwnershipKey{query: "q1.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "q1.example"}})
	assert.Contains(t, keys, dnsOwnershipKey{query: "q3.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "q3.example"}})
	allowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.1"}, allowed)
	assert.Equal(t, uint64(1), manager.churnBudget.activeUnits, "metadata-only edge reclamation is uncharged")
}

func TestDNSEdgePressureMinimizesPhysicalCollateralBeforeLRU(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 1, 2, 3, 2}
	manager, ff := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "shared-old.example", "shared-old.example", time.Hour, "192.0.2.2"))

	outcome, err := manager.admitDetailed(dnsAdmissionRequest{
		queryDomain: "incoming.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "incoming.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.2"), ttl: time.Hour}},
	})
	require.NoError(t, err, "a zero-churn logical alternative must succeed with an exhausted budget")
	assert.Zero(t, outcome.committedUnits)
	assert.Equal(t, dnsCapacityPressure|dnsWorkPressure, outcome.resolvedPressure)
	assert.Contains(t, manager.entries, netip.MustParseAddr("192.0.2.1"), "old sole-owner key must survive")
	shared := manager.entries[netip.MustParseAddr("192.0.2.2")]
	assert.Equal(t, []dnsOwnershipKey{{query: "incoming.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "incoming.example"}}}, dnsLRUEdgeKeys(shared))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, allowed)
	assert.Zero(t, manager.stats().lruEvictions)
}

func TestDNSDomainPressureMinimizesPhysicalCollateralBeforeLRU(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 1, 2, 2, 3}
	manager, ff := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "shared-old.example", "shared-old.example", time.Hour, "192.0.2.2"))

	outcome, err := manager.admitDetailed(dnsAdmissionRequest{
		queryDomain: "incoming.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "incoming.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.2"), ttl: time.Hour}},
	})
	require.NoError(t, err, "tracked-query reclamation must prefer the zero-churn complete group")
	assert.Zero(t, outcome.committedUnits)
	assert.Contains(t, manager.entries, netip.MustParseAddr("192.0.2.1"))
	shared := manager.entries[netip.MustParseAddr("192.0.2.2")]
	assert.Equal(t, []dnsOwnershipKey{{query: "incoming.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "incoming.example"}}}, dnsLRUEdgeKeys(shared))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, allowed)
}

func TestDNSOwnerPressureMinimizesPhysicalCollateralBeforeLRU(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{3, 1, 2, 4, 4}
	manager, ff := newDNSLRUTestManager(t, 3, limits, dnsChurnLimits{maxUnits: 3, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "owner.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "shared-owner.example", "owner.example", time.Hour, "192.0.2.2"))
	require.NoError(t, admitDNSLRUTest(t, manager, "shared-other.example", "other.example", time.Hour, "192.0.2.2"))
	clock.Advance(time.Second)

	outcome, err := manager.admitDetailed(dnsAdmissionRequest{
		queryDomain: "incoming.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "owner.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.3"), ttl: time.Hour}},
	})
	require.NoError(t, err, "owner-cap reclamation must leave the shared physical key and spend only the incoming unit")
	assert.Equal(t, uint64(1), outcome.committedUnits)
	assert.Contains(t, manager.entries, netip.MustParseAddr("192.0.2.1"), "older sole-owner key must survive when a zero-collateral alternative exists")
	shared := manager.entries[netip.MustParseAddr("192.0.2.2")]
	assert.Equal(t, []dnsOwnershipKey{{query: "shared-other.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "other.example"}}}, dnsLRUEdgeKeys(shared))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, allowed)
	assert.Equal(t, uint64(3), manager.churnBudget.activeUnits)
}

func TestDNSDomainGroupTieUsesLowestCanonicalNewestMember(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{5, 2, 2, 2, 5}
	manager, ff := newDNSLRUTestManager(t, 5, limits, dnsChurnLimits{maxUnits: 10, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "a.example", "a.example", time.Hour, "192.0.2.4", "192.0.2.1"))
	require.NoError(t, admitDNSLRUTest(t, manager, "b.example", "b.example", time.Hour, "192.0.2.3", "192.0.2.2"))
	require.NoError(t, admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.5"))

	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.2", "192.0.2.3", "192.0.2.5"}, allowed,
		"equal-recency complete groups use their lowest canonical newest-member address")
}

func TestDNSLogicalReclamationRecomputesPhysicalRecency(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 1, 2, 3, 4}
	manager, ff := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 10, window: time.Minute}, clock)
	require.NoError(t, manager.reconcile(limits, map[string]struct{}{"keep.example": {}}, func(query string) (dnsPolicyOwner, bool) {
		return dnsPolicyOwner{kind: dnsOwnerRule, domain: query}, true
	}, true))
	require.NoError(t, admitDNSLRUTest(t, manager, "keep.example", "keep.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "alternative.example", "alternative.example", time.Hour, "192.0.2.2"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "remove.example", "remove.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.3"))

	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.2", "192.0.2.3"}, allowed,
		"removing the recent logical edge must expose .1's older remaining observation to physical LRU")
	assert.Equal(t, uint64(1), manager.stats().lruEvictions)
}

func TestDNSReconcileCollisionKeepsIndependentMaxDeadlineAndObservation(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 1, 2, 3, 4}
	manager, ff := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 10, window: time.Minute}, clock)
	firstObserved := clock.Now()
	require.NoError(t, admitDNSLRUTest(t, manager, "shared.example", "old-one.example", 30*time.Minute, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "other.example", "other.example", time.Hour, "192.0.2.2"))
	clock.Advance(time.Second)
	secondObserved := clock.Now()
	require.NoError(t, admitDNSLRUTest(t, manager, "shared.example", "old-two.example", time.Hour, "192.0.2.1"))

	winner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "winner.example"}
	require.NoError(t, manager.reconcile(limits, nil, func(query string) (dnsPolicyOwner, bool) {
		if query == "shared.example" {
			return winner, true
		}
		return dnsPolicyOwner{kind: dnsOwnerRule, domain: query}, true
	}, true))
	entry := manager.entries[netip.MustParseAddr("192.0.2.1")]
	merged := dnsOwnershipKey{query: "shared.example", owner: winner}
	deadline, ok := entry.owners.get(merged)
	require.True(t, ok)
	assert.Equal(t, secondObserved.Add(time.Hour), deadline)
	assert.Equal(t, secondObserved, entry.owners.observed(merged))
	assert.Equal(t, secondObserved, entry.lastObserved)
	assert.True(t, firstObserved.Before(entry.lastObserved))

	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.3"))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.3"}, allowed,
		"the merged key's newest observation must keep it newer than the independent .2 key")
}

func TestDNSPhysicalLRUEvictionRemovesEverySharedOwner(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 1, 1, 3, 3}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 3, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "first.example", "first.example", time.Hour, "192.0.2.1"))
	require.NoError(t, admitDNSLRUTest(t, manager, "second.example", "second.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.2"))

	assert.NotContains(t, manager.queryRefs, "first.example")
	assert.NotContains(t, manager.queryRefs, "second.example")
	assert.Contains(t, manager.queryRefs, "incoming.example")
	allowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.2"}, allowed)
	assert.Equal(t, uint64(1), manager.stats().lruEvictions)
}

func TestDNSPolicyOwnerPressurePreservesOtherOwnerOnSharedIP(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{3, 1, 1, 8, 8}
	manager, ff := newDNSLRUTestManager(t, 3, limits, dnsChurnLimits{maxUnits: 8, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "a.child.example", "example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "other.example", "other.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "b.child.example", "example", time.Hour, "192.0.2.2"))
	shared := manager.entries[netip.MustParseAddr("192.0.2.1")]
	keys := dnsLRUEdgeKeys(shared)
	assert.Equal(t, []dnsOwnershipKey{{query: "other.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "other.example"}}}, keys)
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, allowed)
	assert.Zero(t, manager.stats().lruEvictions)
}

func TestDNSProvisionalKeyProtectsPhysicalButNotNormalMetadata(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{dnsAllowed: []string{"192.0.2.1"}, dnsCapacity4: 2, dnsCapacity6: 2}
	limits := dnsAdmissionLimits{2, 1, 2, 4, 1}
	manager, err := newDNSOwnershipManagerWithChurn(ff, limits, dnsChurnLimits{maxUnits: 4, window: time.Minute}, time.Second, clock.Now)
	require.NoError(t, err)
	require.NoError(t, manager.seedPinned())
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "new.example", "new.example", time.Hour, "192.0.2.2"))
	protected := manager.entries[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, 1, protected.owners.len())
	assert.Equal(t, dnsOwnerProvisional, protected.owners.inlineKey.owner.kind)
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, allowed)
	assert.Zero(t, manager.stats().lruEvictions)
}

func TestDNSNormalFamilyPressureStripsMetadataFromProvisionalKey(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{dnsAllowed: []string{"192.0.2.1"}, dnsCapacity4: 2, dnsCapacity6: 2}
	limits := dnsAdmissionLimits{1, 1, 1, 2, 2}
	manager, err := newDNSOwnershipManagerWithChurn(ff, limits, dnsChurnLimits{maxUnits: 1, window: time.Minute}, time.Second, clock.Now)
	require.NoError(t, err)
	require.NoError(t, manager.seedPinned())
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	clock.Advance(time.Second)
	require.NoError(t, admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.2"))

	pinned := manager.entries[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, 1, pinned.owners.len())
	assert.Equal(t, dnsOwnerProvisional, pinned.owners.inlineKey.owner.kind,
		"normal metadata is reclaimable while the restored physical pin survives")
	assert.Equal(t, uint64(1), manager.normalIPv4)
	assert.Equal(t, uint64(2), manager.physicalIPv4)
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, allowed)
	assert.Equal(t, uint64(1), manager.churnBudget.activeUnits, "only the incoming physical key is charged")
	assert.Zero(t, manager.stats().lruEvictions)
}

func TestDNSNormalFamilyPressureCannotStripIncomingEdgeFromProvisionalKey(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{dnsAllowed: []string{"192.0.2.1"}, dnsCapacity4: 2, dnsCapacity6: 2}
	limits := dnsAdmissionLimits{1, 2, 2, 3, 3}
	manager, err := newDNSOwnershipManagerWithChurn(ff, limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, time.Second, clock.Now)
	require.NoError(t, err)
	require.NoError(t, manager.seedPinned())
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	before := cloneDNSOwnedEntries(manager.entries)

	err = admitDNSLRUTest(t, manager, "incoming.example", "incoming.example", time.Hour, "192.0.2.1", "192.0.2.2")
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Equal(t, before, manager.entries, "the whole response fails atomically when every violating key is incoming-protected")
	allowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.1"}, allowed)
}

func TestDNSChurnBudgetBoundsRecoveryHistoryAndOverflow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	budget := newDNSChurnBudget(dnsChurnLimits{maxUnits: math.MaxUint32, window: time.Minute})
	reservation, err := budget.reserve(now, math.MaxUint32, math.MaxUint32)
	require.NoError(t, err)
	budget.commit(reservation)
	assert.Equal(t, uint64(math.MaxUint32), budget.activeUnits)
	_, err = budget.reserve(now, math.MaxUint32, 1)
	require.ErrorIs(t, err, errDNSAdmissionBudget)
	assert.Len(t, budget.buckets, 1, "unit count is bucketed instead of allocating one timestamp per unit")

	// Lowering does not discard history; a later raise still sees every unit.
	_, err = budget.reserve(now, 1, 1)
	require.ErrorIs(t, err, errDNSAdmissionBudget)
	_, err = budget.reserve(now, math.MaxUint32, 1)
	require.ErrorIs(t, err, errDNSAdmissionBudget)

	// Exact cutoff: age==window is expired and can be replaced by one bucket.
	reservation, err = budget.reserve(now.Add(time.Minute), math.MaxUint32, math.MaxUint32)
	require.NoError(t, err)
	budget.commit(reservation)
	assert.Equal(t, uint64(math.MaxUint32), budget.activeUnits)
	assert.Len(t, budget.buckets, 1)
	assert.True(t, reflect.DeepEqual(now.Add(time.Minute), budget.buckets[0].stamp))

	// A committed future timestamp remains active after wall-clock rollback
	// and expires only at its own exact window cutoff.
	_, err = budget.reserve(now, math.MaxUint32, 1)
	require.ErrorIs(t, err, errDNSAdmissionBudget)
	reservation, err = budget.reserve(now.Add(2*time.Minute), math.MaxUint32, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), reservation.units)
}

func TestDNSChurnBudgetDequeRemainsCeilingBoundedAcrossRollingExpiry(t *testing.T) {
	const ceiling = uint32(8)
	window := 8 * time.Second
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	budget := newDNSChurnBudget(dnsChurnLimits{maxUnits: ceiling, window: window})

	for i := 0; i < 2_000; i++ {
		now := start.Add(time.Duration(i) * time.Second)
		reservation, err := budget.reserve(now, ceiling, 1)
		require.NoError(t, err)
		budget.commit(reservation)

		active := budget.buckets[budget.head:]
		assert.LessOrEqual(t, len(active), int(ceiling))
		assert.LessOrEqual(t, len(budget.buckets), int(ceiling))
		assert.LessOrEqual(t, cap(budget.buckets), int(ceiling),
			"expired prefixes must not grow the backing allocation beyond the immutable unit ceiling")
		var sum uint64
		for j, bucket := range active {
			if j != 0 {
				assert.False(t, bucket.stamp.Before(active[j-1].stamp), "active buckets must remain chronological")
			}
			assert.Less(t, now.Sub(bucket.stamp), window, "age exactly equal to the window must be pruned")
			sum += uint64(bucket.units)
		}
		assert.Equal(t, budget.activeUnits, sum)
		assert.LessOrEqual(t, budget.activeUnits, uint64(ceiling))
	}
}

func newDNSMaxWorkGuardFixture(t testing.TB, clock *fakeClock) (*dnsOwnershipManager, *fakeFilter, dnsAdmissionRequest) {
	t.Helper()
	limits := dnsAdmissionLimits{2, 2, 2, 2, 4}
	manager, ff := newDNSLRUTestManager(t, 2, limits,
		dnsChurnLimits{maxUnits: 8192, window: time.Minute}, clock)
	manager.policyDomains = map[string]struct{}{"policy-one.example": {}, "policy-two.example": {}}
	manager.rebuildOwnershipIndexes()
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "policy-one.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "policy-one.example"},
		records: []dnsAdmissionRecord{
			{ip: net.ParseIP("192.0.2.1"), ttl: time.Hour},
			{ip: net.ParseIP("2001:db8::1"), ttl: time.Hour},
		},
	}))
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "policy-two.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "policy-two.example"},
		records: []dnsAdmissionRecord{
			{ip: net.ParseIP("192.0.2.2"), ttl: time.Hour},
			{ip: net.ParseIP("2001:db8::2"), ttl: time.Hour},
		},
	}))
	request := dnsAdmissionRequest{
		queryDomain: "attacker.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "attacker.example"},
		records: []dnsAdmissionRecord{
			{ip: net.ParseIP("192.0.2.1"), ttl: time.Hour},
			{ip: net.ParseIP("2001:db8::1"), ttl: time.Hour},
		},
	}
	return manager, ff, request
}

func TestDNSSlowPlanWorkGuardAllowsEightMaxPassesThenRejectsBeforePlanner(t *testing.T) {
	clock := newFakeClock()
	manager, ff, request := newDNSMaxWorkGuardFixture(t, clock)
	assert.Equal(t, uint32(1024), manager.workScale)
	assert.Equal(t, uint64(12), manager.workMaxItems)
	assert.Equal(t, uint64(1024), manager.slowPlanWorkCost(len(request.records)),
		"the fixture fills every immutable work dimension")
	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeMutationBudget := manager.churnBudget
	beforeAllowed, beforeAdds := ff.dnsSnapshot()

	for attempt := 1; attempt <= 8; attempt++ {
		err := manager.admit(request)
		require.ErrorIs(t, err, errDNSAdmissionCapacity, "max-shape plan %d must run before the work allowance is exhausted", attempt)
		require.NotErrorIs(t, err, errDNSAdmissionWorkBudget)
		assert.Equal(t, uint64(attempt*1024), manager.workBudget.activeUnits)
	}
	err := manager.admit(request)
	require.ErrorIs(t, err, errDNSAdmissionWorkBudget, "the ninth full-equivalent attempt must be rejected before graph projection")
	assert.Equal(t, uint64(8192), manager.workBudget.activeUnits)
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, beforeMutationBudget.buckets, manager.churnBudget.buckets)
	assert.Equal(t, beforeMutationBudget.activeUnits, manager.churnBudget.activeUnits,
		"failed planning and work throttling must not consume physical mutation history")
	afterAllowed, afterAdds := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)
	assert.Equal(t, beforeAdds, afterAdds)

	clock.Advance(time.Minute)
	err = manager.admit(request)
	require.ErrorIs(t, err, errDNSAdmissionCapacity,
		"work history expires at age exactly equal to the immutable window")
	require.NotErrorIs(t, err, errDNSAdmissionWorkBudget)
	assert.Equal(t, uint64(1024), manager.workBudget.activeUnits)
}

func TestDNSSlowPlanWorkGuardLowerRaiseRetainsStableHistory(t *testing.T) {
	clock := newFakeClock()
	manager, _, request := newDNSMaxWorkGuardFixture(t, clock)
	require.ErrorIs(t, manager.admit(request), errDNSAdmissionCapacity)
	assert.Equal(t, uint64(1024), manager.workBudget.activeUnits)
	assert.Equal(t, uint32(8192), manager.currentWorkLimit())

	resolver := func(query string) (dnsPolicyOwner, bool) {
		return dnsPolicyOwner{kind: dnsOwnerRule, domain: query}, true
	}
	require.NoError(t, manager.reconcileWithChurn(manager.limits,
		dnsChurnLimits{maxUnits: 1, window: time.Minute}, manager.policyDomains, resolver, true))
	assert.Equal(t, uint32(1024), manager.currentWorkLimit(),
		"lowering physical churn below the immutable scale still retains one max-equivalent pass")
	require.ErrorIs(t, manager.admit(request), errDNSAdmissionWorkBudget,
		"the prior full-pass unit remains active after lowering")
	assert.Equal(t, uint64(1024), manager.workBudget.activeUnits)

	require.NoError(t, manager.reconcileWithChurn(manager.limits,
		dnsChurnLimits{maxUnits: 8192, window: time.Minute}, manager.policyDomains, resolver, true))
	require.ErrorIs(t, manager.admit(request), errDNSAdmissionCapacity,
		"raising permits more work without reinterpreting or forgetting the prior stable-unit history")
	assert.Equal(t, uint64(2048), manager.workBudget.activeUnits)
}

func TestDNSSlowPlanWorkCostUsesSaturatingArithmetic(t *testing.T) {
	clock := newFakeClock()
	manager, _, _ := newDNSMaxWorkGuardFixture(t, clock)
	manager.physicalIPv4 = math.MaxUint64
	manager.physicalIPv6 = math.MaxUint64
	manager.edgeCount = math.MaxUint64
	manager.trackedDomains = math.MaxUint64
	assert.Equal(t, uint64(manager.workScale), manager.slowPlanWorkCost(math.MaxInt),
		"corrupt or saturated counters must clamp to one full-equivalent pass without wrapping")

	manager.physicalIPv4, manager.physicalIPv6 = 0, 0
	manager.edgeCount, manager.trackedDomains = 0, 0
	assert.Equal(t, uint64(1), manager.slowPlanWorkCost(0), "every slow-plan attempt costs at least one stable work unit")

	oversized := &fakeFilter{dnsCapacity4: math.MaxUint32, dnsCapacity6: math.MaxUint32}
	limits := dnsAdmissionLimits{4096, 64, 1024, 1024, 8192}
	manager, err := newDNSOwnershipManagerWithChurn(oversized, limits,
		dnsChurnLimits{maxUnits: 8192, window: time.Minute}, time.Second, clock.Now)
	require.NoError(t, err)
	assert.Equal(t, uint64(17_472), manager.workMaxItems,
		"oversized raw maps must not dilute the normal bound of min(capacity, two families, ownership edges)")
	manager.physicalIPv4, manager.physicalIPv6 = 4096, 4096
	manager.edgeCount, manager.trackedDomains = 8192, 1024
	assert.Equal(t, uint64(1024), manager.slowPlanWorkCost(64),
		"a maximum valid normal graph remains one full-equivalent pass with oversized backing maps")

	manager.physicalIPv4, manager.physicalIPv6 = math.MaxUint32, math.MaxUint32
	manager.edgeCount, manager.trackedDomains = 0, 0
	assert.Equal(t, uint64(1024), manager.slowPlanWorkCost(1),
		"restored provisional physical excess above normal ceilings clamps to a full-equivalent pass")
}

func TestDNSBudgetLowerBoundRejectsNewPhysicalKeyButAllowsZeroCostMetadataPressure(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 1, 1, 2, 1}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 1, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	require.Equal(t, uint64(1), manager.churnBudget.activeUnits)

	before := cloneDNSOwnedEntries(manager.entries)
	err := admitDNSLRUTest(t, manager, "new.example", "new.example", time.Hour, "192.0.2.2")
	require.ErrorIs(t, err, errDNSAdmissionBudget)
	assert.Equal(t, before, manager.entries)
	assert.Zero(t, ff.dnsReplaceCalls, "the response-sized lower-bound rejection must precede graph planning and filter replacement")

	outcome, err := manager.admitDetailed(dnsAdmissionRequest{
		queryDomain: "metadata.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "metadata.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Hour}},
	})
	require.NoError(t, err)
	assert.True(t, outcome.changed)
	assert.Zero(t, outcome.committedUnits,
		"edge pressure on an existing physical key must reach the planner and remain available at an exhausted budget")
	entry := manager.entries[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, []dnsOwnershipKey{{
		query: "metadata.example",
		owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "metadata.example"},
	}}, dnsLRUEdgeKeys(entry))
	assert.Equal(t, uint64(1), manager.churnBudget.activeUnits)
}

func TestDNSChurnCeilingOnlyAllowsPerAttachmentLowering(t *testing.T) {
	ceiling := resolveDNSChurnCeiling(100, 2*time.Minute)
	assert.Equal(t, dnsChurnLimits{maxUnits: 100, window: 2 * time.Minute}, ceiling)

	inherited, err := ceiling.resolve(0)
	require.NoError(t, err)
	assert.Equal(t, ceiling, inherited)
	lowered, err := ceiling.resolve(40)
	require.NoError(t, err)
	assert.Equal(t, dnsChurnLimits{maxUnits: 40, window: 2 * time.Minute}, lowered)
	_, err = ceiling.resolve(101)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds daemon ceiling 100")

	dnsServer := NewDNSServer("churn", "127.0.0.1:0", "127.0.0.1:53", zerolog.Nop(), nil, nil)
	dnsServer.churnCeiling = ceiling
	dnsServer.churnLimits = ceiling
	inheritedPrepared, err := dnsServer.prepareConfig(&apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_DISABLED})
	require.NoError(t, err)
	assert.Equal(t, ceiling, inheritedPrepared.churn, "zero control-plane override inherits the daemon ceiling")
	loweredPrepared, err := dnsServer.prepareConfig(&apiv1.DnsConfig{
		Mode: apiv1.DnsMode_DNS_MODE_DISABLED, MaxChurnUnits: 40,
	})
	require.NoError(t, err)
	require.NoError(t, dnsServer.applyPreparedRules(loweredPrepared))
	assert.Equal(t, uint32(40), dnsServer.currentConfigLocked().MaxChurnUnits)
	require.NoError(t, dnsServer.AllowDomain("preserve.example", false))
	assert.Equal(t, uint32(40), dnsServer.currentConfigLocked().MaxChurnUnits,
		"incremental DNS mutations preserve the applied lowered churn value")

	before := dnsServer.currentConfigLocked()
	_, err = dnsServer.prepareConfig(&apiv1.DnsConfig{
		Mode:          apiv1.DnsMode_DNS_MODE_DISABLED,
		MaxChurnUnits: 101,
	})
	require.Error(t, err)
	after := dnsServer.currentConfigLocked()
	assert.Equal(t, before, after, "an invalid control-plane churn override must not publish partial DNS state")
}

func TestDNSReplacementBudgetThrottlePreservesWorkingSetUntilExactCutoff(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 1, 1, 2, 2}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeBudget := manager.churnBudget

	err := admitDNSLRUTest(t, manager, "new.example", "new.example", time.Hour, "192.0.2.2")
	require.ErrorIs(t, err, errDNSAdmissionBudget, "one add plus one live LRU eviction costs two units")
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, beforeBudget.buckets, manager.churnBudget.buckets)
	assert.Equal(t, beforeBudget.head, manager.churnBudget.head)
	assert.Equal(t, beforeBudget.activeUnits, manager.churnBudget.activeUnits)
	allowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.1"}, allowed)
	assert.Zero(t, ff.dnsReplaceCalls, "budget rejection precedes the filter transaction")

	clock.Advance(time.Minute)
	require.NoError(t, admitDNSLRUTest(t, manager, "new.example", "new.example", time.Hour, "192.0.2.2"),
		"events expire at age exactly equal to the immutable window")
	allowed, _ = ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.2"}, allowed)
	assert.Equal(t, uint64(2), manager.churnBudget.activeUnits)
	assert.Equal(t, uint64(1), manager.stats().lruEvictions)
}

func TestDNSFailedForwardReplacementDoesNotPruneBudgetOrAdvanceClock(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{1, 1, 1, 2, 2}
	manager, ff := newDNSLRUTestManager(t, 1, limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeBuckets := append([]dnsChurnBucket(nil), manager.churnBudget.buckets...)
	beforeHead, beforeActive, beforeClock := manager.churnBudget.head, manager.churnBudget.activeUnits, manager.lastClock
	beforeWork := manager.workBudget.activeUnits

	clock.Advance(time.Minute)
	injected := errors.New("injected forward replacement failure")
	ff.dnsReplaceErr = injected
	err := admitDNSLRUTest(t, manager, "new.example", "new.example", time.Hour, "192.0.2.2")
	require.ErrorIs(t, err, injected)
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, beforeBuckets, manager.churnBudget.buckets)
	assert.Equal(t, beforeHead, manager.churnBudget.head)
	assert.Equal(t, beforeActive, manager.churnBudget.activeUnits)
	assert.Equal(t, beforeClock, manager.lastClock)
	assert.Greater(t, manager.workBudget.activeUnits, beforeWork,
		"the expensive attempt is retained even though the downstream exact replacement failed")

	ff.dnsReplaceErr = nil
	clock.Advance(-30 * time.Second)
	err = admitDNSLRUTest(t, manager, "new.example", "new.example", time.Hour, "192.0.2.2")
	require.ErrorIs(t, err, errDNSAdmissionWorkBudget,
		"a failed forward plan consumes work allowance, and the backward retry must retain that committed attempt history")
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, 1, ff.dnsReplaceCalls, "budget throttle must not make a second filter call")
}

func TestDNSChurnPolicyLowerRaiseRetainsHistoryAndRejectsWindowChanges(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{4, 1, 1, 4, 4}
	ceiling := dnsChurnLimits{maxUnits: 4, window: time.Minute}
	manager, ff := newDNSLRUTestManager(t, 4, limits, ceiling, clock)
	require.NoError(t, admitDNSLRUTest(t, manager, "one.example", "one.example", time.Hour, "192.0.2.1"))
	require.NoError(t, admitDNSLRUTest(t, manager, "two.example", "two.example", time.Hour, "192.0.2.2"))
	resolver := func(query string) (dnsPolicyOwner, bool) {
		return dnsPolicyOwner{kind: dnsOwnerRule, domain: query}, true
	}

	require.NoError(t, manager.reconcileWithChurn(limits, dnsChurnLimits{maxUnits: 1, window: time.Minute}, nil, resolver, true))
	require.NoError(t, admitDNSLRUTest(t, manager, "one.example", "one.example", time.Hour, "192.0.2.1"),
		"a zero-unit refresh remains available while the attachment is above a newly lowered limit")
	err := admitDNSLRUTest(t, manager, "three.example", "three.example", time.Hour, "192.0.2.3")
	require.ErrorIs(t, err, errDNSAdmissionBudget)

	require.NoError(t, manager.reconcileWithChurn(limits, dnsChurnLimits{maxUnits: 2, window: time.Minute}, nil, resolver, true))
	err = admitDNSLRUTest(t, manager, "three.example", "three.example", time.Hour, "192.0.2.3")
	require.ErrorIs(t, err, errDNSAdmissionBudget, "raising must not reconstruct or forget the two original active units")

	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeBudget := append([]dnsChurnBucket(nil), manager.churnBudget.buckets...)
	beforeLimits := manager.churnLimits
	err = manager.reconcileWithChurn(limits, dnsChurnLimits{maxUnits: 5, window: time.Minute}, nil, resolver, true)
	require.Error(t, err)
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, beforeBudget, manager.churnBudget.buckets)
	assert.Equal(t, beforeLimits, manager.churnLimits)
	err = manager.reconcileWithChurn(limits, dnsChurnLimits{maxUnits: 2, window: 2 * time.Minute}, nil, resolver, true)
	require.Error(t, err)
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, beforeBudget, manager.churnBudget.buckets)
	assert.Equal(t, beforeLimits, manager.churnLimits)

	clock.Advance(time.Minute)
	require.NoError(t, admitDNSLRUTest(t, manager, "three.example", "three.example", time.Hour, "192.0.2.3"))
	allowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, allowed)
	assert.Equal(t, uint64(1), manager.churnBudget.activeUnits)
}

func TestDNSChurnAccountingUnits(t *testing.T) {
	t.Run("new physical and duplicate response address", func(t *testing.T) {
		clock := newFakeClock()
		manager, _ := newDNSLRUTestManager(t, 2, dnsAdmissionLimits{2, 2, 2, 2, 2}, dnsChurnLimits{maxUnits: 8, window: time.Minute}, clock)
		outcome, err := manager.admitDetailed(dnsAdmissionRequest{
			queryDomain: "new.example",
			owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "new.example"},
			records: []dnsAdmissionRecord{
				{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute},
				{ip: net.ParseIP("192.0.2.1"), ttl: 2 * time.Minute},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), outcome.committedUnits)
		assert.Equal(t, uint64(1), manager.churnBudget.activeUnits)

		outcome, err = manager.admitDetailed(dnsAdmissionRequest{
			queryDomain: "logical.example",
			owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "logical.example"},
			records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
		})
		require.NoError(t, err)
		assert.Zero(t, outcome.committedUnits, "new logical ownership on an existing physical key is free")
		assert.Equal(t, uint64(1), manager.churnBudget.activeUnits)

		outcome, err = manager.admitDetailed(dnsAdmissionRequest{
			queryDomain: "logical.example",
			owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "logical.example"},
			records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
		})
		require.NoError(t, err)
		assert.False(t, outcome.changed)
		assert.Zero(t, outcome.committedUnits, "an unexpired refresh is free")
	})

	t.Run("expiry and policy removal", func(t *testing.T) {
		clock := newFakeClock()
		limits := dnsAdmissionLimits{2, 1, 1, 2, 2}
		manager, _ := newDNSLRUTestManager(t, 2, limits, dnsChurnLimits{maxUnits: 8, window: time.Minute}, clock)
		require.NoError(t, admitDNSLRUTest(t, manager, "expire.example", "expire.example", time.Second, "192.0.2.1"))
		before := manager.churnBudget.activeUnits
		clock.Advance(2 * time.Second)
		require.NoError(t, manager.expire(clock.Now()))
		assert.Equal(t, before, manager.churnBudget.activeUnits, "expiry physical removal is free")

		require.NoError(t, admitDNSLRUTest(t, manager, "policy.example", "policy.example", time.Hour, "192.0.2.2"))
		before = manager.churnBudget.activeUnits
		require.NoError(t, manager.reconcile(limits, nil, func(string) (dnsPolicyOwner, bool) { return dnsPolicyOwner{}, false }, true))
		assert.Equal(t, before, manager.churnBudget.activeUnits, "policy physical removal is free")
	})

	t.Run("metadata physical removal with existing incoming key", func(t *testing.T) {
		clock := newFakeClock()
		ff := &fakeFilter{dnsAllowed: []string{"192.0.2.2"}, dnsCapacity4: 2, dnsCapacity6: 2}
		limits := dnsAdmissionLimits{2, 1, 1, 2, 1}
		manager, err := newDNSOwnershipManagerWithChurn(ff, limits, dnsChurnLimits{maxUnits: 4, window: time.Minute}, time.Second, clock.Now)
		require.NoError(t, err)
		require.NoError(t, manager.seedPinned())
		require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
		outcome, err := manager.admitDetailed(dnsAdmissionRequest{
			queryDomain: "incoming.example",
			owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "incoming.example"},
			records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.2"), ttl: time.Hour}},
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(1), outcome.committedUnits,
			"deleting one live physical key through metadata LRU costs one while the incoming key already exists")
		assert.Equal(t, uint64(2), manager.churnBudget.activeUnits)
	})

	t.Run("full physical replacement", func(t *testing.T) {
		clock := newFakeClock()
		manager, _ := newDNSLRUTestManager(t, 1, dnsAdmissionLimits{1, 1, 1, 2, 2}, dnsChurnLimits{maxUnits: 4, window: time.Minute}, clock)
		require.NoError(t, admitDNSLRUTest(t, manager, "old.example", "old.example", time.Hour, "192.0.2.1"))
		outcome, err := manager.admitDetailed(dnsAdmissionRequest{
			queryDomain: "new.example",
			owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "new.example"},
			records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.2"), ttl: time.Hour}},
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(2), outcome.committedUnits, "one live eviction plus one new physical admission")
		assert.Equal(t, uint64(3), manager.churnBudget.activeUnits)
	})
}
