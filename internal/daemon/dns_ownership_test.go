package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func TestDNSOwnershipSharedIPPromptRemovalAndTTL(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clock := newFakeClock()
	server.now = clock.Now
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "one.example"}, {Domain: "two.example"}}, nil))

	shared := net.ParseIP("203.0.113.10")
	oneOnly := net.ParseIP("203.0.113.11")
	require.NoError(t, dnsServer.addIPToFilter("one.example", shared, 32, 60))
	require.NoError(t, dnsServer.addIPToFilter("one.example", oneOnly, 32, 60))
	require.NoError(t, dnsServer.addIPToFilter("two.example", shared, 32, 120))
	assertDNSOwnershipIndexes(t, server.attachments[id].dnsSink.manager)
	manager := server.attachments[id].dnsSink.manager
	entry := manager.entries[netipMustParse(t, "203.0.113.10")]
	oneEdge := dnsOwnershipKey{query: "one.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "one.example"}}
	twoEdge := dnsOwnershipKey{query: "two.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "two.example"}}
	assert.True(t, entry.owners.occupied)
	assert.Equal(t, oneEdge, entry.owners.inlineKey)
	assert.Equal(t, clock.Now().Add(time.Minute), entry.owners.inlineDeadline)
	assert.Equal(t, clock.Now().Add(2*time.Minute), entry.owners.overflow[twoEdge])
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"203.0.113.10", "203.0.113.11"}, dnsAllowed)
	_, lpmAllowed, _, _ := ff.snapshot()
	assert.Empty(t, lpmAllowed, "DNS-derived hosts must never pollute the authoritative LPM tier")

	require.NoError(t, server.RemoveDomain(id, "one.example"))
	assertDNSOwnershipIndexes(t, server.attachments[id].dnsSink.manager)
	entry = manager.entries[netipMustParse(t, "203.0.113.10")]
	assert.Equal(t, twoEdge, entry.owners.inlineKey,
		"prompt removal rebuilds the surviving shared edge inline")
	assert.Equal(t, clock.Now().Add(2*time.Minute), entry.owners.inlineDeadline)
	assert.Nil(t, entry.owners.overflow)
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.10"}, dnsAllowed,
		"shared exact key must survive its other live domain owner")

	clock.Advance(2 * time.Minute)
	server.sweepExpiredTTLs(clock.Now())
	assertDNSOwnershipIndexes(t, server.attachments[id].dnsSink.manager)
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
}

func TestDNSOwnershipDuplicateResponseUsesMaxTTL(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{2, 4, 4, 4, 8}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)

	request := dnsAdmissionRequest{
		queryDomain: "Dup.Example.",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "dup.example"},
		records: []dnsAdmissionRecord{
			{ip: net.ParseIP("192.0.2.10"), ttl: 30 * time.Second},
			{ip: net.ParseIP("192.0.2.10").To4(), ttl: 5 * time.Minute},
			{ip: net.ParseIP("192.0.2.10"), ttl: time.Minute},
		},
	}
	require.NoError(t, manager.admit(request))
	require.Len(t, manager.entries, 1)
	entry := manager.entries[netipMustParse(t, "192.0.2.10")]
	require.Equal(t, 1, entry.owners.len())
	entry.owners.each(func(_ dnsOwnershipKey, deadline time.Time) {
		assert.Equal(t, clock.Now().Add(5*time.Minute), deadline)
	})
	dnsAllowed, calls := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.10"}, dnsAllowed)
	assert.Equal(t, 1, calls)
}

func TestDNSOwnerEdgeSetInlineRefreshOverflowAndExpiryPromotion(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{2, 1, 2, 3, 3}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	addr := net.ParseIP("192.0.2.90")
	oneOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "one.example"}
	twoOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "two.example"}
	oneEdge := dnsOwnershipKey{query: "one.example", owner: oneOwner}
	twoEdge := dnsOwnershipKey{query: "two.example", owner: twoOwner}

	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "one.example", owner: oneOwner,
		records: []dnsAdmissionRecord{{ip: addr, ttl: time.Minute}},
	}))
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "one.example", owner: oneOwner,
		records: []dnsAdmissionRecord{{ip: addr.To4(), ttl: 2 * time.Minute}},
	}))
	entry := manager.entries[netipMustParse(t, "192.0.2.90")]
	assert.True(t, entry.owners.occupied)
	assert.Equal(t, oneEdge, entry.owners.inlineKey)
	assert.Equal(t, clock.Now().Add(2*time.Minute), entry.owners.inlineDeadline)
	assert.Nil(t, entry.owners.overflow,
		"refreshing the inline edge must not allocate overflow")

	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "two.example", owner: twoOwner,
		records: []dnsAdmissionRecord{{ip: addr, ttl: 3 * time.Minute}},
	}))
	entry = manager.entries[netipMustParse(t, "192.0.2.90")]
	assert.Equal(t, 2, entry.owners.len())
	assert.Equal(t, clock.Now().Add(2*time.Minute), entry.owners.inlineDeadline)
	assert.Equal(t, clock.Now().Add(3*time.Minute), entry.owners.overflow[twoEdge])

	clock.Advance(2 * time.Minute)
	require.NoError(t, manager.expire(clock.Now()))
	entry = manager.entries[netipMustParse(t, "192.0.2.90")]
	assert.Equal(t, 1, entry.owners.len())
	assert.Equal(t, twoEdge, entry.owners.inlineKey,
		"expiry promotes the surviving overflow edge without dropping the physical key")
	assert.Equal(t, clock.Now().Add(time.Minute), entry.owners.inlineDeadline)
	assert.Nil(t, entry.owners.overflow)
	assert.Zero(t, ff.dnsRemoveCallCount())
	dnsAllowed, addCalls := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.90"}, dnsAllowed)
	assert.Equal(t, 1, addCalls, "shared-edge admission never re-adds the physical key")
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnerEdgeSetPermanentDeadlineWinsMaxUpdates(t *testing.T) {
	key := dnsOwnershipKey{query: "permanent.example", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "permanent.example"}}
	finite := time.Now().Add(time.Minute)

	finiteFirst := newDNSOwnerEdgeSet(key, finite)
	assert.False(t, finiteFirst.putMax(key, time.Time{}))
	deadline, ok := finiteFirst.get(key)
	require.True(t, ok)
	assert.True(t, deadline.IsZero())
	assert.Nil(t, finiteFirst.overflow)

	permanentFirst := newDNSOwnerEdgeSet(key, time.Time{})
	assert.False(t, permanentFirst.putMax(key, finite))
	deadline, ok = permanentFirst.get(key)
	require.True(t, ok)
	assert.True(t, deadline.IsZero())
	assert.Nil(t, permanentFirst.overflow)
}

func TestDNSOwnerEdgeSetRemapCollapseUsesMaximumDeadline(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{dnsAllowed: []string{"192.0.2.91"}}
	limits := dnsAdmissionLimits{2, 2, 2, 4, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	addr := netipMustParse(t, "192.0.2.91")
	query := "collapse.example"
	shortEdge := dnsOwnershipKey{query: query, owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "short.example"}}
	longEdge := dnsOwnershipKey{query: query, owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "long.example"}}
	owners := newDNSOwnerEdgeSet(shortEdge, clock.Now().Add(time.Minute))
	assert.True(t, owners.putMax(longEdge, clock.Now().Add(3*time.Minute)))
	manager.entries[addr] = dnsOwnedIP{addr: addr, owners: owners}
	manager.rebuildOwnershipIndexes()

	newOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "example"}
	require.NoError(t, manager.reconcile(limits, map[string]struct{}{"example": {}},
		func(string) (dnsPolicyOwner, bool) { return newOwner, true }, true))
	entry := manager.entries[addr]
	remapped := dnsOwnershipKey{query: query, owner: newOwner}
	deadline, ok := entry.owners.get(remapped)
	require.True(t, ok)
	assert.Equal(t, clock.Now().Add(3*time.Minute), deadline,
		"colliding remaps retain the maximum edge deadline")
	assert.Equal(t, 1, entry.owners.len())
	assert.Nil(t, entry.owners.overflow)
	assert.Zero(t, ff.dnsRemoveCallCount())
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnerEdgeSetFilterFailurePreservesExactRepresentation(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{3, 2, 3, 4, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	firstOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "first.example"}
	shared := net.ParseIP("192.0.2.92")
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "first.example", owner: firstOwner,
		records: []dnsAdmissionRecord{{ip: shared, ttl: time.Minute}},
	}))
	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeQueries := cloneUint64Map(manager.queryRefs)
	beforeRefs := snapshotOwnerIPRefs(manager.ownerIPRefs)
	beforeAllowed, beforeCalls := ff.dnsSnapshot()
	beforeIPv4, beforeEdges := manager.normalIPv4, manager.edgeCount

	injected := errors.New("injected exact add")
	ff.dnsAddErr = injected
	secondOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "second.example"}
	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "second.example", owner: secondOwner,
		records: []dnsAdmissionRecord{
			{ip: shared, ttl: 2 * time.Minute},
			{ip: net.ParseIP("192.0.2.93"), ttl: 2 * time.Minute},
		},
	})
	require.ErrorIs(t, err, injected)
	assert.Equal(t, beforeEntries, manager.entries,
		"filter failure must not publish the new shared overflow edge or physical entry")
	assert.Equal(t, beforeQueries, manager.queryRefs)
	assert.Equal(t, beforeRefs, snapshotOwnerIPRefs(manager.ownerIPRefs))
	assert.Equal(t, beforeIPv4, manager.normalIPv4)
	assert.Equal(t, beforeEdges, manager.edgeCount)
	afterAllowed, afterCalls := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)
	assert.Equal(t, beforeCalls+1, afterCalls, "the failed exact transaction is attempted once")
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnershipZeroUpstreamTTLUsesFloorButProxyOmissionUsesDefault(t *testing.T) {
	clock := newFakeClock()
	limits := dnsAdmissionLimits{2, 2, 2, 2, 4}
	upstreamFilter := &fakeFilter{}
	upstreamManager, err := newDNSOwnershipManager(upstreamFilter, limits, time.Minute, clock.Now)
	require.NoError(t, err)
	require.NoError(t, upstreamManager.admit(dnsAdmissionRequest{
		queryDomain: "zero.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "zero.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.11"), ttl: 0}},
	}))
	clock.Advance(time.Minute)
	require.NoError(t, upstreamManager.expire(clock.Now()))
	assert.Empty(t, upstreamManager.entries,
		"an upstream TTL=0 record must expire at the configured floor, not the proxy default")

	proxyFilter := &fakeFilter{}
	proxyManager, err := newDNSOwnershipManager(proxyFilter, limits, time.Minute, clock.Now)
	require.NoError(t, err)
	proxyServer := NewDNSServer("proxy", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, nil)
	proxyResp, err := proxyServer.proxyResponse(dnsQuery("proxy.example", dns.TypeA),
		"proxy.example", []string{"192.0.2.12"}, 0)
	require.NoError(t, err)
	proxyRecords, err := dnsAdmissionRecords(proxyResp)
	require.NoError(t, err)
	require.Len(t, proxyRecords, 1)
	assert.Equal(t, 300*time.Second, proxyRecords[0].ttl)
	require.NoError(t, proxyManager.admit(dnsAdmissionRequest{
		queryDomain: "proxy.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerProxy, domain: "proxy.example"},
		records:     proxyRecords,
	}))
	clock.Advance(299 * time.Second)
	require.NoError(t, proxyManager.expire(clock.Now()))
	assert.Len(t, proxyManager.entries, 1)
	clock.Advance(time.Second)
	require.NoError(t, proxyManager.expire(clock.Now()))
	assert.Empty(t, proxyManager.entries,
		"an omitted proxy TTL is explicitly materialized as the 300s proxy default")
}

func TestDNSOwnershipExpiryRemoveFailureRetainsStateForRetry(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{2, 2, 2, 2, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "retry.example"}
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "retry.example",
		owner:       owner,
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.13"), ttl: time.Minute}},
	}))

	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeQueries := cloneUint64Map(manager.queryRefs)
	beforeOwnerRefs := snapshotOwnerIPRefs(manager.ownerIPRefs)
	beforeIPv4, beforeIPv6, beforeEdges := manager.normalIPv4, manager.normalIPv6, manager.edgeCount
	beforeAllowed, beforeAddCalls := ff.dnsSnapshot()
	clock.Advance(time.Minute)

	injected := errors.New("transient exact remove")
	ff.dnsRemoveErr = injected
	err = manager.expire(clock.Now())
	require.ErrorIs(t, err, injected)
	assert.Equal(t, beforeEntries, manager.entries, "failed removal must retain the ownership graph")
	assert.Equal(t, beforeQueries, manager.queryRefs, "failed removal must retain query indexes")
	assert.Equal(t, beforeOwnerRefs, snapshotOwnerIPRefs(manager.ownerIPRefs), "failed removal must retain owner indexes")
	assert.Equal(t, beforeIPv4, manager.normalIPv4)
	assert.Equal(t, beforeIPv6, manager.normalIPv6)
	assert.Equal(t, beforeEdges, manager.edgeCount)
	afterFailureAllowed, afterFailureAddCalls := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterFailureAllowed, "failed removal must leave the exact filter key installed")
	assert.Equal(t, beforeAddCalls, afterFailureAddCalls)
	assert.Equal(t, 1, ff.dnsRemoveCallCount())
	assertDNSOwnershipIndexes(t, manager)

	ff.dnsRemoveErr = nil
	require.NoError(t, manager.expire(clock.Now()))
	assert.Empty(t, manager.entries)
	assert.Empty(t, manager.queryRefs)
	assert.Empty(t, manager.ownerIPRefs)
	assert.Zero(t, manager.normalIPv4)
	assert.Zero(t, manager.normalIPv6)
	assert.Zero(t, manager.edgeCount)
	afterRetryAllowed, afterRetryAddCalls := ff.dnsSnapshot()
	assert.Empty(t, afterRetryAllowed, "the retry must remove the expired exact filter key")
	assert.Equal(t, beforeAddCalls, afterRetryAddCalls)
	assert.Equal(t, 2, ff.dnsRemoveCallCount(), "the next janitor tick must retry the removal")
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnershipCapacityFailureIsAtomicAndRefreshNeedsNoCapacity(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{dnsCapacity4: 1, dnsCapacity6: 1}
	limits := dnsAdmissionLimits{1, 2, 2, 4, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "cap.example"}
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "cap.example", owner: owner,
		records: []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
	}))
	before := cloneDNSOwnedEntries(manager.entries)

	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "cap.example", owner: owner,
		records: []dnsAdmissionRecord{
			{ip: net.ParseIP("192.0.2.1"), ttl: 10 * time.Minute},
			{ip: net.ParseIP("192.0.2.2"), ttl: time.Minute},
		},
	})
	require.Error(t, err)
	assert.Equal(t, before, manager.entries, "failed response must not even refresh existing metadata")
	dnsAllowed, calls := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.1"}, dnsAllowed)
	assert.Equal(t, 1, calls)

	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "cap.example", owner: owner,
		records: []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: 10 * time.Minute}},
	}))
	_, calls = ff.dnsSnapshot()
	assert.Equal(t, 1, calls, "refreshing an admitted address needs no new exact capacity")
}

func TestDNSOwnershipTrackedDomainCapsIncludePolicyAndLiveQueriesAtomically(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{2, 2, 2, 2, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)

	policyLimits := limits
	policyLimits.maxTrackedDomains = 1
	err = manager.reconcile(policyLimits, map[string]struct{}{"one.example": {}, "two.example": {}},
		ownershipResolver(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil), true)
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Contains(t, err.Error(), "track 2 total policy/query domains")
	assert.Empty(t, manager.policyDomains, "an oversized policy map must be rejected before publication")
	assert.Empty(t, manager.entries)
	assertDNSOwnershipIndexes(t, manager)

	require.NoError(t, manager.reconcile(limits, map[string]struct{}{"example": {}},
		ownershipResolver(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil), true))
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "example"}
	shared := net.ParseIP("192.0.2.30")
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "a.example", owner: owner,
		records: []dnsAdmissionRecord{{ip: shared, ttl: time.Minute}},
	}))
	before := cloneDNSOwnedEntries(manager.entries)
	beforeQueries := cloneUint64Map(manager.queryRefs)
	beforeEdges := manager.edgeCount
	beforeAllowed, beforeCalls := ff.dnsSnapshot()

	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "b.example", owner: owner,
		records: []dnsAdmissionRecord{{ip: shared, ttl: time.Minute}},
	})
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Contains(t, err.Error(), "total policy/query domains")
	assert.Equal(t, before, manager.entries)
	assert.Equal(t, beforeQueries, manager.queryRefs)
	assert.Equal(t, beforeEdges, manager.edgeCount)
	afterAllowed, afterCalls := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)
	assert.Equal(t, beforeCalls, afterCalls)
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnershipEdgeCapRejectsSharedPhysicalIPWithoutMutation(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{2, 2, 2, 4, 1}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	shared := net.ParseIP("192.0.2.31")
	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "one.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "one.example"},
		records:     []dnsAdmissionRecord{{ip: shared, ttl: time.Minute}},
	}))
	before := cloneDNSOwnedEntries(manager.entries)
	beforeQueries := cloneUint64Map(manager.queryRefs)
	beforeOwnerRefs := snapshotOwnerIPRefs(manager.ownerIPRefs)
	beforeAllowed, beforeCalls := ff.dnsSnapshot()

	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "two.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "two.example"},
		records:     []dnsAdmissionRecord{{ip: shared, ttl: time.Minute}},
	})
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Contains(t, err.Error(), "ownership would use 2 edges")
	assert.Equal(t, before, manager.entries)
	assert.Equal(t, beforeQueries, manager.queryRefs)
	assert.Equal(t, beforeOwnerRefs, snapshotOwnerIPRefs(manager.ownerIPRefs))
	assert.Equal(t, uint64(1), manager.edgeCount)
	afterAllowed, afterCalls := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)
	assert.Equal(t, beforeCalls, afterCalls, "shared physical capacity must not be touched on edge rejection")
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnershipPolicyOwnerCapCountsUniqueIPsAcrossWildcardQueries(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{2, 1, 1, 4, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	require.NoError(t, manager.reconcile(limits, map[string]struct{}{"example": {}},
		ownershipResolver(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil), true))
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "example"}
	shared := net.ParseIP("192.0.2.40")
	for _, query := range []string{"a.example", "b.example"} {
		require.NoError(t, manager.admit(dnsAdmissionRequest{
			queryDomain: query,
			owner:       owner,
			records:     []dnsAdmissionRecord{{ip: shared, ttl: time.Minute}},
		}))
	}
	assert.Equal(t, uint64(2), manager.edgeCount, "each query keeps its own TTL edge")
	assert.Equal(t, 1, manager.ownerIPRefs[owner].uniqueLen(), "a shared IP consumes one matched-owner address slot")
	before := cloneDNSOwnedEntries(manager.entries)
	beforeQueries := cloneUint64Map(manager.queryRefs)
	beforeOwnerRefs := snapshotOwnerIPRefs(manager.ownerIPRefs)
	beforeAllowed, beforeCalls := ff.dnsSnapshot()

	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "c.example",
		owner:       owner,
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.41"), ttl: time.Minute}},
	})
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Contains(t, err.Error(), `policy owner "example" would own 2 unique addresses`)
	assert.Equal(t, before, manager.entries)
	assert.Equal(t, beforeQueries, manager.queryRefs)
	assert.Equal(t, beforeOwnerRefs, snapshotOwnerIPRefs(manager.ownerIPRefs))
	assert.Equal(t, uint64(2), manager.edgeCount)
	afterAllowed, afterCalls := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)
	assert.Equal(t, beforeCalls, afterCalls)
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSOwnerIPRefSetInlineOverflowFailureAndExpiryRebuild(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{3, 1, 2, 4, 4}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	owner := dnsPolicyOwner{kind: dnsOwnerRule, domain: "example"}
	first := net.ParseIP("192.0.2.50")
	second := net.ParseIP("192.0.2.51")

	for _, query := range []string{"a.example", "b.example"} {
		require.NoError(t, manager.admit(dnsAdmissionRequest{
			queryDomain: query,
			owner:       owner,
			records:     []dnsAdmissionRecord{{ip: first, ttl: time.Minute}},
		}))
	}
	refs := manager.ownerIPRefs[owner]
	firstAddr := netipMustParse(t, "192.0.2.50")
	assert.Equal(t, 1, refs.uniqueLen())
	assert.Equal(t, uint64(2), refs.count(firstAddr),
		"two query edges to one owner/address share one unique-IP slot")
	assert.Nil(t, refs.overflow)

	require.NoError(t, manager.admit(dnsAdmissionRequest{
		queryDomain: "c.example",
		owner:       owner,
		records:     []dnsAdmissionRecord{{ip: second, ttl: 2 * time.Minute}},
	}))
	refs = manager.ownerIPRefs[owner]
	secondAddr := netipMustParse(t, "192.0.2.51")
	assert.Equal(t, 2, refs.uniqueLen())
	assert.Equal(t, uint64(2), refs.count(firstAddr))
	assert.Equal(t, uint64(1), refs.count(secondAddr))
	assert.Len(t, refs.overflow, 1, "a second distinct owner address uses bounded overflow")
	beforeEntries := cloneDNSOwnedEntries(manager.entries)
	beforeQueries := cloneUint64Map(manager.queryRefs)
	beforeRefs := snapshotOwnerIPRefs(manager.ownerIPRefs)
	beforeInline := refs
	beforeInline.overflow = cloneUint64Map(refs.overflow)
	beforeAllowed, beforeCalls := ff.dnsSnapshot()

	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "d.example",
		owner:       owner,
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.52"), ttl: time.Minute}},
	})
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Equal(t, beforeEntries, manager.entries)
	assert.Equal(t, beforeQueries, manager.queryRefs)
	assert.Equal(t, beforeRefs, snapshotOwnerIPRefs(manager.ownerIPRefs))
	assert.Equal(t, beforeInline, manager.ownerIPRefs[owner],
		"failed admission must not mutate the inline/overflow representation")
	afterAllowed, afterCalls := ff.dnsSnapshot()
	assert.Equal(t, beforeAllowed, afterAllowed)
	assert.Equal(t, beforeCalls, afterCalls)

	clock.Advance(time.Minute)
	require.NoError(t, manager.expire(clock.Now()))
	refs = manager.ownerIPRefs[owner]
	assert.Equal(t, 1, refs.uniqueLen())
	assert.Equal(t, secondAddr, refs.firstAddr,
		"rebuild promotes the surviving address after the prior inline address expires")
	assert.Equal(t, uint64(1), refs.firstCount)
	assert.Nil(t, refs.overflow)
	assertDNSOwnershipIndexes(t, manager)
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.51"}, dnsAllowed)
}

func TestDNSResponseCapacityServfailsAndPreservesExistingWorkingSet(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	upstream, _, _ := startDualProtocolUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		addresses := []string{"192.0.2.20"}
		query, _ := validateAndNormalizeDomain(req.Question[0].Name)
		if query == "overflow.example" {
			addresses = []string{"192.0.2.21", "192.0.2.22"}
		}
		for _, raw := range addresses {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(raw).To4(),
			})
		}
		_ = w.WriteMsg(resp)
	}))
	prepared, err := dnsServer.prepareConfig(&apiv1.DnsConfig{
		Mode:              apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		AllowDomains:      []*apiv1.DomainEntry{{Domain: "first.example"}, {Domain: "overflow.example"}},
		UpstreamServers:   []string{upstream},
		MaxIpsPerResponse: 1,
	})
	require.NoError(t, err)
	state, done, err := server.beginAttachmentMutation(id)
	require.NoError(t, err)
	err = server.replaceDNSPreparedAdmitted(id, state, prepared)
	require.NoError(t, server.finishDNSMutation(state, done, err))

	first := queryServer(dnsServer, "first.example", dns.TypeA)
	require.NotNil(t, first)
	assert.Equal(t, dns.RcodeSuccess, first.Rcode)
	require.Len(t, first.Answer, 1)

	overflow := queryServer(dnsServer, "overflow.example", dns.TypeA)
	require.NotNil(t, overflow)
	assert.Equal(t, dns.RcodeServerFailure, overflow.Rcode)
	assert.Empty(t, overflow.Answer)
	dnsAllowed, calls := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.20"}, dnsAllowed,
		"a rejected response must preserve the previously admitted working set exactly")
	assert.Equal(t, 1, calls, "the over-limit response must fail before any exact-map mutation")
}

func TestDNSDenylistAdmitsDefaultAndExplicitAllowsButNotDeniedQueries(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	upstream := startDNSOwnershipUpstream(t, map[string]string{
		"default.example":  "192.0.2.70",
		"explicit.example": "192.0.2.71",
		"denied.example":   "192.0.2.72",
	})
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST,
		[]*apiv1.DomainEntry{{Domain: "explicit.example"}},
		[]*apiv1.DomainEntry{{Domain: "denied.example"}}, []string{upstream}))

	defaultResp := queryServer(dnsServer, "default.example", dns.TypeA)
	explicitResp := queryServer(dnsServer, "explicit.example", dns.TypeA)
	deniedResp := queryServer(dnsServer, "denied.example", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, defaultResp.Rcode)
	assert.Equal(t, dns.RcodeSuccess, explicitResp.Rcode)
	assert.Equal(t, dns.RcodeRefused, deniedResp.Rcode)
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.70", "192.0.2.71"}, dnsAllowed)
	_, lpmAllowed, _, _ := ff.snapshot()
	assert.Empty(t, lpmAllowed, "resolver answers must use only the exact tier")

	manager := server.attachments[id].dnsSink.manager
	defaultEntry := manager.entries[netipMustParse(t, "192.0.2.70")]
	explicitEntry := manager.entries[netipMustParse(t, "192.0.2.71")]
	require.Equal(t, 1, defaultEntry.owners.len())
	require.Equal(t, 1, explicitEntry.owners.len())
	defaultEntry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
		assert.Equal(t, dnsOwnerDenylistDefault, edge.owner.kind)
	})
	explicitEntry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
		assert.Equal(t, dnsOwnerRule, edge.owner.kind)
	})
	assert.NotContains(t, manager.entries, netipMustParse(t, "192.0.2.72"))
}

func TestDNSExactAdmissionSurvivesPacketDenylistToAllowlistFlipWithoutRequery(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	upstream := startDNSOwnershipUpstream(t, map[string]string{"cached.example": "192.0.2.73"})
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DENYLIST))
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST, nil, nil, []string{upstream}))

	resp := queryServer(dnsServer, "cached.example", dns.TypeA)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	before, addCalls := ff.dnsSnapshot()
	require.Equal(t, []string{"192.0.2.73"}, before)
	require.Equal(t, 1, addCalls)

	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	after, addCalls := ff.dnsSnapshot()
	assert.Equal(t, before, after,
		"the exact working set must already be ready when packet policy begins consulting it")
	assert.Equal(t, 1, addCalls, "the mode flip must not rely on another DNS query")
	mode, err := ff.GetMode()
	require.NoError(t, err)
	assert.Equal(t, filter.ModeAllowlist, mode)
}

func TestDNSDenylistExplicitAllowRemovalRemapsToDefaultAndDenyEvicts(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	upstream := startDNSOwnershipUpstream(t, map[string]string{"remap.example": "192.0.2.74"})
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST,
		[]*apiv1.DomainEntry{{Domain: "remap.example"}}, nil, []string{upstream}))
	require.Equal(t, dns.RcodeSuccess, queryServer(dnsServer, "remap.example", dns.TypeA).Rcode)

	require.NoError(t, server.RemoveDomain(id, "remap.example"))
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.74"}, dnsAllowed,
		"removing an explicit allow in DNS DENYLIST remaps ownership to implicit default allow")
	entry := server.attachments[id].dnsSink.manager.entries[netipMustParse(t, "192.0.2.74")]
	require.Equal(t, 1, entry.owners.len())
	entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
		assert.Equal(t, dnsOwnerDenylistDefault, edge.owner.kind)
	})

	require.NoError(t, server.DenyDomain(id, "remap.example", false))
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed, "adding a deny must promptly evict the query's last exact owner")
	assert.NotContains(t, server.attachments[id].dnsSink.manager.entries, netipMustParse(t, "192.0.2.74"))
}

func TestDNSOwnershipWildcardRemapCapRejectsConfigAtomically(t *testing.T) {
	server, _, _, ff, dnsServer := newTestServerWithAttachment(t)
	overrides := dnsAdmissionLimitOverrides{maxIPsPerPolicyDomain: 1}
	initial, err := prepareDNSRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "a.example"}, {Domain: "b.example"}}, nil, nil,
		server.defaultDNSUpstream, dnsServer.limitCeilings, overrides)
	require.NoError(t, err)
	require.NoError(t, dnsServer.applyPreparedRules(initial))
	require.NoError(t, dnsServer.addIPToFilter("a.example", net.ParseIP("192.0.2.1"), 32, 60))
	require.NoError(t, dnsServer.addIPToFilter("b.example", net.ParseIP("192.0.2.2"), 32, 60))

	wildcard, err := prepareDNSRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "example", IncludeSubdomains: true}}, nil, nil,
		server.defaultDNSUpstream, dnsServer.limitCeilings, overrides)
	require.NoError(t, err)
	err = dnsServer.applyPreparedRules(wildcard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "would own 2 unique addresses")
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, dnsAllowed)
	dnsServer.mu.RLock()
	assert.Contains(t, dnsServer.allowedDomains, "a.example")
	assert.Contains(t, dnsServer.allowedDomains, "b.example")
	assert.NotContains(t, dnsServer.allowedDomains, "example")
	dnsServer.mu.RUnlock()
}

func TestDNSOwnershipPinnedProvisionalIsBoundedAndAuthoritativelyRemoved(t *testing.T) {
	ff := &fakeFilter{
		dnsAllowed:   []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"},
		dnsCapacity4: 2,
		dnsCapacity6: 2,
	}
	global := dnsAdmissionLimits{4096, 64, 1024, 1024, 8192}
	manager, err := newDNSOwnershipManager(ff, global, time.Second, time.Now)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), manager.limits.maxIPsPerFamily)
	assert.Equal(t, uint32(4), manager.limits.maxIPsPerResponse,
		"dependent default is recapped to the adopted maps' aggregate capacity")
	require.NoError(t, manager.seedPinned())
	require.Len(t, manager.entries, 3)

	// An incremental update is not authoritative enough to discard restored
	// keys, even when ordinary logical caps are lower than provisional state.
	tiny := dnsAdmissionLimits{1, 1, 1, 1, 1}
	require.NoError(t, manager.reconcile(tiny, nil,
		ownershipResolver(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil), false))
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Len(t, dnsAllowed, 3)

	require.NoError(t, manager.reconcile(tiny, nil,
		ownershipResolver(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil), true))
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
	assert.Empty(t, manager.entries)
}

func TestDNSOwnershipPinnedInventoryAmbiguityIsRejected(t *testing.T) {
	mapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}
	ff := &fakeFilter{
		dnsListOverride: []net.IP{mapped},
		dnsOccupancyOverride: &filter.DNSAllowOccupancy{
			IPv4Entries: 0, IPv4Capacity: 1,
			IPv6Entries: 1, IPv6Capacity: 1,
		},
	}
	manager, err := newDNSOwnershipManager(ff, dnsAdmissionLimits{1, 1, 1, 1, 1}, time.Second, time.Now)
	require.NoError(t, err)
	err = manager.seedPinned()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inventory is ambiguous")
	assert.Empty(t, manager.entries)
}

func TestDNSOwnershipPinnedCanonicalCollisionIsRejectedAtomically(t *testing.T) {
	mapped := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}
	ff := &fakeFilter{
		dnsListOverride: []net.IP{net.IPv4(192, 0, 2, 1).To4(), mapped},
		dnsOccupancyOverride: &filter.DNSAllowOccupancy{
			IPv4Entries: 2, IPv4Capacity: 2,
			IPv6Capacity: 2,
		},
	}
	manager, err := newDNSOwnershipManager(ff, dnsAdmissionLimits{2, 2, 2, 2, 2}, time.Second, time.Now)
	require.NoError(t, err)
	err = manager.seedPinned()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "canonical collision")
	assert.Empty(t, manager.entries, "a rejected inventory must not publish a partial provisional graph")
	assert.False(t, manager.seeded)
}

func netipMustParse(t *testing.T, value string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(value)
	require.NoError(t, err)
	return addr
}

func TestDNSOwnershipAmbiguousMutationErrorIsRecognizable(t *testing.T) {
	ff := &fakeFilter{dnsAddErr: errors.Join(errors.New("write failed"), filter.ErrDNSAllowRollback)}
	manager, err := newDNSOwnershipManager(ff, dnsAdmissionLimits{1, 1, 1, 2, 2}, time.Second, time.Now)
	require.NoError(t, err)
	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "ambiguous.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "ambiguous.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
	})
	require.ErrorIs(t, err, filter.ErrDNSAllowRollback)
	assert.Empty(t, manager.entries)
}

func TestDNSAdmissionRejectsReplacedSinkWithSameFilter(t *testing.T) {
	server, _, id, ff, oldDNS := newTestServerWithAttachment(t)
	server.mu.RLock()
	oldSink := server.attachments[id].dnsSink
	server.mu.RUnlock()

	newSink, err := server.newDNSFilterSink(id, ff)
	require.NoError(t, err)
	newDNS := NewDNSServer(id, oldDNS.listenAddr, oldDNS.defaultUpstream, server.logger, newSink, nil, newSink.LimitCeilings())
	server.mu.Lock()
	server.attachments[id].dnsSink = newSink
	server.attachments[id].dns = newDNS
	server.mu.Unlock()

	done, err := oldSink.BeginAdmission()
	require.Error(t, err)
	assert.Nil(t, done)
	assert.Contains(t, err.Error(), "stale")

	done, err = newSink.BeginAdmission()
	require.NoError(t, err)
	require.NotNil(t, done)
	done()
}

func TestDNSCapacityDropsIncludeLogicalAndPhysicalButNotIO(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	server.mu.RLock()
	sink := server.attachments[id].dnsSink
	server.mu.RUnlock()
	require.NotNil(t, sink)
	sink.manager.limits.maxIPsPerResponse = 1
	request := dnsAdmissionRequest{
		queryDomain: "capacity.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "capacity.example"},
		records: []dnsAdmissionRecord{
			{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute},
			{ip: net.ParseIP("192.0.2.2"), ttl: time.Minute},
		},
	}
	require.ErrorIs(t, sink.AdmitResponse(request), errDNSAdmissionCapacity)
	assert.Equal(t, uint64(1), sink.CapacityDropCount())

	request.records = request.records[:1]
	ff.dnsAddErr = filter.ErrDNSAllowCapacity
	require.ErrorIs(t, sink.AdmitResponse(request), filter.ErrDNSAllowCapacity)
	assert.Equal(t, uint64(2), sink.CapacityDropCount())

	ff.dnsAddErr = fmt.Errorf("concurrent exact map fill: %w", syscall.E2BIG)
	require.Error(t, sink.AdmitResponse(request))
	assert.Equal(t, uint64(3), sink.CapacityDropCount(),
		"a backend map-full errno remains capacity pressure even after userspace preflight")

	ff.dnsAddErr = errors.Join(fmt.Errorf("ambiguous concurrent fill: %w", syscall.E2BIG), filter.ErrDNSAllowRollback)
	require.ErrorIs(t, sink.AdmitResponse(request), filter.ErrDNSAllowRollback)
	assert.Equal(t, uint64(4), sink.CapacityDropCount(),
		"rollback ambiguity changes quarantine handling, not capacity-drop classification")

	ff.dnsAddErr = errors.New("injected I/O failure")
	require.Error(t, sink.AdmitResponse(request))
	assert.Equal(t, uint64(4), sink.CapacityDropCount(), "arbitrary I/O failure is not capacity pressure")

	ff.dnsAddErr = nil
	ff.setAllowErr(fmt.Errorf("authoritative map full: %w", syscall.ENOSPC))
	require.Error(t, server.AllowCIDR(id, mustCIDR(t, "198.51.100.1/32"), 0))
	stats := server.GetAttachmentStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(5), stats[0].MapFullDrops,
		"compatibility stat sums one authoritative LPM drop and four exact/logical DNS drops")
}

func TestDNSCapacityWarningsAreRateLimitedButOtherFailuresRemainVisible(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clock := newFakeClock()
	server.now = clock.Now
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	server.logger = logger
	dnsServer.logger = logger.With().Str("component", "dns").Logger()
	server.mu.RLock()
	sink := server.attachments[id].dnsSink
	server.mu.RUnlock()
	sink.logger = logger.With().Str("id", id).Logger()
	upstream := startTestUpstream(t)
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "pressure.example"}}, nil, []string{upstream}))
	sink.manager.limits.maxIPsPerResponse = 0

	for range 3 {
		assert.Equal(t, dns.RcodeServerFailure, queryServer(dnsServer, "pressure.example", dns.TypeA).Rcode)
	}
	assert.Equal(t, uint64(3), sink.CapacityDropCount())
	clock.Advance(dnsCapacityWarnInterval)
	assert.Equal(t, dns.RcodeServerFailure, queryServer(dnsServer, "pressure.example", dns.TypeA).Rcode)
	assert.Equal(t, uint64(4), sink.CapacityDropCount())
	output := logs.String()
	assert.Equal(t, 2, strings.Count(output, "DNS exact-tier admission rejected; existing working set preserved"),
		"repeated capacity failures must emit at most one Warn per interval")
	assert.Contains(t, output, `"capacity_drops":1`)
	assert.Contains(t, output, `"capacity_drops":4`)
	assert.Contains(t, output, "filter.max_dns_rule_entries")
	assert.Equal(t, 2, strings.Count(output, `"level":"warn"`),
		"the per-query resolver log must not duplicate the sink's rate-limited warning")

	logs.Reset()
	sink.manager.limits.maxIPsPerResponse = 1
	ff.dnsAddErr = errors.New("injected exact I/O")
	assert.Equal(t, dns.RcodeServerFailure, queryServer(dnsServer, "pressure.example", dns.TypeA).Rcode)
	assert.Contains(t, logs.String(), "DNS response admission failed",
		"non-capacity I/O failures remain immediately visible")
	assert.Equal(t, uint64(4), sink.CapacityDropCount())

	logs.Reset()
	ff.dnsAddErr = errors.Join(fmt.Errorf("ambiguous map fill: %w", syscall.E2BIG), filter.ErrDNSAllowRollback)
	assert.Equal(t, dns.RcodeServerFailure, queryServer(dnsServer, "pressure.example", dns.TypeA).Rcode)
	assert.Contains(t, logs.String(), "DNS response admission failed",
		"rollback ambiguity remains immediately visible for quarantine diagnosis")
	assert.NotContains(t, logs.String(), "existing working set preserved",
		"ambiguity must not emit the ordinary capacity-pressure message")
	assert.Equal(t, uint64(5), sink.CapacityDropCount())
}

func TestDNSOwnershipCounterArithmeticCannotWrap(t *testing.T) {
	ff := &fakeFilter{}
	limits := dnsAdmissionLimits{math.MaxUint32, 1, math.MaxUint32, math.MaxUint32, math.MaxUint32}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, time.Now)
	require.NoError(t, err)
	manager.normalIPv4 = math.MaxUint32
	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "overflow.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "overflow.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
	})
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Contains(t, err.Error(), "4294967296")

	manager.normalIPv4 = 0
	manager.edgeCount = math.MaxUint32
	err = manager.admit(dnsAdmissionRequest{
		queryDomain: "overflow.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "overflow.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.1"), ttl: time.Minute}},
	})
	require.ErrorIs(t, err, errDNSAdmissionCapacity)
	assert.Contains(t, err.Error(), "4294967296")
}

func TestDNSOwnershipNearCapacityNoopExpiryAllocatesNothing(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	manager := populatedDNSOwnershipManager(t, 4095, now)
	allocs := testing.AllocsPerRun(100, func() {
		if err := manager.expire(now); err != nil {
			panic(err)
		}
	})
	assert.Zero(t, allocs)
	assert.Len(t, manager.entries, 4095)
	assertDNSOwnershipIndexes(t, manager)
	ff := manager.filter.(*fakeFilter)
	assert.Zero(t, ff.dnsRemoveCallCount(), "a no-op expiry tick must not attempt an exact-map removal")
}

func TestDNSOwnershipTrustedCanonicalWarmRefreshAllocatesNothing(t *testing.T) {
	clock := newFakeClock()
	ff := &fakeFilter{dnsCapacity4: 2, dnsCapacity6: 2}
	limits := dnsAdmissionLimits{2, 1, 1, 1, 1}
	manager, err := newDNSOwnershipManager(ff, limits, time.Second, clock.Now)
	require.NoError(t, err)
	request, err := canonicalizeDNSAdmissionRequest(dnsAdmissionRequest{
		queryDomain: "warm.example",
		owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: "warm.example"},
		records:     []dnsAdmissionRecord{{ip: net.ParseIP("192.0.2.72"), ttl: time.Minute}},
	})
	require.NoError(t, err)
	require.NoError(t, manager.admitCanonical(request))

	allocs := testing.AllocsPerRun(100, func() {
		if err := manager.admitCanonical(request); err != nil {
			panic(err)
		}
	})
	assert.Zero(t, allocs,
		"a validated resolver snapshot must not repeat wire canonicalization on every refresh")
	_, addCalls := ff.dnsSnapshot()
	assert.Equal(t, 1, addCalls)
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSAmbiguousAddBlocksAndQuarantinesBeforeQueuedModeWrite(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	upstream := startTestUpstream(t)
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "ambiguous.example"}}, nil, []string{upstream}))
	entered := make(chan struct{})
	release := make(chan struct{})
	ff.dnsAddEntered = entered
	ff.dnsAddRelease = release
	ff.dnsAddErr = errors.Join(errors.New("ambiguous exact add"), filter.ErrDNSAllowRollback)

	response := make(chan *dns.Msg, 1)
	go func() { response <- queryServer(dnsServer, "ambiguous.example", dns.TypeA) }()
	<-entered
	queued := make(chan struct{})
	server.mutationAdmissionHook = func(hookID string, _ *attachmentState) {
		if hookID == id {
			close(queued)
		}
	}
	modeResult := make(chan error, 1)
	go func() { modeResult <- server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DISABLED) }()
	<-queued // mode mutation now owns mutation R and is queued on the serial lock
	server.mutationAdmissionHook = nil
	close(release)
	resp := <-response
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	assert.Empty(t, resp.Answer)
	require.Error(t, <-modeResult)

	server.mu.RLock()
	state := server.attachments[id]
	assert.True(t, state.mutationsClosed)
	server.mu.RUnlock()
	mode, err := ff.GetMode()
	require.NoError(t, err)
	assert.Equal(t, filter.ModeBlockAll, mode, "queued mode write must never reopen after ambiguity")
	stored, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), stored.Mode)
}

func TestDNSAmbiguousPromptRemovalQuarantinesAndSubsequentQueryServfails(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	upstream := startTestUpstream(t)
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "remove.example"}}, nil, []string{upstream}))
	require.NoError(t, dnsServer.addIPToFilter("remove.example", net.ParseIP("203.0.113.10"), 32, 60))
	ff.dnsRemoveErr = errors.Join(errors.New("ambiguous exact remove"), filter.ErrDNSAllowRollback)
	err := server.RemoveDomain(id, "remove.example")
	require.ErrorIs(t, err, filter.ErrDNSAllowRollback)

	mode, modeErr := ff.GetMode()
	require.NoError(t, modeErr)
	assert.Equal(t, filter.ModeBlockAll, mode)
	stored, storeErr := st.GetAttachment(id)
	require.NoError(t, storeErr)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), stored.Mode)
	resp := queryServer(dnsServer, "remove.example", dns.TypeA)
	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	assert.Empty(t, resp.Answer)
}

func TestDNSAmbiguousExpiryQuarantinesAndPreservesRetryState(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	clock := newFakeClock()
	server.now = clock.Now
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "expiry.example"}}, nil))
	require.NoError(t, dnsServer.addIPToFilter("expiry.example", net.ParseIP("203.0.113.12"), 32, 60))
	ff.dnsRemoveErr = errors.Join(errors.New("ambiguous exact expiry"), filter.ErrDNSAllowRollback)

	clock.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clock.Now())

	mode, err := ff.GetMode()
	require.NoError(t, err)
	assert.Equal(t, filter.ModeBlockAll, mode)
	server.mu.RLock()
	state := server.attachments[id]
	assert.True(t, state.mutationsClosed)
	assert.Contains(t, state.dnsSink.manager.entries, netipMustParse(t, "203.0.113.12"),
		"failed expiry must retain ownership so a later authoritative retry can remove it")
	server.mu.RUnlock()
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.12"}, dnsAllowed)
	stored, storeErr := st.GetAttachment(id)
	require.NoError(t, storeErr)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), stored.Mode)
}

func startDNSOwnershipUpstream(t testing.TB, answers map[string]string) string {
	t.Helper()
	upstream, _, _ := startDualProtocolUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		query, _ := validateAndNormalizeDomain(req.Question[0].Name)
		if raw := answers[query]; raw != "" {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(raw).To4(),
			})
		}
		_ = w.WriteMsg(resp)
	}))
	return upstream
}

func cloneUint64Map[K comparable](input map[K]uint64) map[K]uint64 {
	clone := make(map[K]uint64, len(input))
	for key, value := range input {
		clone[key] = value
	}
	return clone
}

func snapshotOwnerIPRefs(input map[dnsPolicyOwner]dnsOwnerIPRefSet) map[dnsPolicyOwner]map[netip.Addr]uint64 {
	snapshot := make(map[dnsPolicyOwner]map[netip.Addr]uint64, len(input))
	for owner, refs := range input {
		flat := make(map[netip.Addr]uint64, refs.uniqueLen())
		if refs.firstCount != 0 {
			flat[refs.firstAddr] = refs.firstCount
		}
		for addr, count := range refs.overflow {
			flat[addr] = count
		}
		snapshot[owner] = flat
	}
	return snapshot
}

func assertDNSOwnershipIndexes(t *testing.T, manager *dnsOwnershipManager) {
	t.Helper()
	want4, want6, wantEdges := uint64(0), uint64(0), uint64(0)
	wantQueries := make(map[string]uint64)
	wantOwnerIPs := make(map[dnsPolicyOwner]map[netip.Addr]uint64)
	for addr, entry := range manager.entries {
		if entryHasNormalOwner(entry) {
			if addr.Is4() {
				want4++
			} else {
				want6++
			}
		}
		entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
			if edge.owner.kind == dnsOwnerProvisional {
				return
			}
			wantEdges++
			wantQueries[edge.query]++
			refs := wantOwnerIPs[edge.owner]
			if refs == nil {
				refs = make(map[netip.Addr]uint64)
				wantOwnerIPs[edge.owner] = refs
			}
			refs[addr]++
		})
	}
	assert.Equal(t, want4, manager.normalIPv4)
	assert.Equal(t, want6, manager.normalIPv6)
	assert.Equal(t, wantEdges, manager.edgeCount)
	assert.Equal(t, wantQueries, manager.queryRefs)
	assert.Equal(t, wantOwnerIPs, snapshotOwnerIPRefs(manager.ownerIPRefs))
}
