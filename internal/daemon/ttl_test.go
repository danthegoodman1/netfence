package daemon

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// fakeClock is an injectable clock for deterministic TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func allowCidrCmd(id, cidr string, ttl time.Duration) *apiv1.ControlCommand {
	entry := &apiv1.CIDREntry{Cidr: cidr}
	if ttl > 0 {
		entry.Ttl = durationpb.New(ttl)
	}
	return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: entry}}
}

func denyCidrCmd(id, cidr string, ttl time.Duration) *apiv1.ControlCommand {
	entry := &apiv1.CIDREntry{Cidr: cidr}
	if ttl > 0 {
		entry.Ttl = durationpb.New(ttl)
	}
	return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: entry}}
}

func removeCidrCmd(id, cidr string) *apiv1.ControlCommand {
	return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: cidr}}
}

// registryLen reports the attachment's pending-expiry count: entries with a
// finite deadline the janitor will eventually remove. Permanent entries are
// tracked too (for aliasing pins and the 2C diff seam) but never expire, so
// they are excluded here.
func registryLen(t *testing.T, server *Server, id string) int {
	t.Helper()
	server.mu.RLock()
	defer server.mu.RUnlock()
	state, ok := server.attachments[id]
	require.True(t, ok)
	return state.ttls.pendingLen()
}

// TestTTLCIDRExpiresAfterSweep covers the AllowCidr/DenyCidr command entry
// points: TTL'd entries are removed from the filter once the janitor sweeps
// past their deadline, and only then.
func TestTTLCIDRExpiresAfterSweep(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 5*time.Second))
	c.handleCommand(denyCidrCmd(id, "192.0.2.0/24", 10*time.Second))

	_, allowed, denied, _ := ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, denied)
	assert.Equal(t, 2, registryLen(t, server, id))

	// Not expired yet: sweep must not remove anything.
	clk.Advance(4 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, denied, _ = ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, denied)

	// Past the allow entry's TTL, before the deny entry's.
	clk.Advance(1 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, denied, _ = ff.snapshot()
	assert.Empty(t, allowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, denied)
	assert.Equal(t, 1, registryLen(t, server, id))

	// Past the deny entry's TTL.
	clk.Advance(5 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, denied, _ = ff.snapshot()
	assert.Empty(t, allowed)
	assert.Empty(t, denied)
	assert.Zero(t, registryLen(t, server, id))
}

// TestPermanentCIDRNeverExpires: entries without a TTL (nil proto duration)
// are permanent and never tracked or removed.
func TestPermanentCIDRNeverExpires(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 0))
	c.handleCommand(denyCidrCmd(id, "192.0.2.0/24", 0))
	assert.Zero(t, registryLen(t, server, id))

	clk.Advance(1000 * time.Hour)
	server.sweepExpiredTTLs(clk.Now())

	_, allowed, denied, _ := ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, denied)
}

// TestReAddRefreshesTTL: re-adding the same CIDR upserts its deadline, so a
// sweep past the original deadline does not remove it.
func TestReAddRefreshesTTL(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 5*time.Second))
	clk.Advance(3 * time.Second)
	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 5*time.Second)) // deadline now t=8s

	clk.Advance(3 * time.Second) // t=6s: past original deadline, before refreshed one
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed, "refreshed entry must survive its original deadline")
	assert.Equal(t, 1, registryLen(t, server, id))

	clk.Advance(2 * time.Second) // t=8s: refreshed deadline reached
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Empty(t, allowed)
}

// TestReAddWithoutTTLMakesPermanent: re-adding with ttl=0 clears the pending
// deadline entirely.
func TestReAddWithoutTTLMakesPermanent(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 5*time.Second))
	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 0))
	assert.Zero(t, registryLen(t, server, id))

	clk.Advance(1000 * time.Hour)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
}

// TestRemoveCidrPurgesRegistry: an explicit RemoveCidr drops the pending
// deadline, so a later re-add as permanent is not spuriously expired.
func TestRemoveCidrPurgesRegistry(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 5*time.Second))
	c.handleCommand(denyCidrCmd(id, "10.0.0.0/8", 5*time.Second))
	assert.Equal(t, 2, registryLen(t, server, id))

	// RemoveCidr removes from both lists and must purge both deadlines.
	c.handleCommand(removeCidrCmd(id, "10.0.0.0/8"))
	assert.Zero(t, registryLen(t, server, id))

	// Re-add as permanent; the old deadline must not fire.
	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 0))
	clk.Advance(1000 * time.Hour)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, denied, _ := ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Empty(t, denied)
}

// TestBulkUpdatePurgesAndTracksTTLs: a bulk update that re-declares a
// previously TTL'd CIDR as permanent pins it (the stale deadline cannot
// fire), while TTL'd entries in the bulk payload are tracked and expire.
func TestBulkUpdatePurgesAndTracksTTLs(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 5*time.Second))
	assert.Equal(t, 1, registryLen(t, server, id))

	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: "10.0.0.0/8"}, // now permanent
			{Cidr: "198.51.100.0/24", Ttl: durationpb.New(3 * time.Second)},
		},
	})
	assert.Equal(t, 1, registryLen(t, server, id))

	// Past the pre-bulk deadline for 10.0.0.0/8 and the bulk TTL for
	// 198.51.100.0/24: only the latter may be removed.
	clk.Advance(10 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Zero(t, registryLen(t, server, id))
}

// TestSubscribedAckTracksTTLs covers the applySubscribedAck entry point.
func TestSubscribedAckTracksTTLs(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.applySubscribedAck(id, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: "10.0.0.0/8", Ttl: durationpb.New(2 * time.Second)},
			{Cidr: "198.51.100.0/24"},
		},
		DenyCidrs: []*apiv1.CIDREntry{
			{Cidr: "192.0.2.0/24", Ttl: durationpb.New(2 * time.Second)},
		},
	})
	assert.Equal(t, 2, registryLen(t, server, id))

	clk.Advance(2 * time.Second)
	server.sweepExpiredTTLs(clk.Now())

	_, allowed, denied, _ := ff.snapshot()
	assert.Equal(t, []string{"198.51.100.0/24"}, allowed)
	assert.Empty(t, denied)
	assert.Zero(t, registryLen(t, server, id))
}

// TestSweepToleratesDetachedAttachment: detaching purges the registry and a
// sweep over an empty/missing attachment set does not panic or remove
// anything.
func TestSweepToleratesDetachedAttachment(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 1*time.Second))

	// Simulate the teardown bookkeeping done by Detach/handleTargetRemoved.
	server.mu.Lock()
	state := server.attachments[id]
	delete(server.attachments, id)
	delete(server.targetIndex, state.info.Target)
	server.mu.Unlock()
	state.ttls.purge()

	clk.Advance(time.Hour)
	server.sweepExpiredTTLs(clk.Now()) // must not panic
	assert.Zero(t, state.ttls.len())
}

// TestTTLJanitorGoroutineRemovesExpiredEntry exercises the real janitor
// goroutine end-to-end (ticker + stop channel): a short-TTL entry is removed
// without any manual sweep, and shutdown terminates the goroutine.
func TestTTLJanitorGoroutineRemovesExpiredEntry(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	server.ttlJanitorInterval = 5 * time.Millisecond
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", time.Millisecond))
	c.handleCommand(allowCidrCmd(id, "198.51.100.0/24", 0)) // permanent

	server.janitorWG.Add(1)
	go server.runTTLJanitor()

	require.Eventually(t, func() bool {
		_, allowed, _, _ := ff.snapshot()
		return len(allowed) == 1 && allowed[0] == "198.51.100.0/24"
	}, 5*time.Second, 5*time.Millisecond, "janitor should remove only the TTL'd entry")

	server.janitorStopOnce.Do(func() { close(server.janitorStop) })
	server.janitorWG.Wait()
}

// TestTTLConcurrentAddAndSweep hammers re-adds against janitor sweeps so the
// race detector can vet the registry locking, and verifies the invariant
// that a just-re-added entry is never left absent after a concurrent expiry.
func TestTTLConcurrentAddAndSweep(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", time.Second))
			// The entry was just re-added with a fresh deadline and the clock
			// has not advanced yet, so no concurrent sweep may remove it. A
			// non-atomic expire (decide under lock, remove filter entry
			// outside it) fails this assertion deterministically, not just
			// under the race detector.
			_, allowed, _, _ := ff.snapshot()
			if !assert.Contains(t, allowed, "10.0.0.0/8", "iteration %d: entry missing immediately after re-add", i) {
				return
			}
			clk.Advance(2 * time.Second)
		}
	}()

	for {
		select {
		case <-done:
			// Final re-add, then a sweep before its deadline: the entry must
			// be present regardless of how adds and sweeps interleaved.
			c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", time.Second))
			server.sweepExpiredTTLs(clk.Now())
			_, allowed, _, _ := ff.snapshot()
			assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
			return
		default:
			server.sweepExpiredTTLs(clk.Now())
		}
	}
}

// ---------------------------------------------------------------------------
// Phase 2B: DNS-populated IP expiry, aliasing, TTL floor, map-full handling.
// ---------------------------------------------------------------------------

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	cidr, err := filter.ParseCIDR(s)
	require.NoError(t, err)
	return cidr
}

// TestDNSAddedIPExpiresViaJanitor: a DNS-resolved IP whose record TTL is
// below the floor lives for the floor (default 60s), then the janitor
// removes it from the filter and the registry.
func TestDNSAddedIPExpiresViaJanitor(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	dnsServer.addIPToFilter("example.com", net.ParseIP("203.0.113.10"), 32, 30)
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"203.0.113.10/32"}, allowed)
	assert.Equal(t, 1, registryLen(t, server, id))

	// At the record TTL (30s) the 60s floor keeps it alive.
	clk.Advance(30 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"203.0.113.10/32"}, allowed, "floor must outlive the record TTL")

	// At the floor it expires.
	clk.Advance(30 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Empty(t, allowed)
	assert.Zero(t, registryLen(t, server, id))
}

// TestDNSRecordTTLAboveFloorIsHonored: the filter deadline is
// max(record TTL, floor), so a 300s record outlives the 60s floor.
func TestDNSRecordTTLAboveFloorIsHonored(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	dnsServer.addIPToFilter("example.com", net.ParseIP("203.0.113.11"), 32, 300)

	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"203.0.113.11/32"}, allowed, "record TTL above the floor must govern")

	clk.Advance(240 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Empty(t, allowed)
	assert.Zero(t, registryLen(t, server, id))
}

// TestDNSReResolutionRefreshesDeadline: re-resolving a tracked IP extends
// its deadline (max model) without touching the kernel map again.
func TestDNSReResolutionRefreshesDeadline(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	dnsServer.addIPToFilter("example.com", net.ParseIP("203.0.113.12"), 32, 60) // deadline t0+60
	clk.Advance(30 * time.Second)
	dnsServer.addIPToFilter("example.com", net.ParseIP("203.0.113.12"), 32, 60) // deadline t0+90
	assert.Equal(t, 1, ff.allowCallCount(), "re-resolution of a tracked IP must not hit the filter")

	clk.Advance(30 * time.Second) // t0+60: past the original deadline
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"203.0.113.12/32"}, allowed, "refreshed deadline must survive the original one")

	clk.Advance(30 * time.Second) // t0+90
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Empty(t, allowed)
	assert.Zero(t, registryLen(t, server, id))
}

// TestPermanentCPAllowPinsAliasedDNSIP is the aliasing key test: a permanent
// control-plane allow for the same /32 a DNS resolution produced must NEVER
// be removed when the DNS TTL lapses — in either arrival order, and
// including a bare-IP CP rule that canonicalizes to the same /32 key.
func TestPermanentCPAllowPinsAliasedDNSIP(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	// Order 1: CP permanent first, DNS resolution second.
	c.handleCommand(allowCidrCmd(id, "203.0.113.10/32", 0))
	dnsServer.addIPToFilter("one.example.com", net.ParseIP("203.0.113.10"), 32, 30)
	assert.Zero(t, registryLen(t, server, id), "permanent pin must not gain a deadline from DNS")

	// Order 2: DNS first, CP permanent (as bare IP) second.
	dnsServer.addIPToFilter("two.example.com", net.ParseIP("203.0.113.20"), 32, 30)
	assert.Equal(t, 1, registryLen(t, server, id))
	c.handleCommand(allowCidrCmd(id, "203.0.113.20", 0))
	assert.Zero(t, registryLen(t, server, id), "permanent CP re-add must clear the DNS deadline")

	clk.Advance(1000 * time.Hour)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.ElementsMatch(t, []string{"203.0.113.10/32", "203.0.113.20/32"}, allowed,
		"CP-permanent entries aliased by DNS resolutions must never expire")
}

// TestAliasedDeadlineIsMaxOfSources: when a TTL'd CP rule and a DNS
// resolution alias the same CIDR, the entry lives until the LATEST deadline
// of any source.
func TestAliasedDeadlineIsMaxOfSources(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	// CP rule with 10min TTL, then a DNS resolution floored to 60s: the CP
	// deadline is later and must win.
	c.handleCommand(allowCidrCmd(id, "203.0.113.30/32", 10*time.Minute))
	dnsServer.addIPToFilter("a.example.com", net.ParseIP("203.0.113.30"), 32, 30)

	clk.Advance(2 * time.Minute) // far past the DNS deadline
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"203.0.113.30/32"}, allowed, "DNS TTL lapse must not remove a longer-lived CP rule")

	clk.Advance(8 * time.Minute) // t0+10min
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Empty(t, allowed)

	// Reverse: DNS (floored 60s) first, then a longer CP TTL extends it.
	dnsServer.addIPToFilter("b.example.com", net.ParseIP("203.0.113.31"), 32, 30)
	c.handleCommand(allowCidrCmd(id, "203.0.113.31/32", 2*time.Minute))

	clk.Advance(90 * time.Second) // past the DNS deadline, before the CP one
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"203.0.113.31/32"}, allowed)

	clk.Advance(30 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Empty(t, allowed)
	assert.Zero(t, registryLen(t, server, id))
}

// TestDNSEntriesDrainAfterExpiry: DNS tracking is bounded — there is no
// per-DNS-server cache anymore, and the registry drains fully once TTLs
// lapse instead of accumulating entries forever.
func TestDNSEntriesDrainAfterExpiry(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	for i := 0; i < 100; i++ {
		dnsServer.addIPToFilter("bulk.example.com", net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1)).To4(), 32, 30)
	}
	assert.Equal(t, 100, registryLen(t, server, id))

	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	assert.Zero(t, registryLen(t, server, id))
	server.mu.RLock()
	total := server.attachments[id].ttls.len()
	server.mu.RUnlock()
	assert.Zero(t, total, "registry must drain fully after expiry")
	_, allowed, _, _ := ff.snapshot()
	assert.Empty(t, allowed)
}

// TestMapFullCountedSurfacedAndRecovers: a full rule map increments the
// per-attachment map_full_drops stat (DNS and CP paths alike) instead of
// silently dropping, records nothing bogus in the registry, and recovers as
// soon as capacity frees up.
func TestMapFullCountedSurfacedAndRecovers(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	mapFull := fmt.Errorf("updating allowed_ipv4: %w", syscall.ENOSPC)
	ff.setAllowErr(mapFull)

	dnsServer.addIPToFilter("a.example.com", net.ParseIP("203.0.113.40"), 32, 30)
	dnsServer.addIPToFilter("b.example.com", net.ParseIP("203.0.113.41"), 32, 30)
	assert.Zero(t, registryLen(t, server, id), "dropped adds must not be tracked")

	err := server.AllowCIDR(id, mustCIDR(t, "198.51.100.1/32"), 0)
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOSPC)

	var stat *apiv1.AttachmentStats
	for _, s := range server.GetAttachmentStats() {
		if s.Id == id {
			stat = s
		}
	}
	require.NotNil(t, stat)
	assert.Equal(t, uint64(3), stat.MapFullDrops, "every dropped add (DNS and CP) must be counted")

	// Capacity frees up (janitor expired something): adds work again and the
	// counter stops growing.
	ff.setAllowErr(nil)
	dnsServer.addIPToFilter("a.example.com", net.ParseIP("203.0.113.40"), 32, 30)
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{"203.0.113.40/32"}, allowed)
	assert.Equal(t, 1, registryLen(t, server, id))
	server.mu.RLock()
	drops := server.attachments[id].ttls.mapFullCount()
	server.mu.RUnlock()
	assert.Equal(t, uint64(3), drops)
}

// ---------------------------------------------------------------------------
// Phase 2C: BulkUpdate reconciliation without transient windows.
// ---------------------------------------------------------------------------

// TestBulkUpdateNoWindowForSurvivingRules is the unit-level no-window proof:
// across two consecutive bulk updates, a CIDR present in both the old and
// new declared sets is NEVER passed to the filter's Remove — only genuinely
// stale rules are removed, new ones added, and the mode changes in place
// with zero ClearRules calls.
func TestBulkUpdateNoWindowForSurvivingRules(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	// Initial state via individual commands.
	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", 0))
	c.handleCommand(denyCidrCmd(id, "192.0.2.0/24", 0))

	// Bulk 1: keeps both, adds a TTL'd allow, switches mode.
	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: "10.0.0.0/8"},
			{Cidr: "198.51.100.0/24", Ttl: durationpb.New(5 * time.Second)},
		},
		DenyCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
	})

	mode, allowed, denied, clearCalls := ff.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)
	assert.Zero(t, clearCalls)
	assert.ElementsMatch(t, []string{"10.0.0.0/8", "198.51.100.0/24"}, allowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, denied)
	removedAllowed, removedDenied := ff.removeCalls()
	assert.Empty(t, removedAllowed, "no allow rule may be removed when all survive")
	assert.Empty(t, removedDenied, "no deny rule may be removed when all survive")

	// Bulk 2: drops the TTL'd allow and the deny, keeps 10.0.0.0/8.
	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "10.0.0.0/8"}},
	})

	_, allowed, denied, clearCalls = ff.snapshot()
	assert.Zero(t, clearCalls)
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Empty(t, denied)
	removedAllowed, removedDenied = ff.removeCalls()
	assert.Equal(t, []string{"198.51.100.0/24"}, removedAllowed, "only the dropped allow may be removed")
	assert.Equal(t, []string{"192.0.2.0/24"}, removedDenied)
	assert.NotContains(t, removedAllowed, "10.0.0.0/8", "surviving rule must never see a Remove")

	// The survivor is permanent: no janitor sweep may ever take it.
	clk := newFakeClock()
	server.now = clk.Now
	clk.Advance(1000 * time.Hour)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
}

// TestBulkUpdatePreservesDNSPopulatedIPs: a DNS-populated /32 absent from
// the bulk's declared CP set is NOT removed by the resync — it stays in the
// filter and only ages out later when its own DNS TTL lapses.
func TestBulkUpdatePreservesDNSPopulatedIPs(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	dnsServer.addIPToFilter("cached.example.com", net.ParseIP("203.0.113.5"), 32, 30) // floored to 60s

	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}},
	})

	_, allowed, _, _ := ff.snapshot()
	assert.ElementsMatch(t, []string{"203.0.113.5/32", "198.51.100.0/24"}, allowed,
		"DNS-populated IP must survive the bulk update")
	removedAllowed, _ := ff.removeCalls()
	assert.Empty(t, removedAllowed)

	// It ages out by its own DNS TTL, not the resync.
	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"198.51.100.0/24"}, allowed)
}

// TestBulkUpdateClearsCPSourceButDNSKeepsEntry: when a CIDR held by BOTH a
// TTL'd CP rule and a DNS resolution is dropped from the bulk's declared
// set, only the CP source is cleared — the DNS source keeps the entry in
// the filter, and it then expires at the DNS deadline, NOT the (longer) CP
// deadline the bulk revoked.
func TestBulkUpdateClearsCPSourceButDNSKeepsEntry(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "203.0.113.6/32", 10*time.Minute))
	dnsServer.addIPToFilter("both.example.com", net.ParseIP("203.0.113.6"), 32, 30) // DNS deadline: 60s floor

	// Bulk drops the CP rule for it.
	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}},
	})

	_, allowed, _, _ := ff.snapshot()
	assert.Contains(t, allowed, "203.0.113.6/32", "live DNS source must keep the entry through the bulk")
	removedAllowed, _ := ff.removeCalls()
	assert.Empty(t, removedAllowed)

	// The revoked CP deadline (10min) must NOT keep it alive: it expires at
	// the DNS deadline (60s).
	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"198.51.100.0/24"}, allowed,
		"entry must expire at the DNS deadline once the bulk cleared the CP source")
	// Only the bulk's permanent entry remains, and it is pinned: nothing
	// is pending expiry.
	assert.Zero(t, registryLen(t, server, id))
}

// TestBulkUpdateConcurrentWithDNSAdds hammers bulk reconciles against
// concurrent DNS sink adds and janitor sweeps so the race detector can vet
// the reconcile locking, and asserts the invariant that a CIDR declared in
// every bulk is present at the end.
func TestBulkUpdateConcurrentWithDNSAdds(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			dnsServer.addIPToFilter("churn.example.com", net.ParseIP("203.0.113.7"), 32, 30)
			clk.Advance(30 * time.Second)
			server.sweepExpiredTTLs(clk.Now())
		}
	}()

	for i := 0; i < 100; i++ {
		c.applyBulkUpdate(id, &apiv1.BulkUpdate{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{
				{Cidr: "10.0.0.0/8"},
				{Cidr: "198.51.100.0/24", Ttl: durationpb.New(time.Hour)},
			},
		})
	}
	<-done

	// The permanent survivor must be present and must never have been
	// removed by any interleaving.
	_, allowed, _, _ := ff.snapshot()
	assert.Contains(t, allowed, "10.0.0.0/8")
	removedAllowed, _ := ff.removeCalls()
	assert.NotContains(t, removedAllowed, "10.0.0.0/8")
}

// indexOfEvent returns the index of the first occurrence of event in events,
// failing the test if absent.
func indexOfEvent(t *testing.T, events []string, event string) int {
	t.Helper()
	for i, ev := range events {
		if ev == event {
			return i
		}
	}
	t.Fatalf("event %q not found in %v", event, events)
	return -1
}

// TestBulkUpdateModeFlipOrdering proves the window-free ORDERING of a bulk
// apply via the fakeFilter's sequenced call log: the list the NEW mode
// consults is fully reconciled (adds AND removes) BEFORE the SetMode lands,
// and the other list only after. Without that order an allowlist->denylist
// flip consults a still-stale deny map and fails OPEN until the deny rules
// land (and denylist->allowlist fails open via stale inert allow entries).
func TestBulkUpdateModeFlipOrdering(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	// Establish allowlist state; the deny rule is inert under allowlist.
	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "10.0.0.0/8"}, {Cidr: "172.16.0.0/12"}},
		DenyCidrs:  []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
	})

	t.Run("allowlist_to_denylist", func(t *testing.T) {
		before := len(ff.eventLog())
		c.applyBulkUpdate(id, &apiv1.BulkUpdate{
			Mode:       apiv1.PolicyMode_POLICY_MODE_DENYLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "10.0.0.0/8"}},      // drops 172.16.0.0/12
			DenyCidrs:  []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}}, // adds this, drops 192.0.2.0/24
		})
		events := ff.eventLog()[before:]
		modeIdx := indexOfEvent(t, events, "set-mode "+filter.ModeDenylist.String())
		for i, ev := range events {
			switch {
			case strings.HasPrefix(ev, "deny ") || strings.HasPrefix(ev, "remove-deny "):
				assert.Less(t, i, modeIdx, "deny-list op %q must precede the flip to denylist (log: %v)", ev, events)
			case strings.HasPrefix(ev, "allow ") || strings.HasPrefix(ev, "remove-allow "):
				assert.Greater(t, i, modeIdx, "allow-list op %q must follow the flip to denylist (log: %v)", ev, events)
			}
		}
		// The deny map was corrected in full, and the surviving allow rule
		// was never removed.
		assert.Contains(t, events, "deny 198.51.100.0/24")
		assert.Contains(t, events, "remove-deny 192.0.2.0/24")
		assert.Contains(t, events, "remove-allow 172.16.0.0/12")
		assert.NotContains(t, events, "remove-allow 10.0.0.0/8")
	})

	t.Run("denylist_to_allowlist", func(t *testing.T) {
		before := len(ff.eventLog())
		c.applyBulkUpdate(id, &apiv1.BulkUpdate{
			Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "10.0.0.0/8"}, {Cidr: "203.0.113.0/24"}},
			// deny set emptied: drops 198.51.100.0/24
		})
		events := ff.eventLog()[before:]
		modeIdx := indexOfEvent(t, events, "set-mode "+filter.ModeAllowlist.String())
		for i, ev := range events {
			switch {
			case strings.HasPrefix(ev, "allow ") || strings.HasPrefix(ev, "remove-allow "):
				assert.Less(t, i, modeIdx, "allow-list op %q must precede the flip to allowlist (log: %v)", ev, events)
			case strings.HasPrefix(ev, "deny ") || strings.HasPrefix(ev, "remove-deny "):
				assert.Greater(t, i, modeIdx, "deny-list op %q must follow the flip to allowlist (log: %v)", ev, events)
			}
		}
		assert.Contains(t, events, "allow 203.0.113.0/24")
		assert.Contains(t, events, "remove-deny 198.51.100.0/24")
		assert.NotContains(t, events, "remove-allow 10.0.0.0/8")
	})

	t.Run("same_mode_resync", func(t *testing.T) {
		before := len(ff.eventLog())
		c.applyBulkUpdate(id, &apiv1.BulkUpdate{
			Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "10.0.0.0/8"}, {Cidr: "198.51.100.0/24"}}, // drops 203.0.113.0/24
		})
		events := ff.eventLog()[before:]
		modeIdx := indexOfEvent(t, events, "set-mode "+filter.ModeAllowlist.String())
		for i, ev := range events {
			if strings.HasPrefix(ev, "allow ") || strings.HasPrefix(ev, "remove-allow ") {
				assert.Less(t, i, modeIdx, "live-list op %q must precede the (no-op) mode write (log: %v)", ev, events)
			}
		}
		// Survivor never removed; the live list is reconciled with survivor
		// dedup so there is no window on the same-mode path either.
		assert.Contains(t, events, "allow 198.51.100.0/24")
		assert.Contains(t, events, "remove-allow 203.0.113.0/24")
		assert.NotContains(t, events, "remove-allow 10.0.0.0/8")
		assert.NotContains(t, events, "clear")
	})
}
