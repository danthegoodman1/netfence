package daemon

import (
	"errors"
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

func assertProtectedCurrent(t testing.TB, reg *ttlRegistry, allow4, allow6, deny4, deny6 uint32) {
	t.Helper()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	assert.Equal(t, protectedRuleCurrent{allow4: allow4, allow6: allow6, deny4: deny4, deny6: deny6}, reg.protectedCurrent)
}

func TestProtectedCurrentCountersTrackPhysicalTransitionsAndFailures(t *testing.T) {
	ff := &fakeFilter{}
	reg := newTTLRegistry()
	now := time.Now()
	allow4 := mustCIDR(t, "192.0.2.1/32")
	allow6 := mustCIDR(t, "2001:db8:1::1/128")
	deny4 := mustCIDR(t, "198.51.100.1/32")
	deny6 := mustCIDR(t, "2001:db8:2::1/128")

	require.NoError(t, reg.addSystem(ff, allow4, listAllow))
	require.NoError(t, reg.addCP(ff, allow4, listAllow, 0, now))
	assertProtectedCurrent(t, reg, 1, 0, 0, 0)
	require.NoError(t, reg.removeSystem(ff, allow4, listAllow))
	assertProtectedCurrent(t, reg, 1, 0, 0, 0)

	require.NoError(t, reg.addCP(ff, allow6, listAllow, 0, now))
	require.NoError(t, reg.addCP(ff, deny4, listDeny, 0, now))
	require.NoError(t, reg.addCP(ff, deny6, listDeny, 0, now))
	assertProtectedCurrent(t, reg, 1, 1, 1, 1)

	ff.setAllowErr(errors.New("injected add failure"))
	require.Error(t, reg.addCP(ff, mustCIDR(t, "192.0.2.2/32"), listAllow, 0, now))
	ff.setAllowErr(nil)
	assertProtectedCurrent(t, reg, 1, 1, 1, 1)

	ff.removeDenyErr = errors.New("injected remove failure")
	require.Error(t, reg.reconcileCP(ff, listDeny, []parsedCIDR{{cidr: deny6}}, now))
	assertProtectedCurrent(t, reg, 1, 1, 1, 1)
	ff.removeDenyErr = nil
	require.NoError(t, reg.reconcileCP(ff, listDeny, []parsedCIDR{{cidr: deny6}}, now))
	assertProtectedCurrent(t, reg, 1, 1, 0, 1)

	ff.removeAllowErr = errors.New("injected clear failure")
	require.Error(t, reg.clear(ff))
	assertProtectedCurrent(t, reg, 1, 1, 0, 0)
	ff.removeAllowErr = nil
	require.NoError(t, reg.clear(ff))
	assertProtectedCurrent(t, reg, 0, 0, 0, 0)
	assert.Equal(t, uint32(1), reg.allowedIPv4HighWater.Load())
	assert.Equal(t, uint32(1), reg.allowedIPv6HighWater.Load())
	assert.Equal(t, uint32(1), reg.deniedIPv4HighWater.Load())
	assert.Equal(t, uint32(1), reg.deniedIPv6HighWater.Load())

	expiring := mustCIDR(t, "203.0.113.9/32")
	require.NoError(t, reg.addCP(ff, expiring, listAllow, time.Second, now))
	assertProtectedCurrent(t, reg, 1, 0, 0, 0)
	ff.removeAllowErr = errors.New("injected expiry failure")
	swept := reg.expire(ff, now.Add(time.Second))
	require.Len(t, swept, 1)
	require.Error(t, swept[0].err)
	assertProtectedCurrent(t, reg, 1, 0, 0, 0)
	ff.removeAllowErr = nil
	swept = reg.expire(ff, now.Add(2*time.Second))
	require.Len(t, swept, 1)
	require.NoError(t, swept[0].err)
	assertProtectedCurrent(t, reg, 0, 0, 0, 0)

	ff.protectedReplaceErr = errors.New("injected authoritative failure")
	require.Error(t, reg.reconcileAuthoritative(ff, filter.ModeDenylist,
		[]parsedCIDR{{cidr: allow4}, {cidr: allow6}}, []parsedCIDR{{cidr: deny4}, {cidr: deny6}}, now))
	assertProtectedCurrent(t, reg, 0, 0, 0, 0)
	ff.protectedReplaceErr = nil
	require.NoError(t, reg.reconcileAuthoritative(ff, filter.ModeDenylist,
		[]parsedCIDR{{cidr: allow4}, {cidr: allow6}}, []parsedCIDR{{cidr: deny4}, {cidr: deny6}}, now))
	assertProtectedCurrent(t, reg, 1, 1, 1, 1)
}

func protectedCapacitySeedCIDRs(t testing.TB, perMap int) (allowed, denied []*net.IPNet) {
	t.Helper()
	parse := func(raw string) *net.IPNet {
		_, cidr, err := net.ParseCIDR(raw)
		require.NoError(t, err)
		return cidr
	}
	allowed = make([]*net.IPNet, 0, perMap*2)
	denied = make([]*net.IPNet, 0, perMap*2)
	for i := 0; i < perMap; i++ {
		allowed = append(allowed,
			parse(fmt.Sprintf("10.%d.%d.%d/32", (i>>16)&255, (i>>8)&255, i&255)),
			parse(fmt.Sprintf("2001:db8:1::%x/128", i+1)),
		)
		denied = append(denied,
			parse(fmt.Sprintf("11.%d.%d.%d/32", (i>>16)&255, (i>>8)&255, i&255)),
			parse(fmt.Sprintf("2001:db8:2::%x/128", i+1)),
		)
	}
	return allowed, denied
}

func TestSeedAdoptedMaxCapacityIsAtomicAndTracksHighWaterWithoutMapWrites(t *testing.T) {
	const perMap = 4096
	allowed, denied := protectedCapacitySeedCIDRs(t, perMap)
	reg := newTTLRegistry()
	require.NoError(t, reg.seedAdopted(allowed, denied))
	assert.Equal(t, perMap*4, reg.len())
	assertProtectedCurrent(t, reg, perMap, perMap, perMap, perMap)
	assert.Equal(t, uint32(perMap), reg.allowedIPv4HighWater.Load())
	assert.Equal(t, uint32(perMap), reg.allowedIPv6HighWater.Load())
	assert.Equal(t, uint32(perMap), reg.deniedIPv4HighWater.Load())
	assert.Equal(t, uint32(perMap), reg.deniedIPv6HighWater.Load())

	beforeCurrent := reg.protectedCurrent
	beforeLen := reg.len()
	require.Error(t, reg.seedAdopted([]*net.IPNet{mustCIDR(t, "192.0.2.1/32"), nil}, nil))
	assert.Equal(t, beforeLen, reg.len(), "invalid inventory must not partially replace registry entries")
	assert.Equal(t, beforeCurrent, reg.protectedCurrent, "invalid inventory must not partially replace counters")
}

func TestSystemOwnedDNSBootstrapSurvivesAuthoritativeStateTTLRemoveAndClear(t *testing.T) {
	ff := &fakeFilter{}
	reg := newTTLRegistry()
	clock := newFakeClock()
	bootstrap := mustCIDR(t, testDNSBootstrapCIDR)

	require.NoError(t, reg.addSystem(ff, bootstrap, listAllow))
	require.NoError(t, reg.addCP(ff, bootstrap, listAllow, time.Second, clock.Now()))
	require.NoError(t, reg.reconcileCP(ff, listAllow, nil, clock.Now()))

	clock.Advance(time.Hour)
	assert.Empty(t, reg.expire(ff, clock.Now()))
	require.NoError(t, reg.remove(ff, bootstrap, listAllow))
	_, allowed, _, _ := ff.snapshot()
	assert.Equal(t, []string{testDNSBootstrapCIDR}, allowed)
	removed, _ := ff.removeCalls()
	assert.Empty(t, removed, "control-plane removal must not issue a kernel remove for the system route")

	ordinary := mustCIDR(t, "192.0.2.55/32")
	require.NoError(t, reg.addCP(ff, ordinary, listAllow, 0, clock.Now()))
	ff.setRemoveAllowedErr(syscall.EIO)
	require.Error(t, reg.clear(ff))
	_, allowed, _, clearCalls := ff.snapshot()
	assert.ElementsMatch(t, []string{testDNSBootstrapCIDR, ordinary.String()}, allowed)
	assert.Zero(t, clearCalls, "protected clear must never call the physical all-map clear")
	assert.Equal(t, 2, reg.len(), "failed ordinary removal and protected bootstrap remain retry-accurate")

	ff.setRemoveAllowedErr(nil)
	require.NoError(t, reg.clear(ff))
	_, allowed, _, clearCalls = ff.snapshot()
	assert.Equal(t, []string{testDNSBootstrapCIDR}, allowed)
	assert.Zero(t, clearCalls)
	assert.Zero(t, reg.pendingLen(), "system ownership is permanent and not janitor work")
	for _, event := range ff.eventLog() {
		assert.NotEqual(t, "clear", event)
		assert.NotEqual(t, "remove-allow "+testDNSBootstrapCIDR, event)
	}
}

// registryLen reports the attachment's pending-expiry count: entries with a
// finite deadline the LPM janitor will eventually remove. Permanent CP and
// daemon-system entries are tracked for authoritative diff reconciliation but
// never expire, so they are excluded here. DNS exact ownership is separate.
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

// A full desired state replaces CP lifetimes exactly. Incremental adds remain
// monotonic, but a BulkUpdate/SubscribedAck must be able to correct a long
// deadline to a short one without removing/re-adding the surviving map entry.
func TestBulkUpdateShortensSurvivingCPDeadlineWithoutRemove(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

	c.handleCommand(allowCidrCmd(id, "10.0.0.0/8", time.Hour))
	require.NoError(t, c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{
			Cidr: "10.0.0.0/8",
			Ttl:  durationpb.New(2 * time.Second),
		}},
	}))
	removed, _ := ff.removeCalls()
	assert.Empty(t, removed, "survivor lifetime correction must be bookkeeping-only")

	clk.Advance(2 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.Empty(t, allowed, "the authoritative shorter deadline must replace the incremental longer deadline")
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
// DNS exact-tier expiry, CP overlap, TTL floor, and capacity handling.
// ---------------------------------------------------------------------------

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	cidr, err := filter.ParseCIDR(s)
	require.NoError(t, err)
	return cidr
}

// TestDNSAddedIPExpiresViaJanitor: a DNS-resolved IP whose record TTL is
// below the floor lives for the floor (default 60s), then the janitor
// removes it from the exact filter tier and ownership manager.
func TestDNSAddedIPExpiresViaJanitor(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	dnsServer.addIPToFilter("example.com", net.ParseIP("203.0.113.10"), 32, 30)
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.10"}, dnsAllowed)
	assert.Zero(t, registryLen(t, server, id), "DNS exact ownership is not stored in the authoritative LPM TTL registry")

	// At the record TTL (30s) the 60s floor keeps it alive.
	clk.Advance(30 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.10"}, dnsAllowed, "floor must outlive the record TTL")

	// At the floor it expires.
	clk.Advance(30 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
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
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.11"}, dnsAllowed, "record TTL above the floor must govern")

	clk.Advance(240 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
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
	_, dnsAddCalls := ff.dnsSnapshot()
	assert.Equal(t, 1, dnsAddCalls, "re-resolution of a tracked IP must not hit the exact map")

	clk.Advance(30 * time.Second) // t0+60: past the original deadline
	server.sweepExpiredTTLs(clk.Now())
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.12"}, dnsAllowed, "refreshed deadline must survive the original one")

	clk.Advance(30 * time.Second) // t0+90
	server.sweepExpiredTTLs(clk.Now())
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
	assert.Zero(t, registryLen(t, server, id))
}

// TestPermanentCPAllowPinsAliasedDNSIP proves independent-tier overlap: a
// permanent control-plane LPM allow for the same host a DNS resolution
// admitted exactly must survive exact ownership expiry in either arrival
// order.
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
	assert.Zero(t, registryLen(t, server, id), "DNS ownership has an independent bounded exact registry")
	c.handleCommand(allowCidrCmd(id, "203.0.113.20", 0))
	assert.Zero(t, registryLen(t, server, id), "the permanent CP LPM owner has no pending LPM deadline")

	clk.Advance(1000 * time.Hour)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ := ff.snapshot()
	assert.ElementsMatch(t, []string{"203.0.113.10/32", "203.0.113.20/32"}, allowed,
		"CP-permanent entries aliased by DNS resolutions must never expire")
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed, "expired DNS exact aliases are removed independently of protected CP LPM allows")
}

// TestAliasedDeadlineIsMaxOfSources proves each tier honors its own deadline:
// connectivity survives while either the CP LPM or DNS exact owner remains.
func TestIndependentCPAndDNSDeadlinesPreserveCoverage(t *testing.T) {
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
// per-DNS-server cache anymore, and the ownership graph drains fully once
// TTLs lapse instead of accumulating entries forever.
func TestDNSEntriesDrainAfterExpiry(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	for i := 0; i < 100; i++ {
		dnsServer.addIPToFilter("bulk.example.com", net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1)).To4(), 32, 30)
	}
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Len(t, dnsAllowed, 100)
	assert.Zero(t, registryLen(t, server, id))

	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	assert.Zero(t, registryLen(t, server, id))
	server.mu.RLock()
	total := server.attachments[id].ttls.len()
	server.mu.RUnlock()
	assert.Zero(t, total, "registry must drain fully after expiry")
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
}

// TestMapFullCountedSurfacedAndRecovers: authoritative LPM pressure remains
// independently counted; DNS exact admission does not consume that map.
func TestMapFullCountedSurfacedAndRecovers(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now

	mapFull := fmt.Errorf("updating allowed_ipv4: %w", syscall.ENOSPC)
	ff.setAllowErr(mapFull)

	dnsServer.addIPToFilter("a.example.com", net.ParseIP("203.0.113.40"), 32, 30)
	dnsServer.addIPToFilter("b.example.com", net.ParseIP("203.0.113.41"), 32, 30)
	assert.Zero(t, registryLen(t, server, id))
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.ElementsMatch(t, []string{"203.0.113.40", "203.0.113.41"}, dnsAllowed,
		"DNS exact admission must remain independent of an LPM allow-map failure")

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
	assert.Equal(t, uint64(1), stat.MapFullDrops, "the failed authoritative LPM add is counted independently")

	// Capacity frees up (janitor expired something): adds work again and the
	// counter stops growing.
	ff.setAllowErr(nil)
	dnsServer.addIPToFilter("a.example.com", net.ParseIP("203.0.113.40"), 32, 30)
	_, allowed, _, _ := ff.snapshot()
	assert.Empty(t, allowed)
	assert.Zero(t, registryLen(t, server, id))
	server.mu.RLock()
	drops := server.attachments[id].ttls.mapFullCount()
	server.mu.RUnlock()
	assert.Equal(t, uint64(1), drops)
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

// TestBulkUpdatePreservesDNSPopulatedIPs: a DNS-populated exact host absent from
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
		Dns: &apiv1.DnsConfig{
			Mode:         apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains: []*apiv1.DomainEntry{{Domain: "cached.example.com"}},
		},
	})

	_, allowed, _, _ := ff.snapshot()
	assert.ElementsMatch(t, []string{"198.51.100.0/24"}, allowed)
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.5"}, dnsAllowed,
		"an exact key whose query remains authorized must survive the bulk update")
	removedAllowed, _ := ff.removeCalls()
	assert.Empty(t, removedAllowed)

	// It ages out by its own DNS TTL, not the resync.
	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"198.51.100.0/24"}, allowed)
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
}

// TestBulkUpdateClearsCPSourceButDNSKeepsEntry proves a BulkUpdate can revoke
// an overlapping CP LPM rule while its still-authorized DNS exact owner stays
// live until the independent DNS deadline.
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
		Dns: &apiv1.DnsConfig{
			Mode:         apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains: []*apiv1.DomainEntry{{Domain: "both.example.com"}},
		},
	})

	_, allowed, _, _ := ff.snapshot()
	assert.NotContains(t, allowed, "203.0.113.6/32", "the revoked CP LPM owner is removed")
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Contains(t, dnsAllowed, "203.0.113.6", "the independent DNS exact owner keeps connectivity")
	removedAllowed, _ := ff.removeCalls()
	assert.Contains(t, removedAllowed, "203.0.113.6/32", "the revoked CP source is removed only from the LPM tier")

	// The revoked CP deadline (10min) must NOT keep it alive: it expires at
	// the DNS deadline (60s).
	clk.Advance(60 * time.Second)
	server.sweepExpiredTTLs(clk.Now())
	_, allowed, _, _ = ff.snapshot()
	assert.Equal(t, []string{"198.51.100.0/24"}, allowed,
		"entry must expire at the DNS deadline once the bulk cleared the CP source")
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
	// Only the bulk's permanent entry remains, and it is pinned: nothing
	// is pending expiry.
	assert.Zero(t, registryLen(t, server, id))
}

// TestBulkUpdateConcurrentWithDNSAdds hammers independent LPM reconciliation
// and exact ownership admission/expiry under the attachment mutation barrier,
// and asserts the permanent CP survivor remains installed.
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
		assert.NotContains(t, events, "set-mode "+filter.ModeAllowlist.String(), "same-mode reconcile does not rewrite the mode map")
		// Survivor never removed; the live list is reconciled with survivor
		// dedup so there is no window on the same-mode path either.
		assert.Contains(t, events, "allow 198.51.100.0/24")
		assert.Contains(t, events, "remove-allow 203.0.113.0/24")
		assert.NotContains(t, events, "remove-allow 10.0.0.0/8")
		assert.NotContains(t, events, "clear")
	})
}
