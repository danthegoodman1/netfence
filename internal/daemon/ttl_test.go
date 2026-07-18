package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

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

func registryLen(t *testing.T, server *Server, id string) int {
	t.Helper()
	server.mu.RLock()
	defer server.mu.RUnlock()
	state, ok := server.attachments[id]
	require.True(t, ok)
	return state.ttls.len()
}

// TestTTLCIDRExpiresAfterSweep covers the AllowCidr/DenyCidr command entry
// points: TTL'd entries are removed from the filter once the janitor sweeps
// past their deadline, and only then.
func TestTTLCIDRExpiresAfterSweep(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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

// TestBulkUpdatePurgesAndTracksTTLs: a bulk update's ClearRules purges stale
// deadlines (rules rebuilt as permanent stay), and TTL'd entries in the bulk
// payload are tracked and expire.
func TestBulkUpdatePurgesAndTracksTTLs(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clk := newFakeClock()
	server.now = clk.Now
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

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
