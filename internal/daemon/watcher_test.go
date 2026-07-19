//go:build linux

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// fakeLinkSubscriber stands in for netlink.LinkSubscribeWithOptions. It
// mirrors the real netlink contract the watcher relies on: the updates
// channel is closed when the subscription dies — either spontaneously
// (simulated via fakeSubscription.fail) or because the caller closed the done
// channel (netlink closes its socket, its receive goroutine errors and
// defer-closes the channel).
type fakeLinkSubscriber struct {
	calls atomic.Int64
	subs  chan *fakeSubscription
	// failOnSubscribe, when true, closes every new subscription's channel
	// immediately, simulating a subscription that dies instantly every time.
	failOnSubscribe atomic.Bool
}

type fakeSubscription struct {
	ch        chan<- netlink.LinkUpdate
	closeOnce sync.Once
}

// fail simulates netlink's receive goroutine dying (e.g. ENOBUFS): the
// updates channel is closed.
func (s *fakeSubscription) fail() {
	s.closeOnce.Do(func() { close(s.ch) })
}

func newFakeLinkSubscriber() *fakeLinkSubscriber {
	return &fakeLinkSubscriber{subs: make(chan *fakeSubscription, 32)}
}

func (f *fakeLinkSubscriber) subscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
	f.calls.Add(1)
	sub := &fakeSubscription{ch: ch}
	go func() {
		<-done
		sub.fail()
	}()
	if f.failOnSubscribe.Load() {
		sub.fail()
	}
	f.subs <- sub
	return nil
}

func (f *fakeLinkSubscriber) waitForSubscription(t *testing.T) *fakeSubscription {
	t.Helper()
	select {
	case sub := <-f.subs:
		return sub
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a netlink subscription")
		return nil
	}
}

func fakeIfindex(name string) int {
	index := 1
	for i := range name {
		index = index*31 + int(name[i])
	}
	if index < 0 {
		index = -index
	}
	return index + 1
}

func newTestTargetWatcher(onRemoved func(watchToken)) *TargetWatcher {
	w := NewTargetWatcher(zerolog.Nop(), onRemoved)
	w.interfaceIdentity = func(name string) (uint64, error) { return uint64(fakeIfindex(name)), nil }
	return w
}

func linkDel(name string) netlink.LinkUpdate {
	return linkDelIndex(name, fakeIfindex(name))
}

func linkDelIndex(name string, ifindex int) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_DELLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: ifindex}},
	}
}

func dummyLinks(names ...string) []netlink.Link {
	links := make([]netlink.Link, 0, len(names))
	for _, name := range names {
		links = append(links, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: fakeIfindex(name)}})
	}
	return links
}

func dummyLink(name string, ifindex int) []netlink.Link {
	return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: ifindex}}}
}

func watchTestCgroup(t *testing.T, w *TargetWatcher, path string) watchToken {
	t.Helper()
	identity, err := w.cgroupIdentity(path)
	require.NoError(t, err)
	token, err := w.WatchCgroup(path, identity)
	require.NoError(t, err)
	return token
}

func expectRemoved(t *testing.T, removed <-chan string, want string) {
	t.Helper()
	select {
	case got := <-removed:
		require.Equal(t, want, got)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for onRemoved(%q)", want)
	}
}

// TestWatcherNetlinkResubscribeAfterClose: when netlink closes the updates
// channel, the watcher must resubscribe and removal detection must still work
// on the new subscription.
func TestWatcherNetlinkResubscribeAfterClose(t *testing.T) {
	removed := make(chan string, 16)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token.target })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return dummyLinks("veth0"), nil }

	_, err := w.WatchInterface("veth0", uint64(fakeIfindex("veth0")))
	require.NoError(t, err)
	require.NoError(t, w.Start())
	defer w.Stop()

	sub1 := fake.waitForSubscription(t)

	// Simulate the netlink receive goroutine dying: it closes the channel.
	sub1.fail()

	// The loop must resubscribe rather than spin on the closed channel.
	sub2 := fake.waitForSubscription(t)

	// A removal delivered on the new subscription must still be detected.
	sub2.ch <- linkDel("veth0")
	expectRemoved(t, removed, "veth0")
}

// TestWatcherResubscribeBackoffBounded: a subscription that dies instantly
// every time must be retried with bounded backoff, not a hot loop.
func TestWatcherResubscribeBackoffBounded(t *testing.T) {
	w := newTestTargetWatcher(func(watchToken) {})

	fake := newFakeLinkSubscriber()
	fake.failOnSubscribe.Store(true)
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	require.NoError(t, w.Start())
	defer w.Stop()

	// Drain subscriptions so the fake never blocks.
	stopDrain := make(chan struct{})
	defer close(stopDrain)
	go func() {
		for {
			select {
			case <-fake.subs:
			case <-stopDrain:
				return
			}
		}
	}()

	// With min backoff 100ms doubling per attempt, ~700ms allows at most
	// subscribes at t=0, 100, 300, 700 (4 total). A hot loop would produce
	// thousands; no resubscription at all produces exactly 1.
	time.Sleep(700 * time.Millisecond)
	calls := fake.calls.Load()
	require.GreaterOrEqual(t, calls, int64(2), "watcher never resubscribed after the updates channel closed")
	require.LessOrEqual(t, calls, int64(6), "watcher is hot-looping on resubscription (%d subscribes in 700ms)", calls)
}

// TestWatcherReconcileCatchesRemovalDuringResubscribeGap: an interface that
// vanishes while the subscription is down produces no netlink event; the
// post-resubscribe reconcile must still fire onRemoved for it.
func TestWatcherReconcileCatchesRemovalDuringResubscribeGap(t *testing.T) {
	removed := make(chan string, 16)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token.target })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe

	var links atomic.Value
	links.Store(dummyLinks("veth-gap"))
	reconciled := make(chan struct{}, 16)
	w.listLinks = func() ([]netlink.Link, error) {
		defer func() { reconciled <- struct{}{} }()
		return links.Load().([]netlink.Link), nil
	}

	_, err := w.WatchInterface("veth-gap", uint64(fakeIfindex("veth-gap")))
	require.NoError(t, err)
	require.NoError(t, w.Start())
	defer w.Stop()

	sub1 := fake.waitForSubscription(t)

	// Let the initial reconcile finish while the interface still exists so
	// it cannot be the source of the removal below.
	select {
	case <-reconciled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for initial reconcile")
	}
	select {
	case got := <-removed:
		t.Fatalf("unexpected removal %q while interface still exists", got)
	default:
	}

	// The interface disappears during the gap: no event will ever arrive on
	// the next subscription's channel.
	links.Store(dummyLinks())
	sub1.fail()

	// Only the post-resubscribe reconcile can detect it.
	expectRemoved(t, removed, "veth-gap")
}

// TestWatcherReconcileTreatsSameNameNewIfindexAsRemoval verifies that a link
// deleted and recreated under the same name while netlink is down does not
// fool the post-resubscribe reconciliation. The old identity is removed, and
// a delayed DELLINK for it cannot remove a newly registered generation.
func TestWatcherReconcileTreatsSameNameNewIfindexAsRemoval(t *testing.T) {
	removed := make(chan watchToken, 16)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe

	const (
		name       = "veth-reborn"
		oldIfindex = 101
		newIfindex = 202
	)
	var currentIfindex atomic.Int64
	currentIfindex.Store(oldIfindex)
	w.interfaceIdentity = func(string) (uint64, error) { return uint64(currentIfindex.Load()), nil }

	var links atomic.Value
	links.Store(dummyLink(name, oldIfindex))
	reconciled := make(chan struct{}, 16)
	w.listLinks = func() ([]netlink.Link, error) {
		defer func() { reconciled <- struct{}{} }()
		return links.Load().([]netlink.Link), nil
	}

	oldToken, err := w.WatchInterface(name, oldIfindex)
	require.NoError(t, err)
	require.NoError(t, w.Start())
	defer w.Stop()

	sub1 := fake.waitForSubscription(t)
	select {
	case <-reconciled:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for initial reconcile")
	}

	// The old link disappears and a distinct link takes its name while no
	// subscription is alive. Name-only reconciliation would miss this.
	currentIfindex.Store(newIfindex)
	links.Store(dummyLink(name, newIfindex))
	sub1.fail()
	sub2 := fake.waitForSubscription(t)

	select {
	case got := <-removed:
		require.Equal(t, oldToken, got)
	case <-time.After(3 * time.Second):
		t.Fatal("same-name interface replacement did not remove the old identity")
	}

	newToken, err := w.WatchInterface(name, newIfindex)
	require.NoError(t, err)
	require.NotEqual(t, oldToken, newToken)
	// A late explicit unwatch from the prior owner is generation-scoped too.
	w.UnwatchInterface(oldToken)

	// A delayed kernel event for the old ifindex must not delete the current
	// generation that owns the same name.
	sub2.ch <- linkDelIndex(name, oldIfindex)
	select {
	case got := <-removed:
		t.Fatalf("stale DELLINK dispatched current generation: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}

	w.mu.RLock()
	current, ok := w.interfaces[name]
	w.mu.RUnlock()
	require.True(t, ok)
	require.Equal(t, newToken, current.token)
	require.Equal(t, uint64(newIfindex), current.ifindex)
}

// TestWatcherOnRemovedOffEventLoopAndDeduped: a slow onRemoved must not block
// the event loop or a second distinct removal, and a repeated event for the
// same target must not dispatch it twice.
func TestWatcherOnRemovedOffEventLoopAndDeduped(t *testing.T) {
	gate := make(chan struct{})
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(gate) }) }

	calls := make(chan string, 16)
	w := newTestTargetWatcher(func(token watchToken) {
		calls <- token.target
		if token.target == "slow0" {
			<-gate
		}
	})

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return dummyLinks("slow0", "fast0"), nil }

	_, err := w.WatchInterface("slow0", uint64(fakeIfindex("slow0")))
	require.NoError(t, err)
	_, err = w.WatchInterface("fast0", uint64(fakeIfindex("fast0")))
	require.NoError(t, err)
	require.NoError(t, w.Start())
	// LIFO: the gate must open before Stop so a worker blocked in the slow
	// onRemoved can finish and Stop's wg.Wait can return on failure paths.
	defer w.Stop()
	defer openGate()

	sub := fake.waitForSubscription(t)

	send := func(u netlink.LinkUpdate) {
		t.Helper()
		select {
		case sub.ch <- u:
		case <-time.After(3 * time.Second):
			t.Fatal("event loop is blocked and stopped consuming netlink updates")
		}
	}

	send(linkDel("slow0"))
	expectRemoved(t, calls, "slow0") // slow0 dispatch started, now blocked on gate

	// Re-fire for the same target: must be deduped at dispatch time.
	send(linkDel("slow0"))

	// A second, distinct removal must be processed while slow0 is blocked.
	send(linkDel("fast0"))
	select {
	case got := <-calls:
		require.Equal(t, "fast0", got)
	case <-time.After(3 * time.Second):
		t.Fatal("second removal was blocked behind a slow onRemoved")
	}

	openGate()

	// No further dispatches may arrive: each target exactly once.
	select {
	case got := <-calls:
		t.Fatalf("target %q dispatched more than once", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestWatcherStaleQueuedRemovalCannotTearDownReattachment is the end-to-end
// regression for generation-safe callbacks. An old removal is held inside a
// dispatch worker while the attachment is explicitly detached and the same
// target is attached again. Releasing the old callback must leave both the
// new Server attachment and its new watcher generation intact.
func TestWatcherStaleQueuedRemovalCannotTearDownReattachment(t *testing.T) {
	env := newAttachTestEnv(t, 12119)
	w := env.server.watcher
	env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) { return 77, nil })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return dummyLink("stale-if0", 77), nil }

	originalHandler := w.onRemoved
	callbackStarted := make(chan watchToken, 1)
	releaseCallback := make(chan struct{})
	callbackFinished := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCallback) }) }
	w.onRemoved = func(token watchToken) {
		callbackStarted <- token
		<-releaseCallback
		originalHandler(token)
		close(callbackFinished)
	}

	require.NoError(t, w.Start())
	defer w.Stop()
	defer release()
	fake.waitForSubscription(t)

	oldResp, err := env.server.Attach(context.Background(), attachInterfaceReq("stale-if0"))
	require.NoError(t, err)
	env.server.mu.RLock()
	oldToken := env.server.attachments[oldResp.Id].watch
	env.server.mu.RUnlock()
	require.True(t, oldToken.valid())

	// Remove the watch and queue its token exactly as a real DELLINK would.
	w.dispatchInterfaceRemoved(oldToken, "test")
	select {
	case got := <-callbackStarted:
		require.Equal(t, oldToken, got)
	case <-time.After(3 * time.Second):
		t.Fatal("old removal callback never reached the worker")
	}

	_, err = env.server.Detach(context.Background(), &apiv1.DetachRequest{Id: oldResp.Id})
	require.NoError(t, err)
	newResp, err := env.server.Attach(context.Background(), attachInterfaceReq("stale-if0"))
	require.NoError(t, err)

	env.server.mu.RLock()
	newState := env.server.attachments[newResp.Id]
	newToken := newState.watch
	env.server.mu.RUnlock()
	require.NotEqual(t, oldToken, newToken)

	release()
	select {
	case <-callbackFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("old removal callback did not finish")
	}

	env.server.mu.RLock()
	indexedID, indexed := env.server.targetIndex["stale-if0"]
	stillAttached := env.server.attachments[newResp.Id] == newState
	env.server.mu.RUnlock()
	require.True(t, indexed)
	require.Equal(t, newResp.Id, indexedID)
	require.True(t, stillAttached, "stale callback tore down the fresh attachment")

	w.mu.RLock()
	currentWatch, watched := w.interfaces["stale-if0"]
	w.mu.RUnlock()
	require.True(t, watched, "stale callback tore down the fresh watch")
	require.Equal(t, newToken, currentWatch.token)

	filters := env.createdFilters()
	require.Len(t, filters, 2)
	require.Equal(t, 1, filters[0].detachCallCount())
	require.Zero(t, filters[1].detachCallCount(), "fresh filter was detached by stale callback")

	_, err = env.server.Detach(context.Background(), &apiv1.DetachRequest{Id: newResp.Id})
	require.NoError(t, err)
}

// TestAttachFailsWhenIdentityChangesInWatchRegistrationRecheck pins the
// synchronous failure contract. The target stays stable across filter
// construction and Server's pre-watch validation, then changes only when the
// now-active watch performs its final identity lookup. Attach must return an
// error and its rollback must own exactly-once teardown even though the
// watcher also queued the exact failed generation.
func TestAttachFailsWhenIdentityChangesInWatchRegistrationRecheck(t *testing.T) {
	env := newAttachTestEnv(t, 12121)
	w := env.server.watcher

	originalHandler := w.onRemoved
	callbackStarted := make(chan watchToken, 1)
	releaseCallback := make(chan struct{})
	callbackFinished := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCallback) }) }
	w.onRemoved = func(token watchToken) {
		callbackStarted <- token
		<-releaseCallback
		originalHandler(token)
		close(callbackFinished)
	}

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }
	require.NoError(t, w.Start())
	defer w.Stop()
	defer release()
	fake.waitForSubscription(t)

	const (
		oldIdentity = 901
		newIdentity = 902
	)
	var identityCalls atomic.Int64
	env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) {
		if identityCalls.Add(1) == 4 {
			return newIdentity, nil
		}
		return oldIdentity, nil
	})

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("watch-race-if0"))
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "interface identity changed during watch registration")
	require.ErrorIs(t, err, errTargetIdentityChanged)
	require.GreaterOrEqual(t, identityCalls.Load(), int64(4))

	select {
	case token := <-callbackStarted:
		require.Equal(t, "watch-race-if0", token.target)
	case <-time.After(3 * time.Second):
		t.Fatal("failed watch generation was not queued for callback")
	}
	release()
	select {
	case <-callbackFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("failed watch callback did not finish")
	}

	env.assertNoResidue(t)

	filters := env.createdFilters()
	require.Len(t, filters, 1)
	require.Equal(t, 1, filters[0].detachCallCount(), "failed watch registration must roll the filter back exactly once")

	w.mu.RLock()
	_, watched := w.interfaces["watch-race-if0"]
	w.mu.RUnlock()
	require.False(t, watched)
}

// TestWatcherCgroupRegistrationWindowRemovalDispatchesExactGeneration deletes
// the cgroup after its identity is captured but before its parent watch is
// installed. No fsnotify event can exist, so only the post-registration
// identity recheck can dispatch the exact old generation.
func TestWatcherCgroupRegistrationWindowRemovalDispatchesExactGeneration(t *testing.T) {
	removed := make(chan watchToken, 4)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	parent := t.TempDir()
	cgroup := filepath.Join(parent, "registration-window")
	require.NoError(t, os.Mkdir(cgroup, 0o755))
	identity, err := w.cgroupIdentity(cgroup)
	require.NoError(t, err)

	require.NoError(t, w.Start())
	defer w.Stop()
	require.NoError(t, os.Remove(cgroup))

	token, err := w.WatchCgroup(cgroup, identity)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rechecking cgroup identity")
	select {
	case got := <-removed:
		require.Equal(t, token, got)
	case <-time.After(3 * time.Second):
		t.Fatal("cgroup deleted in registration window was not dispatched")
	}

	w.mu.RLock()
	_, watched := w.cgroups[cgroup]
	w.mu.RUnlock()
	require.False(t, watched)

	select {
	case got := <-removed:
		t.Fatalf("registration recheck and fsnotify double-dispatched token: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestWatcherCgroupRegistrationWindowReplacementDispatchesExactGeneration is
// the same pre-registration gap for reincarnation: the path is replaced
// before the parent watch exists, so there is no event to help. Existence-only
// checks miss this; identity comparison must dispatch the old generation.
func TestWatcherCgroupRegistrationWindowReplacementDispatchesExactGeneration(t *testing.T) {
	removed := make(chan watchToken, 4)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	const (
		oldIdentity = 301
		newIdentity = 302
	)
	var identity atomic.Uint64
	identity.Store(oldIdentity)
	w.cgroupIdentity = func(string) (uint64, error) { return identity.Load(), nil }

	parent := t.TempDir()
	cgroup := filepath.Join(parent, "registration-replacement")
	require.NoError(t, os.Mkdir(cgroup, 0o755))

	require.NoError(t, w.Start())
	defer w.Stop()
	require.NoError(t, os.Remove(cgroup))
	require.NoError(t, os.Mkdir(cgroup, 0o755))
	identity.Store(newIdentity)

	token, err := w.WatchCgroup(cgroup, oldIdentity)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cgroup identity changed during watch registration")
	require.ErrorIs(t, err, errTargetIdentityChanged)
	select {
	case got := <-removed:
		require.Equal(t, token, got)
		require.Equal(t, uint64(oldIdentity), got.identity)
	case <-time.After(3 * time.Second):
		t.Fatal("same-path cgroup replacement was not dispatched")
	}

	w.mu.RLock()
	_, watched := w.cgroups[cgroup]
	w.mu.RUnlock()
	require.False(t, watched)

	select {
	case got := <-removed:
		t.Fatalf("replacement event double-dispatched token: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}

	newToken, err := w.WatchCgroup(cgroup, newIdentity)
	require.NoError(t, err)
	w.UnwatchCgroup(token)
	w.mu.RLock()
	current, stillWatched := w.cgroups[cgroup]
	w.mu.RUnlock()
	require.True(t, stillWatched, "old unwatch removed the replacement generation")
	require.Equal(t, newToken, current)
	w.UnwatchCgroup(newToken)
}

// TestWatcherCgroupEventDetectsSamePathReplacement covers the established
// fsnotify event path (not WatchCgroup's registration recheck). The identity
// lookup is deliberately paused after the Remove event is consumed; the path
// is then recreated before lookup completes. The old token must still fire.
func TestWatcherCgroupEventDetectsSamePathReplacement(t *testing.T) {
	removed := make(chan watchToken, 4)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	const (
		oldIdentity = 501
		newIdentity = 502
	)
	var identity atomic.Uint64
	identity.Store(oldIdentity)
	var blockLookup atomic.Bool
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var lookupStartedOnce sync.Once
	var releaseLookupOnce sync.Once
	release := func() { releaseLookupOnce.Do(func() { close(releaseLookup) }) }
	w.cgroupIdentity = func(string) (uint64, error) {
		if blockLookup.Load() {
			lookupStartedOnce.Do(func() { close(lookupStarted) })
			<-releaseLookup
		}
		return identity.Load(), nil
	}

	parent := t.TempDir()
	cgroup := filepath.Join(parent, "event-replacement")
	require.NoError(t, os.Mkdir(cgroup, 0o755))

	require.NoError(t, w.Start())
	defer w.Stop()
	defer release()
	token, err := w.WatchCgroup(cgroup, oldIdentity)
	require.NoError(t, err)

	// WatchCgroup's post-registration check completed with the old identity;
	// only the established fsnotify reader can trigger from here.
	blockLookup.Store(true)
	require.NoError(t, os.Remove(cgroup))
	select {
	case <-lookupStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("fsnotify Remove event did not reach the identity check")
	}

	require.NoError(t, os.Mkdir(cgroup, 0o755))
	identity.Store(newIdentity)
	release()

	select {
	case got := <-removed:
		require.Equal(t, token, got)
		require.Equal(t, uint64(oldIdentity), got.identity)
	case <-time.After(3 * time.Second):
		t.Fatal("same-path replacement on established watch was not dispatched")
	}

	w.mu.RLock()
	_, watched := w.cgroups[cgroup]
	w.mu.RUnlock()
	require.False(t, watched)

	select {
	case got := <-removed:
		t.Fatalf("established replacement double-dispatched token: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}
}

func countInotifyInstances(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(link, "anon_inode:inotify") {
			n++
		}
	}
	return n
}

// TestWatcherSharedCgroupWatcherScale: >200 cgroups must be watchable on a
// single shared fsnotify (inotify) instance, removal of one must fire
// onRemoved, and siblings sharing a parent directory must keep working as
// others are removed or unwatched (parent-dir refcounting).
func TestWatcherSharedCgroupWatcherScale(t *testing.T) {
	removed := make(chan string, 512)
	w := newTestTargetWatcher(func(token watchToken) { removed <- token.target })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	base := t.TempDir()
	before := countInotifyInstances(t)

	require.NoError(t, w.Start())
	defer w.Stop()

	const parents = 5
	const perParent = 45 // 225 total, above the 128 default inotify instance cap
	var paths []string
	tokens := make(map[string]watchToken, parents*perParent)
	parentDirs := make([]string, 0, parents)
	for p := 0; p < parents; p++ {
		parentDir := filepath.Join(base, fmt.Sprintf("parent%d", p))
		require.NoError(t, os.Mkdir(parentDir, 0o755))
		parentDirs = append(parentDirs, parentDir)
		for c := 0; c < perParent; c++ {
			path := filepath.Join(parentDir, fmt.Sprintf("cg%d", c))
			require.NoError(t, os.Mkdir(path, 0o755))
			paths = append(paths, path)
			token := watchTestCgroup(t, w, path)
			tokens[path] = token
		}
	}

	after := countInotifyInstances(t)
	require.Equal(t, before+1, after,
		"expected exactly one shared inotify instance for %d watched cgroups, got %d new instances",
		len(paths), after-before)

	// Refcount bookkeeping: one dirRefs entry per parent, one ref per child.
	w.mu.RLock()
	require.NotNil(t, w.cgWatcher)
	require.Len(t, w.cgroups, parents*perParent)
	require.Len(t, w.dirRefs, parents)
	require.Len(t, w.dirRefs[parentDirs[0]], perParent)
	w.mu.RUnlock()

	// Removing one cgroup fires its onRemoved...
	victim, sibling := paths[0], paths[1]
	require.NoError(t, os.Remove(victim))
	expectRemoved(t, removed, victim)

	// ...and a sibling under the same parent is still watched afterwards
	// (the victim's dispatch dropped its ref without dropping the dir watch).
	require.NoError(t, os.Remove(sibling))
	expectRemoved(t, removed, sibling)

	// Explicit unwatch of all but one child under a parent must keep the
	// last sibling's watch alive.
	parent1kids := paths[perParent : 2*perParent]
	for _, path := range parent1kids[1:] {
		w.UnwatchCgroup(tokens[path])
	}
	w.mu.RLock()
	require.Len(t, w.dirRefs[parentDirs[1]], 1)
	w.mu.RUnlock()
	require.NoError(t, os.Remove(parent1kids[0]))
	expectRemoved(t, removed, parent1kids[0])

	// The last child under parent1 is gone, so its dir watch is released
	// while parent0's (which still has children) is retained.
	w.mu.RLock()
	_, parent1Watched := w.dirRefs[parentDirs[1]]
	watchList := w.cgWatcher.WatchList()
	w.mu.RUnlock()
	require.False(t, parent1Watched, "parent dir refcount not released after last child removed")
	require.NotContains(t, watchList, parentDirs[1])
	require.Contains(t, watchList, parentDirs[0])

	// No stray dispatches (e.g. duplicate events for already-removed paths).
	select {
	case got := <-removed:
		t.Fatalf("unexpected extra onRemoved(%q)", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestWatcherStopIdempotent: Stop is safe to call twice and leaves no
// goroutine blocked, including with an active netlink subscription and
// watched cgroups.
func TestWatcherStopIdempotent(t *testing.T) {
	w := newTestTargetWatcher(func(watchToken) {})

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	dir := t.TempDir()
	cg := filepath.Join(dir, "cg")
	require.NoError(t, os.Mkdir(cg, 0o755))
	watchTestCgroup(t, w, cg)
	require.NoError(t, w.Start())
	fake.waitForSubscription(t)

	done := make(chan struct{})
	go func() {
		w.Stop()
		w.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return (leaked or blocked goroutine)")
	}

	// After Stop, WatchCgroup of a new path must not resurrect a watcher.
	cg2 := filepath.Join(dir, "cg2")
	require.NoError(t, os.Mkdir(cg2, 0o755))
	identity, err := w.cgroupIdentity(cg2)
	require.NoError(t, err)
	_, err = w.WatchCgroup(cg2, identity)
	require.Error(t, err)
}
