//go:build linux

package daemon

import (
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

func linkDel(name string) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_DELLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}},
	}
}

func dummyLinks(names ...string) []netlink.Link {
	links := make([]netlink.Link, 0, len(names))
	for _, name := range names {
		links = append(links, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	}
	return links
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
	w := NewTargetWatcher(zerolog.Nop(), func(target string) { removed <- target })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return dummyLinks("veth0"), nil }

	w.WatchInterface("veth0")
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
	w := NewTargetWatcher(zerolog.Nop(), func(string) {})

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
	w := NewTargetWatcher(zerolog.Nop(), func(target string) { removed <- target })

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe

	var links atomic.Value
	links.Store(dummyLinks("veth-gap"))
	reconciled := make(chan struct{}, 16)
	w.listLinks = func() ([]netlink.Link, error) {
		defer func() { reconciled <- struct{}{} }()
		return links.Load().([]netlink.Link), nil
	}

	w.WatchInterface("veth-gap")
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

// TestWatcherOnRemovedOffEventLoopAndDeduped: a slow onRemoved must not block
// the event loop or a second distinct removal, and a repeated event for the
// same target must not dispatch it twice.
func TestWatcherOnRemovedOffEventLoopAndDeduped(t *testing.T) {
	gate := make(chan struct{})
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(gate) }) }

	calls := make(chan string, 16)
	w := NewTargetWatcher(zerolog.Nop(), func(target string) {
		calls <- target
		if target == "slow0" {
			<-gate
		}
	})

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return dummyLinks("slow0", "fast0"), nil }

	w.WatchInterface("slow0")
	w.WatchInterface("fast0")
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
	w := NewTargetWatcher(zerolog.Nop(), func(target string) { removed <- target })

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
	parentDirs := make([]string, 0, parents)
	for p := 0; p < parents; p++ {
		parentDir := filepath.Join(base, fmt.Sprintf("parent%d", p))
		require.NoError(t, os.Mkdir(parentDir, 0o755))
		parentDirs = append(parentDirs, parentDir)
		for c := 0; c < perParent; c++ {
			path := filepath.Join(parentDir, fmt.Sprintf("cg%d", c))
			require.NoError(t, os.Mkdir(path, 0o755))
			paths = append(paths, path)
			require.NoError(t, w.WatchCgroup(path))
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
		w.UnwatchCgroup(path)
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
	w := NewTargetWatcher(zerolog.Nop(), func(string) {})

	fake := newFakeLinkSubscriber()
	w.subscribeLinks = fake.subscribe
	w.listLinks = func() ([]netlink.Link, error) { return nil, nil }

	dir := t.TempDir()
	cg := filepath.Join(dir, "cg")
	require.NoError(t, os.Mkdir(cg, 0o755))
	require.NoError(t, w.WatchCgroup(cg))
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
	require.Error(t, w.WatchCgroup(cg2))
}
