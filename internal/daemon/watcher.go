//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// nlUpdateChanSize buffers netlink link updates so short bursts of
	// interface churn are absorbed in userspace instead of queueing in the
	// kernel socket (where overflow surfaces as ENOBUFS and kills the
	// subscription).
	nlUpdateChanSize = 64

	// nlReceiveBufferSize enlarges the netlink socket receive buffer to
	// reduce ENOBUFS under heavy interface churn. The kernel caps it at
	// net.core.rmem_max unless force-sized, which we deliberately don't do.
	nlReceiveBufferSize = 1 << 20

	// netlink closes the updates channel when its internal receive goroutine
	// errors. We resubscribe with capped exponential backoff between these
	// bounds; a subscription that survives nlSubscriptionHealthyAge resets
	// the backoff so a one-off failure after a long healthy period retries
	// quickly, while a persistently failing subscription keeps backing off.
	nlResubscribeMinBackoff  = 100 * time.Millisecond
	nlResubscribeMaxBackoff  = 5 * time.Second
	nlSubscriptionHealthyAge = 30 * time.Second

	// removalWorkerCount bounds the number of concurrent onRemoved
	// dispatches. onRemoved (Server.handleTargetRemoved) does eBPF close +
	// store delete + control-plane send, so it must never run on a watcher
	// event loop, but we also must not spawn a goroutine per event.
	removalWorkerCount = 4
)

type TargetWatcher struct {
	logger    zerolog.Logger
	onRemoved func(target string)

	mu         sync.RWMutex
	interfaces map[string]struct{} // interface name -> watched
	cgroups    map[string]struct{} // cgroup path -> watched
	// dirRefs refcounts parent-directory watches on the single shared
	// fsnotify watcher: parentDir -> set of watched cgroup paths under it.
	// Multiple cgroups can share a parent, so the directory watch is only
	// added on the first child and removed with the last one.
	dirRefs   map[string]map[string]struct{}
	cgWatcher *fsnotify.Watcher // single shared instance for all cgroups

	// pending queues removed targets for the dispatch workers. A target is
	// deleted from its watched set at enqueue time, so each target is
	// enqueued at most once per watch (dedupe) and the queue length is
	// bounded by the number of watched targets.
	pendingMu sync.Mutex
	pending   []string
	pendingCh chan struct{} // wakeup signal, capacity 1

	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Test seams: default to the real netlink calls (set in
	// NewTargetWatcher), overridden in tests to drive the resubscribe and
	// reconcile paths deterministically.
	subscribeLinks func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
	listLinks      func() ([]netlink.Link, error)
}

func NewTargetWatcher(logger zerolog.Logger, onRemoved func(target string)) *TargetWatcher {
	w := &TargetWatcher{
		logger:     logger.With().Str("component", "watcher").Logger(),
		onRemoved:  onRemoved,
		interfaces: make(map[string]struct{}),
		cgroups:    make(map[string]struct{}),
		dirRefs:    make(map[string]map[string]struct{}),
		pendingCh:  make(chan struct{}, 1),
		done:       make(chan struct{}),
	}
	w.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
			ReceiveBufferSize: nlReceiveBufferSize,
			ErrorCallback: func(err error) {
				w.logger.Warn().Err(err).Msg("netlink link subscription error")
			},
		})
	}
	w.listLinks = netlink.LinkList
	return w
}

func (w *TargetWatcher) Start() error {
	w.wg.Add(1)
	go w.watchInterfaces()

	for i := 0; i < removalWorkerCount; i++ {
		w.wg.Add(1)
		go w.runRemovalWorker()
	}
	return nil
}

func (w *TargetWatcher) Stop() {
	w.stopOnce.Do(func() { close(w.done) })

	w.mu.Lock()
	if w.cgWatcher != nil {
		w.cgWatcher.Close()
		w.cgWatcher = nil
	}
	w.mu.Unlock()

	w.wg.Wait()
}

func (w *TargetWatcher) WatchInterface(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.interfaces[name] = struct{}{}
	w.logger.Debug().Str("interface", name).Msg("watching interface")
}

func (w *TargetWatcher) UnwatchInterface(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.interfaces, name)
	w.logger.Debug().Str("interface", name).Msg("unwatching interface")
}

func (w *TargetWatcher) WatchCgroup(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, ok := w.cgroups[path]; ok {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if err := w.ensureCgroupWatcherLocked(); err != nil {
		return err
	}

	// Watch the parent directory so we can detect when the cgroup is
	// removed. The parent-dir watch is refcounted across siblings.
	parentDir := filepath.Dir(path)
	refs, ok := w.dirRefs[parentDir]
	if !ok {
		if err := w.cgWatcher.Add(parentDir); err != nil {
			return err
		}
		refs = make(map[string]struct{})
		w.dirRefs[parentDir] = refs
	}
	refs[path] = struct{}{}
	w.cgroups[path] = struct{}{}

	w.logger.Debug().Str("cgroup", path).Msg("watching cgroup")
	return nil
}

func (w *TargetWatcher) UnwatchCgroup(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.removeCgroupLocked(path) {
		w.logger.Debug().Str("cgroup", path).Msg("unwatching cgroup")
	}
}

// ensureCgroupWatcherLocked lazily creates the single shared fsnotify watcher
// (one inotify instance total, regardless of cgroup count) and its reader
// goroutine. Caller must hold w.mu.
func (w *TargetWatcher) ensureCgroupWatcherLocked() error {
	if w.cgWatcher != nil {
		return nil
	}
	select {
	case <-w.done:
		return errors.New("target watcher is stopped")
	default:
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	w.cgWatcher = watcher
	w.wg.Add(1)
	go w.watchCgroups(watcher)
	return nil
}

// removeCgroupLocked removes path from the watched set and decrements its
// parent-directory refcount, dropping the fsnotify directory watch only when
// the last watched cgroup under that parent is gone (so unwatching one cgroup
// never breaks a sibling sharing the parent). Returns false if path was not
// watched. Caller must hold w.mu.
func (w *TargetWatcher) removeCgroupLocked(path string) bool {
	if _, ok := w.cgroups[path]; !ok {
		return false
	}
	delete(w.cgroups, path)

	parentDir := filepath.Dir(path)
	if refs, ok := w.dirRefs[parentDir]; ok {
		delete(refs, path)
		if len(refs) > 0 {
			return true
		}
		delete(w.dirRefs, parentDir)
	}
	if w.cgWatcher != nil {
		// The kernel drops the watch itself if the directory was deleted,
		// so a failure here is expected and non-fatal.
		if err := w.cgWatcher.Remove(parentDir); err != nil {
			w.logger.Debug().Err(err).Str("dir", parentDir).Msg("removing parent directory watch")
		}
	}
	return true
}

func (w *TargetWatcher) watchInterfaces() {
	defer w.wg.Done()

	backoff := nlResubscribeMinBackoff
	for {
		updates := make(chan netlink.LinkUpdate, nlUpdateChanSize)
		subDone := make(chan struct{})

		if err := w.subscribeLinks(updates, subDone); err != nil {
			close(subDone)
			w.logger.Error().Err(err).Dur("backoff", backoff).Msg("failed to subscribe to netlink link updates")
			if !w.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		subscribedAt := time.Now()

		// Deletions that happened while we were not subscribed produce no
		// event, so reconcile the watched set against reality after every
		// (re)subscribe to close the gap.
		w.reconcileInterfaces()

		channelClosed := w.consumeLinkUpdates(updates)

		// Always signal netlink to close its socket and reap its internal
		// done-watcher goroutine.
		close(subDone)

		if !channelClosed {
			// Stopping: drain until netlink's receive goroutine notices the
			// closed socket and closes the channel, so it is never left
			// blocked on a send.
			w.wg.Add(1)
			go func() {
				defer w.wg.Done()
				for range updates {
				}
			}()
			return
		}

		// netlink closed the updates channel (receive error, e.g. ENOBUFS
		// under churn). Resubscribe with bounded backoff — never hot-loop on
		// the closed channel.
		w.logger.Warn().Dur("backoff", backoff).Msg("netlink updates channel closed; resubscribing")
		if time.Since(subscribedAt) >= nlSubscriptionHealthyAge {
			backoff = nlResubscribeMinBackoff
		}
		if !w.sleep(backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// consumeLinkUpdates processes link updates until the channel is closed by
// netlink (returns true: caller should resubscribe) or the watcher is stopped
// (returns false).
func (w *TargetWatcher) consumeLinkUpdates(updates <-chan netlink.LinkUpdate) bool {
	for {
		select {
		case <-w.done:
			return false
		case update, ok := <-updates:
			if !ok {
				return true
			}
			// RTM_DELLINK indicates an interface was removed
			if update.Header.Type != unix.RTM_DELLINK || update.Link == nil {
				continue
			}
			w.dispatchInterfaceRemoved(update.Attrs().Name, "netlink")
		}
	}
}

// reconcileInterfaces fires removal for any watched interface that no longer
// exists. Called after every successful (re)subscribe so deletions during a
// subscription gap are not silently lost.
func (w *TargetWatcher) reconcileInterfaces() {
	w.mu.RLock()
	watched := make([]string, 0, len(w.interfaces))
	for name := range w.interfaces {
		watched = append(watched, name)
	}
	w.mu.RUnlock()
	if len(watched) == 0 {
		return
	}

	links, err := w.listLinks()
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to list links while reconciling watched interfaces")
		return
	}
	present := make(map[string]struct{}, len(links))
	for _, link := range links {
		present[link.Attrs().Name] = struct{}{}
	}
	for _, name := range watched {
		if _, ok := present[name]; !ok {
			w.dispatchInterfaceRemoved(name, "reconcile")
		}
	}
}

func (w *TargetWatcher) watchCgroups(watcher *fsnotify.Watcher) {
	defer w.wg.Done()

	for {
		select {
		case <-w.done:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Remove == 0 {
				continue
			}
			// event.Name is the full path of the removed child; match it
			// against the watched cgroup set.
			path := event.Name
			w.mu.RLock()
			_, watched := w.cgroups[path]
			w.mu.RUnlock()
			if !watched {
				continue
			}
			// Verify it's actually gone (not just renamed)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				w.dispatchCgroupRemoved(path)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			w.logger.Warn().Err(err).Msg("cgroup watcher error")
		}
	}
}

// dispatchInterfaceRemoved hands a removed interface to the dispatch workers.
// The name is deleted from the watched set here, at dispatch time, so repeated
// events for the same target are dropped (dedupe). onRemoved itself never runs
// on a watcher event loop.
func (w *TargetWatcher) dispatchInterfaceRemoved(name, source string) {
	w.mu.Lock()
	_, watched := w.interfaces[name]
	delete(w.interfaces, name)
	w.mu.Unlock()
	if !watched {
		return
	}
	w.logger.Info().Str("interface", name).Str("source", source).Msg("interface removed")
	w.enqueueRemoval(name)
}

func (w *TargetWatcher) dispatchCgroupRemoved(path string) {
	w.mu.Lock()
	removed := w.removeCgroupLocked(path)
	w.mu.Unlock()
	if !removed {
		return
	}
	w.logger.Info().Str("cgroup", path).Msg("cgroup removed")
	w.enqueueRemoval(path)
}

func (w *TargetWatcher) enqueueRemoval(target string) {
	w.pendingMu.Lock()
	w.pending = append(w.pending, target)
	w.pendingMu.Unlock()
	select {
	case w.pendingCh <- struct{}{}:
	default:
	}
}

func (w *TargetWatcher) runRemovalWorker() {
	defer w.wg.Done()
	for {
		select {
		case <-w.done:
			return
		case <-w.pendingCh:
			w.drainPending()
		}
	}
}

func (w *TargetWatcher) drainPending() {
	for {
		select {
		case <-w.done:
			return
		default:
		}
		w.pendingMu.Lock()
		if len(w.pending) == 0 {
			w.pendingMu.Unlock()
			return
		}
		target := w.pending[0]
		w.pending = w.pending[1:]
		remaining := len(w.pending) > 0
		w.pendingMu.Unlock()
		if remaining {
			// Wake another worker so a slow onRemoved doesn't serialize the
			// rest of the queue behind this one.
			select {
			case w.pendingCh <- struct{}{}:
			default:
			}
		}
		// Invoked with no watcher locks held: onRemoved
		// (Server.handleTargetRemoved) takes s.mu and calls back into
		// Unwatch*, which takes w.mu.
		w.onRemoved(target)
	}
}

func (w *TargetWatcher) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-w.done:
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > nlResubscribeMaxBackoff {
		return nlResubscribeMaxBackoff
	}
	return d
}
