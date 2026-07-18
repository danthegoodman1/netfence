//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	apiv1 "github.com/danthegoodman1/netfence/v1"
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

type interfaceWatch struct {
	token   watchToken
	ifindex uint64
}

type TargetWatcher struct {
	logger    zerolog.Logger
	onRemoved func(watchToken)

	mu             sync.RWMutex
	nextGeneration uint64
	interfaces     map[string]interfaceWatch // interface name -> exact watched identity
	cgroups        map[string]watchToken     // cgroup path -> exact watched generation
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
	pending   []watchToken
	pendingCh chan struct{} // wakeup signal, capacity 1

	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Test seams: default to the real netlink calls (set in
	// NewTargetWatcher), overridden in tests to drive the resubscribe and
	// reconcile paths deterministically.
	subscribeLinks    func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
	listLinks         func() ([]netlink.Link, error)
	interfaceIdentity func(name string) (uint64, error)
	cgroupIdentity    func(path string) (uint64, error)
}

func NewTargetWatcher(logger zerolog.Logger, onRemoved func(watchToken)) *TargetWatcher {
	w := &TargetWatcher{
		logger:     logger.With().Str("component", "watcher").Logger(),
		onRemoved:  onRemoved,
		interfaces: make(map[string]interfaceWatch),
		cgroups:    make(map[string]watchToken),
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
	w.interfaceIdentity = currentInterfaceIdentity
	w.cgroupIdentity = currentCgroupIdentity
	return w
}

func (w *TargetWatcher) setTargetIdentityResolver(resolve func(apiv1.AttachmentType, string) (uint64, error)) {
	w.interfaceIdentity = func(name string) (uint64, error) {
		return resolve(apiv1.AttachmentType_ATTACHMENT_TYPE_TC, name)
	}
	w.cgroupIdentity = func(path string) (uint64, error) {
		return resolve(apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP, path)
	}
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

func (w *TargetWatcher) WatchInterface(name string, ifindex uint64) (watchToken, error) {
	w.mu.Lock()
	if w.stoppedLocked() {
		w.mu.Unlock()
		return watchToken{}, errors.New("target watcher is stopped")
	}
	token := w.newTokenLocked(name, watchKindInterface, ifindex)
	w.interfaces[name] = interfaceWatch{token: token, ifindex: ifindex}
	w.mu.Unlock()

	w.logger.Debug().Str("interface", name).Msg("watching interface")

	// Close the lookup -> registration gap too. A DELLINK may have raced
	// before the registration became visible; in that case remove this exact
	// generation. A same-name replacement is also removal of the identity the
	// filter was attached to.
	currentIfindex, err := w.interfaceIdentity(name)
	if err != nil {
		w.dispatchInterfaceRemoved(token, "registration-recheck")
		return token, fmt.Errorf("rechecking interface identity after watch registration: %w", err)
	}
	if currentIfindex != ifindex {
		w.dispatchInterfaceRemoved(token, "registration-recheck")
		return token, fmt.Errorf("interface identity changed during watch registration: was %d, now %d", ifindex, currentIfindex)
	}
	return token, nil
}

func (w *TargetWatcher) UnwatchInterface(token watchToken) {
	w.mu.Lock()
	current, ok := w.interfaces[token.target]
	if ok && current.token == token {
		delete(w.interfaces, token.target)
	}
	w.mu.Unlock()
	if ok && current.token == token {
		w.logger.Debug().Str("interface", token.target).Msg("unwatching interface")
	}
}

func (w *TargetWatcher) WatchCgroup(path string, identity uint64) (watchToken, error) {
	w.mu.Lock()
	if w.stoppedLocked() {
		w.mu.Unlock()
		return watchToken{}, errors.New("target watcher is stopped")
	}
	if err := w.ensureCgroupWatcherLocked(); err != nil {
		w.mu.Unlock()
		return watchToken{}, err
	}

	// Watch the parent directory so we can detect when the cgroup is
	// removed. The parent-dir watch is refcounted across siblings.
	parentDir := filepath.Dir(path)
	refs, ok := w.dirRefs[parentDir]
	if !ok {
		if err := w.cgWatcher.Add(parentDir); err != nil {
			w.mu.Unlock()
			return watchToken{}, err
		}
		refs = make(map[string]struct{})
		w.dirRefs[parentDir] = refs
	}
	token := w.newTokenLocked(path, watchKindCgroup, identity)
	refs[path] = struct{}{}
	w.cgroups[path] = token
	w.mu.Unlock()

	w.logger.Debug().Str("cgroup", path).Msg("watching cgroup")

	// The pre-attachment identity validation and fsnotify Add cannot be
	// atomic. Recheck only after both the directory watch and the exact
	// in-memory generation are active; absence or same-path replacement in
	// that window dispatches this generation. The token comparison makes the
	// result harmless after a later rewatch.
	currentIdentity, err := w.cgroupIdentity(path)
	if err != nil {
		w.dispatchCgroupRemoved(token)
		return token, fmt.Errorf("rechecking cgroup identity after watch registration: %w", err)
	}
	if currentIdentity != identity {
		w.dispatchCgroupRemoved(token)
		return token, fmt.Errorf("cgroup identity changed during watch registration: was %d, now %d", identity, currentIdentity)
	}
	return token, nil
}

func (w *TargetWatcher) UnwatchCgroup(token watchToken) {
	w.mu.Lock()
	removed := w.removeCgroupLocked(token)
	w.mu.Unlock()
	if removed {
		w.logger.Debug().Str("cgroup", token.target).Msg("unwatching cgroup")
	}
}

func (w *TargetWatcher) stoppedLocked() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

func (w *TargetWatcher) newTokenLocked(target string, kind watchKind, identity uint64) watchToken {
	w.nextGeneration++
	return watchToken{generation: w.nextGeneration, target: target, kind: kind, identity: identity}
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
func (w *TargetWatcher) removeCgroupLocked(token watchToken) bool {
	current, ok := w.cgroups[token.target]
	if !ok || current != token {
		return false
	}
	delete(w.cgroups, token.target)

	parentDir := filepath.Dir(token.target)
	if refs, ok := w.dirRefs[parentDir]; ok {
		delete(refs, token.target)
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
			attrs := update.Attrs()
			w.mu.RLock()
			watched, ok := w.interfaces[attrs.Name]
			w.mu.RUnlock()
			if ok && watched.ifindex == uint64(attrs.Index) {
				w.dispatchInterfaceRemoved(watched.token, "netlink")
			}
		}
	}
}

// reconcileInterfaces fires removal for any watched interface that no longer
// exists. Called after every successful (re)subscribe so deletions during a
// subscription gap are not silently lost.
func (w *TargetWatcher) reconcileInterfaces() {
	w.mu.RLock()
	watched := make([]interfaceWatch, 0, len(w.interfaces))
	for _, registration := range w.interfaces {
		watched = append(watched, registration)
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
	present := make(map[string]uint64, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		present[attrs.Name] = uint64(attrs.Index)
	}
	for _, registration := range watched {
		if ifindex, ok := present[registration.token.target]; !ok || ifindex != registration.ifindex {
			w.dispatchInterfaceRemoved(registration.token, "reconcile")
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
			token, watched := w.cgroups[path]
			w.mu.RUnlock()
			if !watched {
				continue
			}
			// A remove followed by a same-path recreation can be coalesced or
			// consumed after the replacement already exists. Compare the kernel
			// object identity, not mere path existence, so the watch for the old
			// cgroup is still removed.
			currentIdentity, err := w.cgroupIdentity(path)
			if err != nil || currentIdentity != token.identity {
				w.dispatchCgroupRemoved(token)
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
func (w *TargetWatcher) dispatchInterfaceRemoved(token watchToken, source string) {
	w.mu.Lock()
	current, watched := w.interfaces[token.target]
	if watched && current.token == token {
		delete(w.interfaces, token.target)
	} else {
		watched = false
	}
	w.mu.Unlock()
	if !watched {
		return
	}
	w.logger.Info().Str("interface", token.target).Str("source", source).Msg("interface removed")
	w.enqueueRemoval(token)
}

func (w *TargetWatcher) dispatchCgroupRemoved(token watchToken) {
	w.mu.Lock()
	removed := w.removeCgroupLocked(token)
	w.mu.Unlock()
	if !removed {
		return
	}
	w.logger.Info().Str("cgroup", token.target).Msg("cgroup removed")
	w.enqueueRemoval(token)
}

func (w *TargetWatcher) enqueueRemoval(token watchToken) {
	w.pendingMu.Lock()
	w.pending = append(w.pending, token)
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
		token := w.pending[0]
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
		w.onRemoved(token)
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
