//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TargetWatcher struct {
	logger    zerolog.Logger
	onRemoved func(target string)

	mu             sync.RWMutex
	interfaces     map[string]struct{} // interface name -> watched
	cgroups        map[string]struct{} // cgroup path -> watched
	cgroupWatchers map[string]*fsnotify.Watcher

	done     chan struct{}
	wg       sync.WaitGroup
	nlDoneCh chan struct{}
}

func NewTargetWatcher(logger zerolog.Logger, onRemoved func(target string)) *TargetWatcher {
	return &TargetWatcher{
		logger:         logger.With().Str("component", "watcher").Logger(),
		onRemoved:      onRemoved,
		interfaces:     make(map[string]struct{}),
		cgroups:        make(map[string]struct{}),
		cgroupWatchers: make(map[string]*fsnotify.Watcher),
		done:           make(chan struct{}),
		nlDoneCh:       make(chan struct{}),
	}
}

func (w *TargetWatcher) Start() error {
	w.wg.Add(1)
	go w.watchInterfaces()
	return nil
}

func (w *TargetWatcher) Stop() {
	close(w.done)

	w.mu.Lock()
	for _, watcher := range w.cgroupWatchers {
		watcher.Close()
	}
	w.mu.Unlock()

	<-w.nlDoneCh
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

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Watch the parent directory so we can detect when the cgroup is removed
	parentDir := filepath.Dir(path)
	if err := watcher.Add(parentDir); err != nil {
		watcher.Close()
		return err
	}

	w.cgroups[path] = struct{}{}
	w.cgroupWatchers[path] = watcher

	w.wg.Add(1)
	go w.watchCgroupPath(path, watcher)

	w.logger.Debug().Str("cgroup", path).Msg("watching cgroup")
	return nil
}

func (w *TargetWatcher) UnwatchCgroup(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if watcher, ok := w.cgroupWatchers[path]; ok {
		watcher.Close()
		delete(w.cgroupWatchers, path)
	}
	delete(w.cgroups, path)
	w.logger.Debug().Str("cgroup", path).Msg("unwatching cgroup")
}

func (w *TargetWatcher) watchInterfaces() {
	defer w.wg.Done()
	defer close(w.nlDoneCh)

	updates := make(chan netlink.LinkUpdate)
	done := make(chan struct{})

	if err := netlink.LinkSubscribe(updates, done); err != nil {
		w.logger.Error().Err(err).Msg("failed to subscribe to netlink link updates")
		return
	}

	for {
		select {
		case <-w.done:
			close(done)
			return
		case update := <-updates:
			// RTM_DELLINK indicates an interface was removed
			if update.Header.Type == unix.RTM_DELLINK {
				name := update.Attrs().Name
				w.mu.RLock()
				_, watched := w.interfaces[name]
				w.mu.RUnlock()

				if watched {
					w.logger.Info().Str("interface", name).Msg("interface removed")
					w.onRemoved(name)
				}
			}
		}
	}
}

func (w *TargetWatcher) watchCgroupPath(path string, watcher *fsnotify.Watcher) {
	defer w.wg.Done()

	baseName := filepath.Base(path)

	for {
		select {
		case <-w.done:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Check if our specific cgroup was removed
			if event.Op&fsnotify.Remove == fsnotify.Remove {
				if filepath.Base(event.Name) == baseName {
					// Verify it's actually gone (not just renamed)
					if _, err := os.Stat(path); os.IsNotExist(err) {
						w.logger.Info().Str("cgroup", path).Msg("cgroup removed")
						w.onRemoved(path)
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			w.logger.Warn().Err(err).Str("cgroup", path).Msg("cgroup watcher error")
		}
	}
}
