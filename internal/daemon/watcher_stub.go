//go:build !linux

package daemon

import "github.com/rs/zerolog"

type TargetWatcher struct{}

func NewTargetWatcher(_ zerolog.Logger, _ func(target string)) *TargetWatcher {
	return &TargetWatcher{}
}

func (w *TargetWatcher) Start() error               { return nil }
func (w *TargetWatcher) Stop()                      {}
func (w *TargetWatcher) WatchInterface(_ string)    {}
func (w *TargetWatcher) UnwatchInterface(_ string)  {}
func (w *TargetWatcher) WatchCgroup(_ string) error { return nil }
func (w *TargetWatcher) UnwatchCgroup(_ string)     {}
