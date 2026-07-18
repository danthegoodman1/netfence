//go:build !linux

package daemon

import (
	"sync/atomic"

	"github.com/rs/zerolog"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type TargetWatcher struct {
	nextGeneration atomic.Uint64
}

func NewTargetWatcher(_ zerolog.Logger, _ func(watchToken)) *TargetWatcher {
	return &TargetWatcher{}
}

func (w *TargetWatcher) setTargetIdentityResolver(_ func(apiv1.AttachmentType, string) (uint64, error)) {
}

func (w *TargetWatcher) Start() error { return nil }
func (w *TargetWatcher) Stop()        {}
func (w *TargetWatcher) WatchInterface(target string, identity uint64) (watchToken, error) {
	return watchToken{generation: w.nextGeneration.Add(1), target: target, kind: watchKindInterface, identity: identity}, nil
}
func (w *TargetWatcher) UnwatchInterface(_ watchToken) {}
func (w *TargetWatcher) WatchCgroup(target string, identity uint64) (watchToken, error) {
	return watchToken{generation: w.nextGeneration.Add(1), target: target, kind: watchKindCgroup, identity: identity}, nil
}
func (w *TargetWatcher) UnwatchCgroup(_ watchToken) {}
