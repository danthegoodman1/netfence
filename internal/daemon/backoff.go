package daemon

import (
	"math/rand/v2"
	"time"
)

const (
	// reconnectBackoffFloor is the first (and post-reset) control-plane
	// reconnect delay. Kept as an in-code constant; only the cap is
	// configurable (control_plane.reconnect_backoff_max).
	reconnectBackoffFloor = time.Second

	// defaultReconnectBackoffMax caps the exponential reconnect schedule
	// when control_plane.reconnect_backoff_max is zero/unset.
	defaultReconnectBackoffMax = 30 * time.Second

	// backoffJitterFraction spreads each reconnect delay by ±20% so a fleet
	// of daemons that lost the same control plane at the same moment does
	// not reconnect in lockstep.
	backoffJitterFraction = 0.2

	// cpConnectionHealthyAge is how long a connection must have stayed
	// CONNECTED for the reconnect backoff to reset to the floor. A
	// connection that dies instantly keeps escalating instead of thrashing
	// at the floor (mirrors nlSubscriptionHealthyAge in watcher.go).
	cpConnectionHealthyAge = 30 * time.Second
)

// reconnectBackoff computes jittered, capped exponential delays between
// control-plane reconnect attempts: floor, 2×floor, 4×floor, … up to max,
// each spread by ±backoffJitterFraction. The schedule resets to the floor
// only after a connection proved healthy (see noteOutcome).
type reconnectBackoff struct {
	floor time.Duration // base of the schedule (first and post-reset delay)
	max   time.Duration // cap on the un-jittered base delay
	cur   time.Duration // next un-jittered base delay
	// rnd is the jitter source, returning values in [0, 1). Injected by
	// tests for determinism; production uses rand.Float64.
	rnd func() float64
}

// newReconnectBackoff builds a schedule from floor to max. Non-positive
// inputs fall back to the defaults (zero configures nothing off, matching
// the config convention); a max below the floor is raised to it. A nil rnd
// uses math/rand/v2.
func newReconnectBackoff(floor, max time.Duration, rnd func() float64) *reconnectBackoff {
	if floor <= 0 {
		floor = reconnectBackoffFloor
	}
	if max <= 0 {
		max = defaultReconnectBackoffMax
	}
	if max < floor {
		max = floor
	}
	if rnd == nil {
		rnd = rand.Float64
	}
	return &reconnectBackoff{floor: floor, max: max, cur: floor, rnd: rnd}
}

// next returns the delay to wait before the next reconnect attempt and
// advances the schedule (doubling the base toward the cap). The returned
// delay is the current base spread by ±backoffJitterFraction and is always
// positive.
func (b *reconnectBackoff) next() time.Duration {
	base := b.cur
	b.cur *= 2
	if b.cur > b.max {
		b.cur = b.max
	}
	// factor is in [1-backoffJitterFraction, 1+backoffJitterFraction).
	factor := 1 + backoffJitterFraction*(2*b.rnd()-1)
	d := time.Duration(float64(base) * factor)
	if d <= 0 {
		// Unreachable with a sane floor; guard against a pathological
		// floor rounding to zero so the caller can never hot-loop.
		d = time.Millisecond
	}
	return d
}

// noteOutcome records how the last connection attempt ended: connectedAt is
// when it reached CONNECTED (zero if it never did) and now is the time it
// ended. Only a connection that stayed up at least cpConnectionHealthyAge
// resets the schedule to the floor — a dial failure or an instantly-dying
// connection keeps escalating.
func (b *reconnectBackoff) noteOutcome(connectedAt, now time.Time) {
	if !connectedAt.IsZero() && now.Sub(connectedAt) >= cpConnectionHealthyAge {
		b.cur = b.floor
	}
}
