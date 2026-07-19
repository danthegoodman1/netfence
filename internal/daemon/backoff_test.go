package daemon

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// midJitter is a deterministic jitter source that always returns 0.5, which
// makes the jitter factor exactly 1.0 — next() then returns the un-jittered
// base delay, so the exponential schedule can be asserted exactly.
func midJitter() float64 { return 0.5 }

func TestReconnectBackoffStartsAtFloorDoublesAndCaps(t *testing.T) {
	b := newReconnectBackoff(time.Second, 30*time.Second, midJitter)

	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second, // 32s capped to the max
		30 * time.Second, // stays at the cap
		30 * time.Second,
	}
	for i, w := range want {
		require.Equal(t, w, b.next(), "delay #%d", i)
	}
}

func TestReconnectBackoffJitterStaysWithinBounds(t *testing.T) {
	// A seeded PRNG keeps the test deterministic while still exercising
	// the full jitter range.
	rng := rand.New(rand.NewPCG(1, 2))
	b := newReconnectBackoff(time.Second, 30*time.Second, rng.Float64)

	base := time.Second
	for i := 0; i < 50; i++ {
		d := b.next()
		lo := time.Duration(float64(base) * (1 - backoffJitterFraction))
		hi := time.Duration(float64(base) * (1 + backoffJitterFraction))
		require.GreaterOrEqual(t, d, lo, "delay #%d below jitter lower bound", i)
		require.LessOrEqual(t, d, hi, "delay #%d above jitter upper bound", i)
		require.Positive(t, d, "delay #%d must be positive", i)
		if base *= 2; base > 30*time.Second {
			base = 30 * time.Second
		}
	}
}

func TestReconnectBackoffExtremeJitterNeverNonPositive(t *testing.T) {
	// rnd()==0 is the worst case (factor 1-backoffJitterFraction); even
	// with a pathological 1ns floor the delay must stay positive so Run
	// can never hot-loop.
	b := newReconnectBackoff(time.Nanosecond, time.Nanosecond, func() float64 { return 0 })
	for i := 0; i < 10; i++ {
		require.Positive(t, b.next(), "delay #%d", i)
	}
}

func TestReconnectBackoffResetsAfterHealthyConnection(t *testing.T) {
	b := newReconnectBackoff(time.Second, 30*time.Second, midJitter)

	// Escalate to the cap.
	for i := 0; i < 8; i++ {
		b.next()
	}
	require.Equal(t, 30*time.Second, b.next())

	// A connection that stayed CONNECTED for the healthy age resets the
	// schedule to the floor.
	now := time.Now()
	b.noteOutcome(now.Add(-cpConnectionHealthyAge), now)
	require.Equal(t, time.Second, b.next(), "backoff should restart at the floor after a healthy connection")
	require.Equal(t, 2*time.Second, b.next(), "and double again from there")
}

func TestReconnectBackoffDoesNotResetOnUnhealthyOutcome(t *testing.T) {
	b := newReconnectBackoff(time.Second, 30*time.Second, midJitter)
	for i := 0; i < 8; i++ {
		b.next()
	}

	now := time.Now()
	// Never connected at all (dial failure): no reset.
	b.noteOutcome(time.Time{}, now)
	require.Equal(t, 30*time.Second, b.next(), "dial failure must not reset the backoff")

	// Connected but died almost immediately: no reset (would thrash at
	// the floor against a flapping control plane).
	b.noteOutcome(now.Add(-cpConnectionHealthyAge/2), now)
	require.Equal(t, 30*time.Second, b.next(), "instantly-dying connection must not reset the backoff")
}

func TestReconnectBackoffDefaultsForZeroInputs(t *testing.T) {
	// Zero floor/max mean "use the defaults", never "no delay" — the same
	// convention as the config knobs.
	b := newReconnectBackoff(0, 0, midJitter)
	require.Equal(t, reconnectBackoffFloor, b.next())
	last := time.Duration(0)
	for i := 0; i < 10; i++ {
		last = b.next()
	}
	require.Equal(t, defaultReconnectBackoffMax, last)

	// A cap below the floor is raised to the floor.
	b = newReconnectBackoff(5*time.Second, time.Second, midJitter)
	require.Equal(t, 5*time.Second, b.next())
	require.Equal(t, 5*time.Second, b.next())
}
