package daemon

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

// ruleList identifies which filter list a tracked entry lives in.
type ruleList int

const (
	listAllow ruleList = iota
	listDeny
)

func (l ruleList) String() string {
	if l == listAllow {
		return "allow"
	}
	return "deny"
}

// ttlKey identifies one tracked filter entry. cidr is the canonical (masked)
// string form produced by (*net.IPNet).String(), so equal networks written
// differently — including a control-plane CIDR and a DNS-resolved /32 for
// the same address — collapse to one key.
type ttlKey struct {
	cidr string
	list ruleList
}

type ttlEntry struct {
	cidr *net.IPNet
	// expiresAt is the entry's deadline. The zero time means permanent:
	// the entry never expires (permanent pin).
	expiresAt time.Time
	// inFilter records whether the entry was successfully written to the
	// eBPF filter, so repeated adds (e.g. every DNS query for a cached
	// domain) skip the redundant map syscall. It stays false while the
	// attachment has no filter yet (restore window, !linux stub) so the
	// first add after the filter exists writes through.
	inFilter bool
}

// ttlRegistry tracks every CIDR entry the daemon has added to one
// attachment's filter — control-plane rules and DNS-resolved IPs alike —
// with an expiry deadline per (cidr, list), and serializes that attachment's
// CIDR-rule mutations: every add/remove/clear/expire routes through a method
// that holds r.mu across BOTH the eBPF filter call and the bookkeeping
// update. That makes "a concurrent re-add wins over an in-flight expiry"
// trivially true — the janitor's expire pass and an add can never interleave
// between the kernel map write and the registry write.
//
// Lifetime model (max-deadline / permanent-pin): an add with ttl <= 0 pins
// the entry permanent; an add with ttl > 0 sets deadline =
// max(existing deadline, now+ttl), and a permanent entry stays permanent.
// So an entry lives as long as the longest-lived source that wants it: a
// permanent control-plane allow aliasing a DNS-resolved /32 is never removed
// when the DNS TTL lapses, while a DNS-only /32 expires on schedule.
// Explicit remove() and clear() are outright (operator/resync actions) and
// drop the entry regardless of pins; a DNS-populated entry self-heals on the
// next resolution.
//
// Locking: r.mu is a leaf lock. Callers snapshot the *ttlRegistry and
// filter.Filter under Server.mu, release Server.mu, and only then lock r.mu;
// no registry method acquires any other lock. So there is no lock-ordering
// cycle and Server.mu is never held during a filter syscall from these
// paths. The filter operations held under r.mu are single BPF map syscalls;
// contention is confined to one attachment's rule mutations, never the
// packet path (the datapath reads kernel maps directly).
//
// Phase 2C seam: because every daemon-side add routes through here, the
// registry doubles as the userspace record of intended filter contents,
// which a diff-apply BulkUpdate can compare against.
type ttlRegistry struct {
	mu      sync.Mutex
	entries map[ttlKey]ttlEntry

	// mapFullDrops counts adds dropped because the filter's rule map was at
	// capacity. Cumulative; surfaced via AttachmentStats.map_full_drops.
	mapFullDrops atomic.Uint64
}

func newTTLRegistry() *ttlRegistry {
	return &ttlRegistry{entries: make(map[ttlKey]ttlEntry)}
}

// isMapFull reports whether a filter insert failed because the underlying
// BPF map is at capacity. LPM tries return ENOSPC; hash-style maps E2BIG.
func isMapFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.E2BIG)
}

// add inserts the CIDR into the given filter list and records its lifetime
// under the max-deadline / permanent-pin model (see type comment):
//   - ttl <= 0 pins the entry permanent (clears any deadline).
//   - ttl > 0 extends the deadline to max(existing, now+ttl); it never
//     shortens one and never unpins a permanent entry. Use remove() to drop
//     an entry early.
//
// The kernel map write is skipped when the entry is already known to be in
// the filter, so repeated DNS resolutions of a cached IP cost no syscall.
func (r *ttlRegistry) add(f filter.Filter, cidr *net.IPNet, list ruleList, ttl time.Duration, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ttlKey{cidr: cidr.String(), list: list}
	existing, exists := r.entries[key]

	entry := ttlEntry{cidr: cidr, inFilter: existing.inFilter}
	if ttl > 0 {
		entry.expiresAt = now.Add(ttl)
		if exists {
			if existing.expiresAt.IsZero() {
				// Permanent pin wins: stays permanent.
				entry.expiresAt = time.Time{}
			} else if existing.expiresAt.After(entry.expiresAt) {
				entry.expiresAt = existing.expiresAt
			}
		}
	}
	// ttl <= 0: entry.expiresAt stays zero — permanent pin.

	if f != nil && !entry.inFilter {
		var err error
		if list == listAllow {
			err = f.AllowIP(cidr)
		} else {
			err = f.DenyIP(cidr)
		}
		if err != nil {
			if isMapFull(err) {
				r.mapFullDrops.Add(1)
			}
			// Leave any existing entry untouched: its previous lifetime is
			// still accurate, and the failed extension must not be recorded.
			return err
		}
		entry.inFilter = true
	}

	r.entries[key] = entry
	return nil
}

// remove deletes the CIDR from the given filter list and purges its deadline
// so the janitor never "expires" an entry that was explicitly removed (and
// possibly re-added as permanent) in the meantime. Mirroring expire()'s
// fail-safe philosophy, the bookkeeping is only dropped after the filter
// removal succeeds: if the rule is still in the kernel map, keeping the
// entry lets the janitor retry the removal instead of leaving a TTL'd entry
// unremovable (fail-open for allow entries). Filter removes are idempotent,
// so a not-present key is a success, not an error.
func (r *ttlRegistry) remove(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if f != nil {
		var err error
		if list == listAllow {
			err = f.RemoveAllowedIP(cidr)
		} else {
			err = f.RemoveDeniedIP(cidr)
		}
		if err != nil {
			return err
		}
	}
	delete(r.entries, ttlKey{cidr: cidr.String(), list: list})
	return nil
}

// clear wipes all filter rules and all tracked entries atomically with
// respect to concurrent adds and janitor sweeps.
func (r *ttlRegistry) clear(f filter.Filter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = make(map[ttlKey]ttlEntry)
	if f == nil {
		return nil
	}
	return f.ClearRules()
}

// purge drops all tracked entries without touching the filter. Used when an
// attachment is detached or its target removed: the filter is being closed
// wholesale, and an in-flight janitor sweep holding a stale snapshot must
// not keep retrying removals against the closed filter.
func (r *ttlRegistry) purge() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[ttlKey]ttlEntry)
}

// len reports the total number of tracked entries (permanent and TTL'd).
func (r *ttlRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// pendingLen reports the number of entries with a finite deadline, i.e.
// those the janitor will eventually expire.
func (r *ttlRegistry) pendingLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, entry := range r.entries {
		if !entry.expiresAt.IsZero() {
			n++
		}
	}
	return n
}

// mapFullCount returns the cumulative number of adds dropped because the
// filter's rule map was full.
func (r *ttlRegistry) mapFullCount() uint64 {
	if r == nil {
		return 0
	}
	return r.mapFullDrops.Load()
}

// sweptEntry reports one expiry processed (or attempted) by expire.
type sweptEntry struct {
	cidr string
	list ruleList
	err  error
}

// expire removes every entry whose finite deadline has passed from both the
// filter and the registry. Permanent (zero-deadline) entries are never
// touched. On a filter removal error the entry is KEPT for retry on the
// next sweep: failing to remove an expired allow entry is fail-open, so
// silently dropping the bookkeeping is the wrong direction. (Detach purges
// the registry, so a closed filter cannot cause an endless retry loop.)
func (r *ttlRegistry) expire(f filter.Filter, now time.Time) []sweptEntry {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var swept []sweptEntry
	for key, entry := range r.entries {
		if entry.expiresAt.IsZero() || entry.expiresAt.After(now) {
			continue
		}
		var err error
		if f != nil {
			if key.list == listAllow {
				err = f.RemoveAllowedIP(entry.cidr)
			} else {
				err = f.RemoveDeniedIP(entry.cidr)
			}
		}
		if err == nil {
			delete(r.entries, key)
		}
		swept = append(swept, sweptEntry{cidr: key.cidr, list: key.list, err: err})
	}
	return swept
}
