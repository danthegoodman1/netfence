package daemon

import (
	"net"
	"sync"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

// ruleList identifies which filter list a TTL-tracked entry lives in.
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
// differently collapse to one key.
type ttlKey struct {
	cidr string
	list ruleList
}

type ttlEntry struct {
	cidr      *net.IPNet
	expiresAt time.Time
}

// ttlRegistry tracks expiry deadlines for one attachment's CIDR filter
// entries and serializes that attachment's CIDR-rule mutations: every
// add/remove/clear/expire routes through a method that holds r.mu across
// BOTH the eBPF filter call and the bookkeeping update. That makes "a
// concurrent re-add wins over an in-flight expiry" trivially true — the
// janitor's expire pass and a control-plane (re-)add can never interleave
// between the kernel map write and the registry write.
//
// Locking: r.mu is a leaf lock. Callers snapshot the *ttlRegistry and
// filter.Filter under Server.mu, release Server.mu, and only then lock r.mu;
// no registry method acquires any other lock. So there is no lock-ordering
// cycle and Server.mu is never held during a filter syscall from these
// paths. The filter operations held under r.mu are single BPF map syscalls;
// contention is confined to one attachment's rule mutations, never the
// packet path (the datapath reads kernel maps directly).
//
// Phase 2B seam: entries are keyed by (cidr, list) with an absolute
// deadline and carry no notion of where the rule came from. DNS-populated
// /32s can be upserted through the same add() with a deadline derived from
// the DNS TTL and swept by the same janitor.
type ttlRegistry struct {
	mu      sync.Mutex
	entries map[ttlKey]ttlEntry
}

func newTTLRegistry() *ttlRegistry {
	return &ttlRegistry{entries: make(map[ttlKey]ttlEntry)}
}

// add inserts the CIDR into the given filter list and records its expiry.
// ttl <= 0 means permanent: the entry is added to the filter and any prior
// deadline for the same (cidr, list) is dropped, so re-adding without a TTL
// makes a previously-TTL'd entry permanent again. Re-adding with a TTL
// replaces the previous deadline (upsert).
func (r *ttlRegistry) add(f filter.Filter, cidr *net.IPNet, list ruleList, ttl time.Duration, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if f != nil {
		var err error
		if list == listAllow {
			err = f.AllowIP(cidr)
		} else {
			err = f.DenyIP(cidr)
		}
		if err != nil {
			return err
		}
	}

	key := ttlKey{cidr: cidr.String(), list: list}
	if ttl <= 0 {
		delete(r.entries, key)
		return nil
	}
	r.entries[key] = ttlEntry{cidr: cidr, expiresAt: now.Add(ttl)}
	return nil
}

// remove deletes the CIDR from the given filter list and purges its deadline
// so the janitor never "expires" an entry that was explicitly removed (and
// possibly re-added as permanent) in the meantime. Mirroring expire()'s
// fail-safe philosophy, the deadline is only dropped after the filter
// removal succeeds: if the rule is still in the kernel map, keeping the
// bookkeeping lets the janitor retry the removal instead of leaving a TTL'd
// entry unremovable (fail-open for allow entries). Filter removes are
// idempotent, so a not-present key is a success, not an error.
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

// clear wipes all filter rules and all tracked deadlines atomically with
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

// purge drops all tracked deadlines without touching the filter. Used when
// an attachment is detached or its target removed: the filter is being
// closed wholesale, and an in-flight janitor sweep holding a stale snapshot
// must not keep retrying removals against the closed filter.
func (r *ttlRegistry) purge() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[ttlKey]ttlEntry)
}

// len reports the number of tracked (non-permanent) entries.
func (r *ttlRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// sweptEntry reports one expiry processed (or attempted) by expire.
type sweptEntry struct {
	cidr string
	list ruleList
	err  error
}

// expire removes every entry whose deadline has passed from both the filter
// and the registry. On a filter removal error the entry is KEPT for retry on
// the next sweep: failing to remove an expired allow entry is fail-open, so
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
		if entry.expiresAt.After(now) {
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
