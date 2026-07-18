package daemon

import (
	"errors"
	"fmt"
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

// ruleSource identifies which independent source contributed a filter entry.
type ruleSource int

const (
	// sourceCP is a control-plane CIDR rule (AllowCidr/DenyCidr commands,
	// SubscribedAck, BulkUpdate).
	sourceCP ruleSource = iota
	// sourceDNS is a DNS-resolved IP added through the DNSFilterSink.
	sourceDNS
)

// ttlKey identifies one tracked filter entry. cidr is the canonical (masked)
// string form produced by (*net.IPNet).String(), so equal networks written
// differently — including a control-plane CIDR and a DNS-resolved /32 for
// the same address — collapse to one key.
type ttlKey struct {
	cidr string
	list ruleList
}

// ttlEntry is one filter entry with its per-source lifetimes. Each source is
// independent: the entry stays in the filter while ANY source is live, and
// its effective deadline is the max over live sources (a permanent CP source
// counts as infinite).
type ttlEntry struct {
	cidr *net.IPNet

	// cpLive reports whether a control-plane rule currently wants this
	// entry. While cpLive, cpDeadline zero means the CP rule is permanent;
	// otherwise it expires at cpDeadline.
	cpLive     bool
	cpDeadline time.Time

	// dnsLive reports whether a DNS resolution currently wants this entry;
	// dnsDeadline (always finite) is when that claim lapses.
	dnsLive     bool
	dnsDeadline time.Time

	// inFilter records whether the entry was successfully written to the
	// eBPF filter, so repeated adds (e.g. every DNS query for a cached
	// domain) skip the redundant map syscall. It stays false while the
	// attachment has no filter yet (restore window, !linux stub) so the
	// first add after the filter exists writes through.
	inFilter bool
}

// cpPermanent reports whether the entry is pinned by a permanent CP rule.
func (e ttlEntry) cpPermanent() bool {
	return e.cpLive && e.cpDeadline.IsZero()
}

// ttlRegistry tracks every CIDR entry the daemon has added to one
// attachment's filter — control-plane rules and DNS-resolved IPs alike —
// with an independent lifetime per source (see ttlEntry), and serializes
// that attachment's CIDR-rule mutations: every add/remove/reconcile/clear/
// expire routes through a method that holds r.mu across BOTH the eBPF
// filter call and the bookkeeping update. That makes "a concurrent re-add
// wins over an in-flight expiry" trivially true — the janitor's expire pass
// and an add can never interleave between the kernel map write and the
// registry write.
//
// Lifetime model (per-source max-deadline / permanent-pin): a CP add with
// ttl <= 0 pins the CP source permanent; a CP add with ttl > 0 extends the
// CP deadline to max(existing, now+ttl) and never demotes a permanent CP
// source; a DNS add extends the DNS deadline the same way. The entry lives
// while ANY source is live, so it lives as long as the longest-lived source
// that wants it: a permanent control-plane allow aliasing a DNS-resolved
// /32 is never removed when the DNS TTL lapses, while a DNS-only /32
// expires on schedule. The source split is what lets BulkUpdate reconcile
// the control-plane rule set as a delta (reconcileCP): entries with a live
// CP source ARE the current CP-declared set, and dropping a CIDR from that
// set clears only the CP source — a live DNS source keeps the entry in the
// filter until its own TTL lapses.
//
// Explicit remove() and clear() are outright (operator/resync actions) and
// drop the entry regardless of sources; a DNS-populated entry self-heals on
// the next resolution.
//
// Locking: r.mu is a leaf lock. Callers snapshot the *ttlRegistry and
// filter.Filter under Server.mu, release Server.mu, and only then lock r.mu;
// no registry method acquires any other lock. So there is no lock-ordering
// cycle and Server.mu is never held during a filter syscall from these
// paths. The filter operations held under r.mu are single BPF map syscalls
// (reconcileCP holds it across one bulk update's worth), and contention is
// confined to one attachment's rule mutations, never the packet path (the
// datapath reads kernel maps directly).
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

// addCP records a control-plane rule for the CIDR: ttl <= 0 pins the CP
// source permanent (never demoted by a later TTL'd re-add); ttl > 0 extends
// the CP deadline to max(existing, now+ttl), never shortening it. Use
// remove() to drop an entry early.
func (r *ttlRegistry) addCP(f filter.Filter, cidr *net.IPNet, list ruleList, ttl time.Duration, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addSourceLocked(f, cidr, list, sourceCP, ttl, now)
}

// addDNS records a DNS-resolution claim on the CIDR, extending the DNS
// deadline to max(existing, now+ttl). It never touches the CP source.
func (r *ttlRegistry) addDNS(f filter.Filter, cidr *net.IPNet, list ruleList, ttl time.Duration, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addSourceLocked(f, cidr, list, sourceDNS, ttl, now)
}

// addSourceLocked updates one source's lifetime on the entry and writes the
// CIDR to the filter if it is not already there. On a filter write error
// nothing is recorded (an existing entry keeps its previous lifetimes) and
// map-full failures are counted. Callers hold r.mu.
func (r *ttlRegistry) addSourceLocked(f filter.Filter, cidr *net.IPNet, list ruleList, src ruleSource, ttl time.Duration, now time.Time) error {
	key := ttlKey{cidr: cidr.String(), list: list}
	entry, exists := r.entries[key]
	if !exists {
		entry = ttlEntry{cidr: cidr}
	}

	switch src {
	case sourceCP:
		if ttl <= 0 {
			entry.cpLive, entry.cpDeadline = true, time.Time{}
		} else if !entry.cpPermanent() {
			deadline := now.Add(ttl)
			if !entry.cpLive || entry.cpDeadline.Before(deadline) {
				entry.cpDeadline = deadline
			}
			entry.cpLive = true
		}
	case sourceDNS:
		deadline := now.Add(ttl)
		if !entry.dnsLive || entry.dnsDeadline.Before(deadline) {
			entry.dnsLive, entry.dnsDeadline = true, deadline
		}
	}

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
			// Leave any existing entry untouched: its previous lifetimes are
			// still accurate, and the failed extension must not be recorded.
			return err
		}
		entry.inFilter = true
	}

	r.entries[key] = entry
	return nil
}

// reconcileCP applies a declared control-plane rule set for one list as a
// delta against the entries with a live CP source (which ARE the current
// CP-declared set):
//   - declared CIDRs are (re-)added through addSourceLocked, so a CIDR in
//     both the old and new set is NEVER removed from the kernel map — no
//     transient allow/block window;
//   - entries whose CP source is no longer declared lose ONLY that source:
//     a live DNS source keeps them in the filter until its own TTL lapses,
//     and only source-less entries are removed from the filter.
//
// The whole reconcile holds r.mu, so concurrent DNS adds and janitor sweeps
// serialize around it and can never observe a half-applied update.
func (r *ttlRegistry) reconcileCP(f filter.Filter, list ruleList, desired []parsedCIDR, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	desiredSet := make(map[string]struct{}, len(desired))
	for _, d := range desired {
		desiredSet[d.cidr.String()] = struct{}{}
		if err := r.addSourceLocked(f, d.cidr, list, sourceCP, d.ttl, now); err != nil {
			errs = append(errs, fmt.Errorf("adding %s: %w", d.cidr, err))
		}
	}

	for key, entry := range r.entries {
		if key.list != list || !entry.cpLive {
			continue
		}
		if _, ok := desiredSet[key.cidr]; ok {
			continue
		}
		entry.cpLive, entry.cpDeadline = false, time.Time{}
		if entry.dnsLive && entry.dnsDeadline.After(now) {
			// DNS still wants it: keep the filter entry, drop only the CP
			// source. It ages out via its DNS deadline.
			r.entries[key] = entry
			continue
		}
		var err error
		if f != nil {
			if list == listAllow {
				err = f.RemoveAllowedIP(entry.cidr)
			} else {
				err = f.RemoveDeniedIP(entry.cidr)
			}
		}
		if err != nil {
			// Keep the source-less entry so the janitor retries the removal
			// (mirrors expire()'s fail-safe).
			errs = append(errs, fmt.Errorf("removing %s: %w", key.cidr, err))
			r.entries[key] = entry
			continue
		}
		delete(r.entries, key)
	}

	return errors.Join(errs...)
}

// remove deletes the CIDR from the given filter list and purges the whole
// entry (all sources) so the janitor never "expires" an entry that was
// explicitly removed (and possibly re-added as permanent) in the meantime.
// Mirroring expire()'s fail-safe philosophy, the bookkeeping is only
// dropped after the filter removal succeeds: if the rule is still in the
// kernel map, keeping the entry lets the janitor retry the removal instead
// of leaving a TTL'd entry unremovable (fail-open for allow entries).
// Filter removes are idempotent, so a not-present key is a success, not an
// error.
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

// len reports the total number of tracked entries.
func (r *ttlRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// pendingLen reports the number of entries the janitor could eventually act
// on: everything except entries pinned by a permanent CP source.
func (r *ttlRegistry) pendingLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, entry := range r.entries {
		if !entry.cpPermanent() {
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

// sweptEntry reports one entry removal processed (or attempted) by expire.
type sweptEntry struct {
	cidr string
	list ruleList
	err  error
}

// expire ages each entry's sources independently and removes an entry from
// both the filter and the registry only when NO source remains live. A
// permanent CP source is never expired; a lapsed DNS source on a CP-pinned
// entry only drops the DNS bookkeeping. On a filter removal error the
// (source-less) entry is KEPT for retry on the next sweep: failing to
// remove an expired allow entry is fail-open, so silently dropping the
// bookkeeping is the wrong direction. (Detach purges the registry, so a
// closed filter cannot cause an endless retry loop.)
func (r *ttlRegistry) expire(f filter.Filter, now time.Time) []sweptEntry {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var swept []sweptEntry
	for key, entry := range r.entries {
		changed := false
		if entry.cpLive && !entry.cpDeadline.IsZero() && !entry.cpDeadline.After(now) {
			entry.cpLive, entry.cpDeadline = false, time.Time{}
			changed = true
		}
		if entry.dnsLive && !entry.dnsDeadline.After(now) {
			entry.dnsLive, entry.dnsDeadline = false, time.Time{}
			changed = true
		}
		if entry.cpLive || entry.dnsLive {
			if changed {
				r.entries[key] = entry
			}
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
		} else {
			r.entries[key] = entry
		}
		swept = append(swept, sweptEntry{cidr: key.cidr, list: key.list, err: err})
	}
	return swept
}
