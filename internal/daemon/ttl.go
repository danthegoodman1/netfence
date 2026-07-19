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
	// sourceSystem is daemon-owned attachment infrastructure. Today it is the
	// concrete host route for the attachment's DNS listener. It is permanent
	// for the attachment lifetime and is deliberately outside authoritative
	// control-plane state and regenerable DNS-derived ownership.
	sourceSystem
)

// ttlKey identifies one tracked filter entry. cidr is the canonical (masked)
// string form produced by (*net.IPNet).String(), so equal control-plane
// networks written differently collapse to one key.
type ttlKey struct {
	cidr string
	list ruleList
}

// ttlEntry is one authoritative/system LPM entry. A system owner pins it for
// the attachment lifetime; otherwise the control-plane lifetime determines
// expiry.
type ttlEntry struct {
	cidr *net.IPNet

	// systemLive pins daemon-owned attachment infrastructure. Control-plane
	// reconciliation/removal, TTL expiry, and rule clears must preserve it.
	systemLive bool

	// cpLive reports whether a control-plane rule currently wants this
	// entry. While cpLive, cpDeadline zero means the CP rule is permanent;
	// otherwise it expires at cpDeadline.
	cpLive     bool
	cpDeadline time.Time

	// inFilter records whether the entry was successfully written to the
	// eBPF filter, so repeated CP/system adds skip the redundant map syscall.
	// It stays false while the
	// attachment has no filter yet (restore window, !linux stub) so the
	// first add after the filter exists writes through.
	inFilter bool
}

// cpPermanent reports whether the entry is pinned by a permanent CP rule.
func (e ttlEntry) cpPermanent() bool {
	return e.cpLive && e.cpDeadline.IsZero()
}

// ttlRegistry is the single owner of authoritative control-plane and
// daemon-system LPM bookkeeping. DNS-derived host allows deliberately do not
// enter this registry; dnsOwnershipManager owns their separate exact HASH
// tier, TTLs, query/policy edges, and prompt removal.
//
// Every LPM add/remove/reconcile/clear/expire holds r.mu across both the eBPF
// syscall and bookkeeping update, so a concurrent re-add cannot interleave
// with expiry. A CP add with ttl <= 0 is permanent; a positive TTL extends the
// deadline monotonically. Authoritative reconcile may replace that lifetime
// exactly. Explicit remove() and clear() drop CP ownership while retaining
// daemon-owned system entries.
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

// addSystem installs a permanent daemon-owned entry. It is used for
// attachment infrastructure that must remain reachable independently of
// authoritative control-plane desired state and DNS-derived admission.
func (r *ttlRegistry) addSystem(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addSourceLocked(f, cidr, list, sourceSystem, 0, time.Time{})
}

// removeSystem rolls back this daemon generation's system claim. Independent
// CP aliases survive; the physical entry is removed only when system was its
// sole owner. On removal failure the source-less entry remains for retry.
func (r *ttlRegistry) removeSystem(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := ttlKey{cidr: cidr.String(), list: list}
	entry, ok := r.entries[key]
	if !ok || !entry.systemLive {
		return nil
	}
	entry.systemLive = false
	if entry.cpLive {
		r.entries[key] = entry
		return nil
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
		r.entries[key] = entry
		return err
	}
	delete(r.entries, key)
	return nil
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
	case sourceSystem:
		entry.systemLive = true
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
//   - declared CIDRs replace the CP source lifetime exactly (a full desired
//     state may shorten a TTL or demote a previously-permanent restored rule)
//     while a CIDR in both old and new sets is NEVER removed/re-added in the
//     kernel map — no transient allow/block window;
//   - entries whose CP source is no longer declared are removed unless a
//     daemon-system owner pins them.
//
// The whole reconcile holds r.mu, so concurrent CP adds and janitor sweeps
// serialize around it and can never observe a half-applied update.
func (r *ttlRegistry) reconcileCP(f filter.Filter, list ruleList, desired []parsedCIDR, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	desiredSet := make(map[string]struct{}, len(desired))
	for _, d := range desired {
		desiredSet[d.cidr.String()] = struct{}{}
		if err := r.replaceCPSourceLocked(f, d.cidr, list, d.ttl, now); err != nil {
			errs = append(errs, fmt.Errorf("adding %s: %w", d.cidr, err))
		}
	}

	for key, entry := range r.entries {
		if key.list != list {
			continue
		}
		if _, ok := desiredSet[key.cidr]; ok {
			continue
		}
		// Clear a formerly-declared CP source. If a prior authoritative
		// reconcile already cleared it but its filter Remove failed, cpLive is
		// already false; continue into the same removal path so every retry keeps
		// reporting failure until the stale kernel rule is actually gone.
		entry.cpLive, entry.cpDeadline = false, time.Time{}
		if entry.systemLive {
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

// replaceCPSourceLocked applies one entry from an authoritative full desired
// state. Unlike incremental addCP's monotonic max-deadline semantics, this
// replaces the CP lifetime exactly: permanent may become finite and a longer
// deadline may become shorter. An already-installed survivor is bookkeeping
// only (no filter Remove/Add).
func (r *ttlRegistry) replaceCPSourceLocked(f filter.Filter, cidr *net.IPNet, list ruleList, ttl time.Duration, now time.Time) error {
	key := ttlKey{cidr: cidr.String(), list: list}
	entry, exists := r.entries[key]
	if !exists {
		entry = ttlEntry{cidr: cidr}
	}

	entry.cpLive = true
	if ttl <= 0 {
		entry.cpDeadline = time.Time{}
	} else {
		entry.cpDeadline = now.Add(ttl)
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
			// Match addSourceLocked: never record desired state that did not
			// reach the kernel; an existing entry retains its prior lifetime.
			return err
		}
		entry.inFilter = true
	}

	r.entries[key] = entry
	return nil
}

// remove deletes control-plane ownership for the CIDR. A protected
// system owner survives without a filter syscall; otherwise it purges the
// whole entry so the janitor never "expires" an entry that was
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

	key := ttlKey{cidr: cidr.String(), list: list}
	if entry, ok := r.entries[key]; ok && entry.systemLive {
		entry.cpLive, entry.cpDeadline = false, time.Time{}
		r.entries[key] = entry
		return nil
	}

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
	delete(r.entries, key)
	return nil
}

// clear removes ordinary filter rules as a delta while preserving daemon-owned
// system entries in place. It deliberately never calls Filter.ClearRules:
// implementations clear several maps sequentially, which would temporarily
// remove the DNS bootstrap and could leave it absent on a partial failure.
// Failed ordinary removals remain source-less in the registry for janitor retry.
func (r *ttlRegistry) clear(f filter.Filter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for key, entry := range r.entries {
		if entry.systemLive {
			entry.cpLive, entry.cpDeadline = false, time.Time{}
			r.entries[key] = entry
			continue
		}
		entry.cpLive, entry.cpDeadline = false, time.Time{}
		var err error
		if f != nil {
			if key.list == listAllow {
				err = f.RemoveAllowedIP(entry.cidr)
			} else {
				err = f.RemoveDeniedIP(entry.cidr)
			}
		}
		if err != nil {
			r.entries[key] = entry
			errs = append(errs, fmt.Errorf("removing %s: %w", key.cidr, err))
			continue
		}
		delete(r.entries, key)
	}
	return errors.Join(errs...)
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
		if !entry.systemLive && !entry.cpPermanent() {
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

// expire removes finite control-plane LPM entries after their deadline. A
// permanent CP or daemon-system source never expires. On a filter removal
// error the source-less entry is kept for retry on the next sweep: silently
// dropping bookkeeping while an expired allow remains live would fail open.
// DNS exact-tier expiry is owned independently by dnsOwnershipManager.
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
		if entry.systemLive || entry.cpLive {
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
