package daemon

import (
	"errors"
	"fmt"
	"net"
	"sort"
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

var errProtectedAllowRemoval = errors.New("protected allow removal failed")

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
	// provisional marks policy ownership reconstructed from an adopted pinned
	// map before a complete authoritative update replaces its lifetime/source.
	provisional bool

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

	allowedIPv4HighWater    atomic.Uint32
	allowedIPv6HighWater    atomic.Uint32
	deniedIPv4HighWater     atomic.Uint32
	deniedIPv6HighWater     atomic.Uint32
	protectedCurrent        protectedRuleCurrent
	lastProtectedOccupancy  filter.ProtectedRuleOccupancy
	protectedOccupancyValid bool
	lastProtectedStatsWarn  time.Time
}

// protectedRuleCurrent tracks physical keys represented by the registry.
// It is maintained under ttlRegistry.mu so observing a successful add is O(1)
// instead of rescanning every entry. In particular, seeding four full maps on
// pinned restore must remain O(N), not O(N^2).
type protectedRuleCurrent struct {
	allow4 uint32
	allow6 uint32
	deny4  uint32
	deny6  uint32
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

// needsPhysicalAdd reports whether addCP would issue a map syscall. Callers
// use it only while holding mutationSerialMu, so the registry cannot change
// before the following addCP acquires r.mu.
func (r *ttlRegistry) needsPhysicalAdd(cidr *net.IPNet, list ruleList) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[ttlKey{cidr: cidr.String(), list: list}]
	return !ok || !entry.inFilter
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
	if !entry.inFilter {
		delete(r.entries, key)
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
	r.decrementProtectedCurrentLocked(entry.cidr, list)
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
		entry.provisional = false
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

	becamePhysical := false
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
		becamePhysical = true
	}

	r.entries[key] = entry
	if becamePhysical {
		r.incrementProtectedCurrentLocked(cidr, list)
	}
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
		entry.cpLive, entry.cpDeadline, entry.provisional = false, time.Time{}, false
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
		if entry.inFilter {
			r.decrementProtectedCurrentLocked(entry.cidr, list)
		}
		delete(r.entries, key)
	}

	return errors.Join(errs...)
}

// seedAdopted records a complete physical inventory read from pinned maps as
// provisional permanent control-plane ownership. The inventory is already the
// kernel truth, so restore must not upsert every key back into the same maps.
// Building the registry and its four current/high-water counters is one O(N)
// pass; a later authoritative update replaces the provisional lifetimes.
func (r *ttlRegistry) seedAdopted(allowed, denied []*net.IPNet) error {
	if r == nil {
		return fmt.Errorf("protected rule registry is unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seeded := make(map[ttlKey]ttlEntry, len(allowed)+len(denied))
	var seededAllowed, seededDenied []*net.IPNet
	seedList := func(list ruleList, cidrs []*net.IPNet) error {
		for _, cidr := range cidrs {
			if cidr == nil {
				return fmt.Errorf("adopted %s inventory contains a nil CIDR", list)
			}
			key := ttlKey{cidr: cidr.String(), list: list}
			if _, exists := seeded[key]; exists {
				continue
			}
			seeded[key] = ttlEntry{
				cidr:        cidr,
				cpLive:      true,
				provisional: true,
				inFilter:    true,
			}
			if list == listAllow {
				seededAllowed = append(seededAllowed, cidr)
			} else {
				seededDenied = append(seededDenied, cidr)
			}
		}
		return nil
	}
	if err := seedList(listAllow, allowed); err != nil {
		return err
	}
	if err := seedList(listDeny, denied); err != nil {
		return err
	}

	r.entries = seeded
	r.setProtectedCurrentLocked(seededAllowed, seededDenied)
	return nil
}

// reconcileAuthoritative projects both complete CP lists together with every
// daemon-system owner, then asks the filter to replace all four physical LPM
// maps and the packet mode as one rollback-safe transaction. Registry
// lifetimes are committed only after the filter proves success, so a capacity,
// snapshot, forward-mutation, mode, or rollback failure leaves the complete
// userspace graph unchanged. The caller deliberately enters durable BLOCK_ALL
// on every such valid-authoritative failure.
func (r *ttlRegistry) reconcileAuthoritative(f filter.Filter, mode filter.PolicyMode, allow, deny []parsedCIDR, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	projected := make(map[ttlKey]ttlEntry, len(allow)+len(deny)+len(r.entries))
	// System ownership is outside CP desired state and must survive every
	// replacement. Source-less retry entries and old CP-only entries disappear
	// from the projection; the physical transaction removes them on success.
	for key, current := range r.entries {
		if !current.systemLive {
			continue
		}
		current.cpLive = false
		current.cpDeadline = time.Time{}
		current.provisional = false
		projected[key] = current
	}
	projectList := func(list ruleList, desired []parsedCIDR) {
		for _, d := range desired {
			key := ttlKey{cidr: d.cidr.String(), list: list}
			entry, exists := projected[key]
			if !exists {
				entry = ttlEntry{cidr: d.cidr}
			}
			entry.cpLive = true
			entry.provisional = false
			if d.ttl <= 0 {
				entry.cpDeadline = time.Time{}
			} else {
				entry.cpDeadline = now.Add(d.ttl)
			}
			projected[key] = entry
		}
	}
	projectList(listAllow, allow)
	projectList(listDeny, deny)

	allowed := make([]*net.IPNet, 0, len(projected))
	denied := make([]*net.IPNet, 0, len(projected))
	for key, entry := range projected {
		if !entry.systemLive && !entry.cpLive {
			continue
		}
		if key.list == listAllow {
			allowed = append(allowed, entry.cidr)
		} else {
			denied = append(denied, entry.cidr)
		}
	}
	sort.Slice(allowed, func(i, j int) bool { return allowed[i].String() < allowed[j].String() })
	sort.Slice(denied, func(i, j int) bool { return denied[i].String() < denied[j].String() })

	if err := f.ReplaceProtectedRules(allowed, denied, mode); err != nil {
		if errors.Is(err, filter.ErrProtectedRuleCapacity) || isMapFull(err) {
			r.mapFullDrops.Add(1)
		}
		return err
	}
	for key, entry := range projected {
		entry.inFilter = true
		projected[key] = entry
	}
	r.entries = projected
	r.setProtectedCurrentLocked(allowed, denied)
	return nil
}

type protectedRuleStats struct {
	occupancy       filter.ProtectedRuleOccupancy
	allow4HighWater uint32
	allow6HighWater uint32
	deny4HighWater  uint32
	deny6HighWater  uint32
}

func updateUint32HighWater(dst *atomic.Uint32, value uint32) {
	for old := dst.Load(); value > old; old = dst.Load() {
		if dst.CompareAndSwap(old, value) {
			return
		}
	}
}

func countProtectedFamilies(cidrs []*net.IPNet) (v4, v6 uint32) {
	for _, cidr := range cidrs {
		if cidr.IP.To4() != nil && len(cidr.Mask) == net.IPv4len {
			v4++
		} else {
			v6++
		}
	}
	return
}

func isProtectedIPv4(cidr *net.IPNet) bool {
	return cidr != nil && cidr.IP.To4() != nil && len(cidr.Mask) == net.IPv4len
}

func (r *ttlRegistry) observeProtectedCurrentLocked() {
	updateUint32HighWater(&r.allowedIPv4HighWater, r.protectedCurrent.allow4)
	updateUint32HighWater(&r.allowedIPv6HighWater, r.protectedCurrent.allow6)
	updateUint32HighWater(&r.deniedIPv4HighWater, r.protectedCurrent.deny4)
	updateUint32HighWater(&r.deniedIPv6HighWater, r.protectedCurrent.deny6)
}

func (r *ttlRegistry) incrementProtectedCurrentLocked(cidr *net.IPNet, list ruleList) {
	switch {
	case list == listAllow && isProtectedIPv4(cidr):
		r.protectedCurrent.allow4++
	case list == listAllow:
		r.protectedCurrent.allow6++
	case isProtectedIPv4(cidr):
		r.protectedCurrent.deny4++
	default:
		r.protectedCurrent.deny6++
	}
	r.observeProtectedCurrentLocked()
}

func (r *ttlRegistry) decrementProtectedCurrentLocked(cidr *net.IPNet, list ruleList) {
	var current *uint32
	switch {
	case list == listAllow && isProtectedIPv4(cidr):
		current = &r.protectedCurrent.allow4
	case list == listAllow:
		current = &r.protectedCurrent.allow6
	case isProtectedIPv4(cidr):
		current = &r.protectedCurrent.deny4
	default:
		current = &r.protectedCurrent.deny6
	}
	if *current > 0 {
		*current = *current - 1
	}
}

func (r *ttlRegistry) setProtectedCurrentLocked(allowed, denied []*net.IPNet) {
	r.protectedCurrent.allow4, r.protectedCurrent.allow6 = countProtectedFamilies(allowed)
	r.protectedCurrent.deny4, r.protectedCurrent.deny6 = countProtectedFamilies(denied)
	r.observeProtectedCurrentLocked()
}

func (r *ttlRegistry) setProtectedCurrentFromOccupancyLocked(occupancy filter.ProtectedRuleOccupancy) {
	r.protectedCurrent = protectedRuleCurrent{
		allow4: occupancy.AllowedIPv4.Entries,
		allow6: occupancy.AllowedIPv6.Entries,
		deny4:  occupancy.DeniedIPv4.Entries,
		deny6:  occupancy.DeniedIPv6.Entries,
	}
	r.observeProtectedCurrentLocked()
}

// protectedStats snapshots physical occupancy/capacity and observes adopted
// pins for generation-local high-water telemetry. A failed inventory is
// surfaced to the caller rather than guessed.
func (r *ttlRegistry) protectedStats(f filter.Filter) (protectedRuleStats, error) {
	if r == nil || f == nil {
		return protectedRuleStats{}, fmt.Errorf("protected rule registry/filter is unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	occupancy, err := f.ProtectedRuleOccupancy()
	if err != nil {
		return protectedRuleStats{
			occupancy:       r.lastProtectedOccupancy,
			allow4HighWater: r.allowedIPv4HighWater.Load(),
			allow6HighWater: r.allowedIPv6HighWater.Load(),
			deny4HighWater:  r.deniedIPv4HighWater.Load(),
			deny6HighWater:  r.deniedIPv6HighWater.Load(),
		}, err
	}
	r.lastProtectedOccupancy = occupancy
	r.protectedOccupancyValid = true
	r.setProtectedCurrentFromOccupancyLocked(occupancy)
	return protectedRuleStats{
		occupancy:       occupancy,
		allow4HighWater: r.allowedIPv4HighWater.Load(),
		allow6HighWater: r.allowedIPv6HighWater.Load(),
		deny4HighWater:  r.deniedIPv4HighWater.Load(),
		deny6HighWater:  r.deniedIPv6HighWater.Load(),
	}, nil
}

func (r *ttlRegistry) protectedStatsWarningAllowed(now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.lastProtectedStatsWarn.IsZero() && now.Sub(r.lastProtectedStatsWarn) < 30*time.Second {
		return false
	}
	r.lastProtectedStatsWarn = now
	return true
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
	entry.provisional = false
	if ttl <= 0 {
		entry.cpDeadline = time.Time{}
	} else {
		entry.cpDeadline = now.Add(ttl)
	}

	becamePhysical := false
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
		becamePhysical = true
	}

	r.entries[key] = entry
	if becamePhysical {
		r.incrementProtectedCurrentLocked(cidr, list)
	}
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
	entry, ok := r.entries[key]
	if !ok {
		return nil
	}
	if entry.systemLive {
		entry.cpLive, entry.cpDeadline, entry.provisional = false, time.Time{}, false
		r.entries[key] = entry
		return nil
	}
	if !entry.inFilter {
		delete(r.entries, key)
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
	r.decrementProtectedCurrentLocked(entry.cidr, list)
	delete(r.entries, key)
	return nil
}

// needsPhysicalRemove reports whether remove will issue a map syscall. A
// missing entry, a system-owned alias, or bookkeeping that never reached the
// filter is an exact physical no-op and must not churn the crash journal.
func (r *ttlRegistry) needsPhysicalRemove(cidr *net.IPNet, list ruleList) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[ttlKey{cidr: cidr.String(), list: list}]
	return ok && !entry.systemLive && entry.inFilter
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
			entry.cpLive, entry.cpDeadline, entry.provisional = false, time.Time{}, false
			r.entries[key] = entry
			continue
		}
		entry.cpLive, entry.cpDeadline, entry.provisional = false, time.Time{}, false
		if !entry.inFilter {
			delete(r.entries, key)
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
		if err != nil {
			r.entries[key] = entry
			wrapped := fmt.Errorf("removing %s: %w", key.cidr, err)
			if key.list == listAllow {
				wrapped = fmt.Errorf("%w: %w", errProtectedAllowRemoval, wrapped)
			}
			errs = append(errs, wrapped)
			continue
		}
		r.decrementProtectedCurrentLocked(entry.cidr, key.list)
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
	r.protectedCurrent = protectedRuleCurrent{}
}

type ttlRuleSnapshot struct {
	cidr        string
	list        ruleList
	policyOwned bool
	systemOwned bool
	expiresAt   time.Time
	provisional bool
	installed   bool
}

// snapshotRules returns a deterministic userspace registry view. It performs
// no protected-map inventory and deliberately retains source-less installed
// entries so inspection can distinguish a pending removal retry from desired
// policy. DNS-derived exact-host ownership lives outside this registry.
func (r *ttlRegistry) snapshotRules() []ttlRuleSnapshot {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rules := make([]ttlRuleSnapshot, 0, len(r.entries))
	for key, entry := range r.entries {
		rules = append(rules, ttlRuleSnapshot{
			cidr:        key.cidr,
			list:        key.list,
			policyOwned: entry.cpLive,
			systemOwned: entry.systemLive,
			expiresAt:   entry.cpDeadline,
			provisional: entry.provisional,
			installed:   entry.inFilter,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].list != rules[j].list {
			return rules[i].list < rules[j].list
		}
		return rules[i].cidr < rules[j].cidr
	})
	return rules
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

// hasRemovableAllow reports whether clear would physically remove at least
// one ordinary allow entry. The caller may use this read-only pre-scan while
// holding the attachment mutationSerialMu to decide whether an intentional
// BLOCK_ALL operation needs a durable crash journal; no registry mutation can
// race between this check and clear in that admitted section.
func (r *ttlRegistry) hasRemovableAllow() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if key.list == listAllow && !entry.systemLive && entry.inFilter {
			return true
		}
	}
	return false
}

// hasExpiredRemovableAllow reports whether expire will attempt to remove an
// allow from the physical map. It includes source-less entries retained after
// an earlier failed removal as well as CP entries whose deadline is due.
// mutationSerialMu makes this pre-scan stable until the following expire.
func (r *ttlRegistry) hasExpiredRemovableAllow(now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if key.list != listAllow || entry.systemLive || !entry.inFilter {
			continue
		}
		if !entry.cpLive || (!entry.cpDeadline.IsZero() && !entry.cpDeadline.After(now)) {
			return true
		}
	}
	return false
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
			entry.cpLive, entry.cpDeadline, entry.provisional = false, time.Time{}, false
			changed = true
		}
		if entry.systemLive || entry.cpLive {
			if changed {
				r.entries[key] = entry
			}
			continue
		}
		if !entry.inFilter {
			delete(r.entries, key)
			swept = append(swept, sweptEntry{cidr: key.cidr, list: key.list})
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
			r.decrementProtectedCurrentLocked(entry.cidr, key.list)
			delete(r.entries, key)
		} else {
			r.entries[key] = entry
		}
		swept = append(swept, sweptEntry{cidr: key.cidr, list: key.list, err: err})
	}
	return swept
}
