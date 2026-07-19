package daemon

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
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

type cpOwnership uint8

const (
	cpNone cpOwnership = iota
	cpFinite
	cpPermanent
	cpProvisional
)

// ttlKey identifies one tracked filter entry. cidr is the canonical (masked)
// string form produced by (*net.IPNet).String(), so equal control-plane
// networks written differently collapse to one key.
type ttlKey struct {
	cidr string
	list ruleList
}

// protectedEntry is one authoritative/system LPM entry. Ownership is desired
// userspace state. registryPresent is the registry's conservative belief used
// for idempotence, removal retry, and aggregate deltas; it is not proof of the
// physical map after a syscall returned an error, which may have happened
// before or after the kernel effect.
type protectedEntry struct {
	cidr *net.IPNet
	cp   cpOwnership
	// deadline is nonzero exactly for finite CP ownership.
	deadline        time.Time
	system          bool
	registryPresent bool
}

func (e protectedEntry) policyOwned() bool {
	return e.cp != cpNone
}

func (e protectedEntry) pending() bool {
	return !e.system && (e.cp == cpNone || e.cp == cpFinite)
}

// ttlRegistry owns control-plane/system LPM bookkeeping; DNS exact-host state
// is separate. Every operation holds this leaf mutex across its filter syscall
// and publication, after callers have released Server.mu. Finite incremental
// adds extend monotonically; authoritative reconcile replaces lifetimes.
type ttlRegistry struct {
	mu      sync.Mutex
	entries map[ttlKey]protectedEntry
	seeded  bool

	// mapFullDrops counts adds dropped because the filter's rule map was at
	// capacity. Cumulative; surfaced via AttachmentStats.map_full_drops.
	mapFullDrops uint64

	protectedCurrent       protectedRuleCurrent
	protectedHighWater     protectedRuleCurrent
	lastProtectedOccupancy filter.ProtectedRuleOccupancy
	lastProtectedStatsWarn time.Time
}

const (
	protectedAllow4 = iota
	protectedAllow6
	protectedDeny4
	protectedDeny6
	protectedBucketCount
)

// protectedRuleCurrent tracks registry-accounted keys by physical map under
// ttlRegistry.mu. Restore remains one O(N) pass rather than O(N^2).
type protectedRuleCurrent [protectedBucketCount]uint32

func newTTLRegistry() *ttlRegistry {
	return &ttlRegistry{entries: make(map[ttlKey]protectedEntry)}
}

// isMapFull reports whether a filter insert failed because the underlying
// BPF map is at capacity. LPM tries return ENOSPC; hash-style maps E2BIG.
func isMapFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.E2BIG)
}

// addCP pins ttl<=0 permanently; finite re-adds only extend their deadline.
func (r *ttlRegistry) addCP(f filter.Filter, cidr *net.IPNet, list ruleList, ttl time.Duration, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addLocked(f, cidr, list, true, ttl, now)
}

// needsPhysicalAdd is stable while its caller holds mutationSerialMu.
func (r *ttlRegistry) needsPhysicalAdd(cidr *net.IPNet, list ruleList) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[ttlKey{cidr: cidr.String(), list: list}]
	return !ok || !entry.registryPresent
}

// addSystem installs permanent daemon-owned attachment infrastructure.
func (r *ttlRegistry) addSystem(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addLocked(f, cidr, list, false, 0, time.Time{})
}

// removeSystem rolls back this daemon generation's system claim. Independent
// CP aliases survive; the physical entry is removed only when system was its
// sole owner. On removal failure the source-less entry remains for retry.
func (r *ttlRegistry) removeSystem(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := ttlKey{cidr: cidr.String(), list: list}
	entry, ok := r.entries[key]
	if !ok || !entry.system {
		return nil
	}
	entry.system = false
	if entry.policyOwned() {
		r.entries[key] = entry
		return nil
	}
	return r.removeUnownedLocked(f, key, entry)
}

// addLocked publishes only after success; an errored syscall leaves registry
// and aggregate state pre-call even when its physical effect occurred.
func (r *ttlRegistry) addLocked(f filter.Filter, cidr *net.IPNet, list ruleList, cp bool, ttl time.Duration, now time.Time) error {
	key := ttlKey{cidr: cidr.String(), list: list}
	entry, ok := r.entries[key]
	if !ok {
		entry = protectedEntry{cidr: cidr}
	}
	if cp {
		if ttl <= 0 {
			entry.cp, entry.deadline = cpPermanent, time.Time{}
		} else {
			switch entry.cp {
			case cpPermanent:
			case cpProvisional:
				// Adoption reconstructs a non-expiring CP pin. A finite
				// incremental add must not demote that restored policy.
				entry.cp, entry.deadline = cpPermanent, time.Time{}
			default:
				deadline := now.Add(ttl)
				if entry.cp != cpFinite || entry.deadline.Before(deadline) {
					entry.deadline = deadline
				}
				entry.cp = cpFinite
			}
		}
	} else {
		entry.system = true
	}

	becamePresent := false
	if f != nil && !entry.registryPresent {
		if err := addProtectedRule(f, cidr, list); err != nil {
			r.recordMapFullLocked(err, false)
			return err
		}
		entry.registryPresent = true
		becamePresent = true
	}

	r.entries[key] = entry
	if becamePresent {
		r.incrementProtectedCurrentLocked(cidr, list)
	}
	return nil
}

func addProtectedRule(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	if list == listAllow {
		return f.AllowIP(cidr)
	}
	return f.DenyIP(cidr)
}

func removeProtectedRule(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	if f == nil {
		return nil
	}
	if list == listAllow {
		return f.RemoveAllowedIP(cidr)
	}
	return f.RemoveDeniedIP(cidr)
}

// removeUnownedLocked commits the loss of the last owner before a removal
// attempt. Failure therefore retains a source-less conservative-present entry
// for the janitor. Explicit CP removal deliberately does not use this helper:
// its failure contract retains the prior CP owner exactly.
func (r *ttlRegistry) removeUnownedLocked(f filter.Filter, key ttlKey, entry protectedEntry) error {
	if !entry.registryPresent {
		delete(r.entries, key)
		return nil
	}
	if err := removeProtectedRule(f, entry.cidr, key.list); err != nil {
		r.entries[key] = entry
		return err
	}
	r.decrementProtectedCurrentLocked(entry.cidr, key.list)
	delete(r.entries, key)
	return nil
}

func (r *ttlRegistry) recordMapFullLocked(err error, authoritative bool) {
	if isMapFull(err) || authoritative && errors.Is(err, filter.ErrProtectedRuleCapacity) {
		r.mapFullDrops++
	}
}

// seedAdopted installs pinned inventory as provisional permanent ownership in
// one O(N), zero-write pass; authoritative reconcile later replaces it.
func (r *ttlRegistry) seedAdopted(allowed, denied []*net.IPNet) error {
	if r == nil {
		return fmt.Errorf("protected rule registry is unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seeded := make(map[ttlKey]protectedEntry, len(allowed)+len(denied))
	seedList := func(list ruleList, cidrs []*net.IPNet) error {
		for _, cidr := range cidrs {
			if cidr == nil {
				return fmt.Errorf("adopted %s inventory contains a nil CIDR", list)
			}
			key := ttlKey{cidr: cidr.String(), list: list}
			if _, exists := seeded[key]; exists {
				continue
			}
			seeded[key] = protectedEntry{
				cidr:            cidr,
				cp:              cpProvisional,
				registryPresent: true,
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
	if r.seeded || len(r.entries) != 0 || r.protectedCurrent != (protectedRuleCurrent{}) {
		return fmt.Errorf("protected rule registry must be empty before adopting pinned inventory")
	}

	r.entries = seeded
	r.seeded = true
	r.setProtectedCurrentFromEntriesLocked(seeded)
	return nil
}

// reconcileAuthoritative projects complete CP state plus system owners, then
// publishes only after the rollback-safe four-map/mode replacement succeeds.
// Its caller enters durable BLOCK_ALL on every valid-authoritative failure.
func (r *ttlRegistry) reconcileAuthoritative(f filter.Filter, mode filter.PolicyMode, allow, deny []parsedCIDR, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	projected := make(map[ttlKey]protectedEntry, len(allow)+len(deny)+len(r.entries))
	// System ownership is outside CP desired state and must survive every
	// replacement. Source-less retry entries and old CP-only entries disappear
	// from the projection; the physical transaction removes them on success.
	for key, current := range r.entries {
		if !current.system {
			continue
		}
		current.cp = cpNone
		current.deadline = time.Time{}
		projected[key] = current
	}
	projectList := func(list ruleList, desired []parsedCIDR) {
		for _, d := range desired {
			key := ttlKey{cidr: d.cidr.String(), list: list}
			entry, exists := projected[key]
			if !exists {
				entry = protectedEntry{cidr: d.cidr}
			}
			if d.ttl <= 0 {
				entry.cp, entry.deadline = cpPermanent, time.Time{}
			} else {
				entry.cp, entry.deadline = cpFinite, now.Add(d.ttl)
			}
			projected[key] = entry
		}
	}
	projectList(listAllow, allow)
	projectList(listDeny, deny)

	allowed := make([]*net.IPNet, 0, len(projected))
	denied := make([]*net.IPNet, 0, len(projected))
	for key, entry := range projected {
		if !entry.system && !entry.policyOwned() {
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
		r.recordMapFullLocked(err, true)
		return err
	}
	for key, entry := range projected {
		entry.registryPresent = true
		projected[key] = entry
	}
	r.entries = projected
	r.setProtectedCurrentFromEntriesLocked(projected)
	return nil
}

type protectedRuleStats struct {
	occupancy       filter.ProtectedRuleOccupancy
	allow4HighWater uint32
	allow6HighWater uint32
	deny4HighWater  uint32
	deny6HighWater  uint32
}

func isProtectedIPv4(cidr *net.IPNet) bool {
	return cidr != nil && cidr.IP.To4() != nil && len(cidr.Mask) == net.IPv4len
}

func protectedBucket(cidr *net.IPNet, list ruleList) int {
	switch {
	case list == listAllow && isProtectedIPv4(cidr):
		return protectedAllow4
	case list == listAllow:
		return protectedAllow6
	case isProtectedIPv4(cidr):
		return protectedDeny4
	default:
		return protectedDeny6
	}
}

func (r *ttlRegistry) incrementProtectedCurrentLocked(cidr *net.IPNet, list ruleList) {
	bucket := protectedBucket(cidr, list)
	r.protectedCurrent[bucket]++
	if r.protectedHighWater[bucket] < r.protectedCurrent[bucket] {
		r.protectedHighWater[bucket] = r.protectedCurrent[bucket]
	}
}

func (r *ttlRegistry) decrementProtectedCurrentLocked(cidr *net.IPNet, list ruleList) {
	bucket := protectedBucket(cidr, list)
	if r.protectedCurrent[bucket] > 0 {
		r.protectedCurrent[bucket]--
	}
}

func (r *ttlRegistry) setProtectedCurrentFromEntriesLocked(entries map[ttlKey]protectedEntry) {
	r.protectedCurrent = protectedRuleCurrent{}
	for key, entry := range entries {
		if entry.registryPresent {
			r.protectedCurrent[protectedBucket(entry.cidr, key.list)]++
		}
	}
	for bucket, current := range r.protectedCurrent {
		if r.protectedHighWater[bucket] < current {
			r.protectedHighWater[bucket] = current
		}
	}
}

func (r *ttlRegistry) setProtectedCurrentFromOccupancyLocked(occupancy filter.ProtectedRuleOccupancy) {
	r.protectedCurrent = protectedRuleCurrent{
		occupancy.AllowedIPv4.Entries,
		occupancy.AllowedIPv6.Entries,
		occupancy.DeniedIPv4.Entries,
		occupancy.DeniedIPv6.Entries,
	}
	for bucket, current := range r.protectedCurrent {
		if r.protectedHighWater[bucket] < current {
			r.protectedHighWater[bucket] = current
		}
	}
}

// protectedStats returns cached occupancy on inventory failure, never a guess.
func (r *ttlRegistry) protectedStats(f filter.Filter) (protectedRuleStats, error) {
	if r == nil || f == nil {
		return protectedRuleStats{}, fmt.Errorf("protected rule registry/filter is unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	occupancy, err := f.ProtectedRuleOccupancy()
	if err != nil {
		occupancy = r.lastProtectedOccupancy
	} else {
		r.lastProtectedOccupancy = occupancy
		r.setProtectedCurrentFromOccupancyLocked(occupancy)
	}
	return protectedRuleStats{
		occupancy:       occupancy,
		allow4HighWater: r.protectedHighWater[protectedAllow4],
		allow6HighWater: r.protectedHighWater[protectedAllow6],
		deny4HighWater:  r.protectedHighWater[protectedDeny4],
		deny6HighWater:  r.protectedHighWater[protectedDeny6],
	}, err
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

// remove drops CP ownership, preserving a system alias. Failure retains prior
// CP exactly; unlike clear/expiry/system teardown it creates no janitor retry.
func (r *ttlRegistry) remove(f filter.Filter, cidr *net.IPNet, list ruleList) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ttlKey{cidr: cidr.String(), list: list}
	entry, ok := r.entries[key]
	if !ok {
		return nil
	}
	if entry.system {
		entry.cp, entry.deadline = cpNone, time.Time{}
		r.entries[key] = entry
		return nil
	}
	if !entry.registryPresent {
		delete(r.entries, key)
		return nil
	}

	// Explicit remove is the one owner-removal path whose failure retains
	// prior CP ownership exactly. Clear, expiry, and removeSystem commit lost
	// ownership and use a source-less retry instead.
	if err := removeProtectedRule(f, cidr, list); err != nil {
		return err
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
	return ok && !entry.system && entry.registryPresent
}

// clear preserves system entries and removes ordinary keys individually so a
// partial multi-map clear cannot lose DNS bootstrap. Failures become retries.
func (r *ttlRegistry) clear(f filter.Filter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for key, entry := range r.entries {
		entry.cp, entry.deadline = cpNone, time.Time{}
		if entry.system {
			r.entries[key] = entry
			continue
		}
		if err := r.removeUnownedLocked(f, key, entry); err != nil {
			wrapped := fmt.Errorf("removing %s: %w", key.cidr, err)
			if key.list == listAllow {
				wrapped = fmt.Errorf("%w: %w", errProtectedAllowRemoval, wrapped)
			}
			errs = append(errs, wrapped)
		}
	}
	return errors.Join(errs...)
}

// purge drops bookkeeping without writes while the whole filter is closing.
func (r *ttlRegistry) purge() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[ttlKey]protectedEntry)
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
// no protected-map inventory and deliberately projects conservative
// registry-present state through the compatibility Installed field. This lets
// inspection distinguish a pending removal retry from desired policy without
// claiming proof after an errored syscall. DNS-derived exact-host ownership
// lives outside this registry.
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
			policyOwned: entry.policyOwned(),
			systemOwned: entry.system,
			expiresAt:   entry.deadline,
			provisional: entry.cp == cpProvisional,
			installed:   entry.registryPresent,
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

// hasRemovableAllow is the stable pre-journal check under mutationSerialMu.
func (r *ttlRegistry) hasRemovableAllow() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if key.list == listAllow && !entry.system && entry.registryPresent {
			return true
		}
	}
	return false
}

// hasExpiredRemovableAllow includes due CP and source-less retry entries; its
// caller holds mutationSerialMu through the following sweep.
func (r *ttlRegistry) hasExpiredRemovableAllow(now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if key.list != listAllow || entry.system || !entry.registryPresent {
			continue
		}
		if entry.cp == cpNone || entry.cp == cpFinite && !entry.deadline.After(now) {
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
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mapFullDrops
}

// sweptEntry reports one entry removal processed (or attempted) by expire.
type sweptEntry struct {
	cidr string
	list ruleList
	err  error
}

// expire removes due finite CP state. Permanent/provisional/system owners
// survive; failed removals become source-less retries. DNS expiry is separate.
func (r *ttlRegistry) expire(f filter.Filter, now time.Time) []sweptEntry {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var swept []sweptEntry
	for key, entry := range r.entries {
		changed := false
		if entry.cp == cpFinite && !entry.deadline.After(now) {
			entry.cp, entry.deadline = cpNone, time.Time{}
			changed = true
		}
		if entry.system || entry.policyOwned() {
			if changed {
				r.entries[key] = entry
			}
			continue
		}
		if !entry.registryPresent {
			delete(r.entries, key)
			swept = append(swept, sweptEntry{cidr: key.cidr, list: key.list})
			continue
		}

		err := r.removeUnownedLocked(f, key, entry)
		swept = append(swept, sweptEntry{cidr: key.cidr, list: key.list, err: err})
	}
	return swept
}
