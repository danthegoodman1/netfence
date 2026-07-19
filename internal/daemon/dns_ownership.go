package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

const (
	defaultDNSMaxIPsPerFamily       uint32 = 4096
	defaultDNSMaxIPsPerResponse     uint32 = 64
	defaultDNSMaxIPsPerPolicyDomain uint32 = 1024
	defaultDNSMaxTrackedDomains     uint32 = 1024
	defaultDNSMaxOwnershipEdges     uint32 = 8192
	defaultDNSMaxChurnUnits         uint32 = 8192
	defaultDNSChurnWindow                  = time.Minute
)

// dnsChurnLimits are separate from ownership limits because the rolling
// window is daemon-global and immutable for one process generation. Only the
// unit count has a per-attachment override, and that override may only lower
// the startup ceiling.
type dnsChurnLimits struct {
	maxUnits uint32
	window   time.Duration
}

func resolveDNSChurnCeiling(configuredMax uint32, configuredWindow time.Duration) dnsChurnLimits {
	if configuredMax == 0 {
		configuredMax = defaultDNSMaxChurnUnits
	}
	if configuredWindow <= 0 {
		configuredWindow = defaultDNSChurnWindow
	}
	return dnsChurnLimits{maxUnits: configuredMax, window: configuredWindow}
}

func (ceiling dnsChurnLimits) resolve(requested uint32) (dnsChurnLimits, error) {
	resolved := ceiling
	if requested == 0 {
		return resolved, nil
	}
	if requested > ceiling.maxUnits {
		return dnsChurnLimits{}, fmt.Errorf("DNS max_churn_units %d exceeds daemon ceiling %d", requested, ceiling.maxUnits)
	}
	resolved.maxUnits = requested
	return resolved, nil
}

// dnsAdmissionLimits bound every userspace structure used to explain exact
// DNS allow keys. maxIPsPerFamily is also a logical ceiling below the actual
// HASH map capacity; the remaining limits bound response fan-out and reverse
// ownership metadata independently.
type dnsAdmissionLimits struct {
	maxIPsPerFamily       uint32
	maxIPsPerResponse     uint32
	maxIPsPerPolicyDomain uint32
	maxTrackedDomains     uint32
	maxOwnershipEdges     uint32
}

type dnsAdmissionLimitOverrides struct {
	maxIPsPerFamily       uint32
	maxIPsPerResponse     uint32
	maxIPsPerPolicyDomain uint32
	maxTrackedDomains     uint32
	maxOwnershipEdges     uint32
}

func resolveDNSAdmissionCeilings(maxExactEntries uint32, configured dnsAdmissionLimitOverrides) dnsAdmissionLimits {
	if maxExactEntries == 0 {
		maxExactEntries = defaultDNSMaxIPsPerFamily
	}
	perFamily := configured.maxIPsPerFamily
	if perFamily == 0 {
		perFamily = maxExactEntries
	}
	aggregate := saturatingDouble(perFamily)
	edges := configured.maxOwnershipEdges
	if edges == 0 {
		edges = defaultDNSMaxOwnershipEdges
	}
	response := configured.maxIPsPerResponse
	if response == 0 {
		response = defaultDNSMaxIPsPerResponse
		if response > aggregate {
			response = aggregate
		}
		if response > edges {
			response = edges
		}
	}
	policy := configured.maxIPsPerPolicyDomain
	if policy == 0 {
		policy = defaultDNSMaxIPsPerPolicyDomain
	}
	if policy > aggregate && configured.maxIPsPerPolicyDomain == 0 {
		policy = aggregate
	}
	domains := configured.maxTrackedDomains
	if domains == 0 {
		domains = defaultDNSMaxTrackedDomains
	}
	return dnsAdmissionLimits{
		maxIPsPerFamily:       perFamily,
		maxIPsPerResponse:     response,
		maxIPsPerPolicyDomain: policy,
		maxTrackedDomains:     domains,
		maxOwnershipEdges:     edges,
	}
}

func saturatingDouble(value uint32) uint32 {
	if value > ^uint32(0)/2 {
		return ^uint32(0)
	}
	return value * 2
}

func (ceilings dnsAdmissionLimits) resolve(overrides dnsAdmissionLimitOverrides) (dnsAdmissionLimits, error) {
	resolved := ceilings
	values := []struct {
		name      string
		requested uint32
		ceiling   uint32
		target    *uint32
	}{
		{"max_ips_per_family", overrides.maxIPsPerFamily, ceilings.maxIPsPerFamily, &resolved.maxIPsPerFamily},
		{"max_ips_per_response", overrides.maxIPsPerResponse, ceilings.maxIPsPerResponse, &resolved.maxIPsPerResponse},
		{"max_ips_per_policy_domain", overrides.maxIPsPerPolicyDomain, ceilings.maxIPsPerPolicyDomain, &resolved.maxIPsPerPolicyDomain},
		{"max_tracked_domains", overrides.maxTrackedDomains, ceilings.maxTrackedDomains, &resolved.maxTrackedDomains},
		{"max_ownership_edges", overrides.maxOwnershipEdges, ceilings.maxOwnershipEdges, &resolved.maxOwnershipEdges},
	}
	for _, value := range values {
		if value.requested == 0 {
			continue
		}
		if value.requested > value.ceiling {
			return dnsAdmissionLimits{}, fmt.Errorf("DNS %s %d exceeds daemon ceiling %d", value.name, value.requested, value.ceiling)
		}
		*value.target = value.requested
	}
	if resolved.maxIPsPerResponse > saturatingDouble(resolved.maxIPsPerFamily) {
		return dnsAdmissionLimits{}, fmt.Errorf("DNS max_ips_per_response %d exceeds the aggregate per-family working-set limit %d", resolved.maxIPsPerResponse, saturatingDouble(resolved.maxIPsPerFamily))
	}
	if resolved.maxIPsPerPolicyDomain > saturatingDouble(resolved.maxIPsPerFamily) {
		return dnsAdmissionLimits{}, fmt.Errorf("DNS max_ips_per_policy_domain %d exceeds the aggregate per-family working-set limit %d", resolved.maxIPsPerPolicyDomain, saturatingDouble(resolved.maxIPsPerFamily))
	}
	if resolved.maxIPsPerResponse > resolved.maxOwnershipEdges {
		return dnsAdmissionLimits{}, fmt.Errorf("DNS max_ips_per_response %d exceeds max_ownership_edges %d", resolved.maxIPsPerResponse, resolved.maxOwnershipEdges)
	}
	return resolved, nil
}

type dnsOwnerKind uint8

const (
	dnsOwnerRule dnsOwnerKind = iota
	dnsOwnerDenylistDefault
	dnsOwnerProxy
	dnsOwnerProvisional
)

// dnsPolicyOwner names the policy fact which authorized one answer. Domain is
// always normalized. The kind prevents a DENYLIST default or proxy decision
// from aliasing an explicit rule with the same spelling.
type dnsPolicyOwner struct {
	kind   dnsOwnerKind
	domain string
}

type dnsOwnershipKey struct {
	query string
	owner dnsPolicyOwner
}

type dnsOwnedIP struct {
	addr         netip.Addr
	owners       dnsOwnerEdgeSet
	lastObserved time.Time
}

// dnsOwnerEdgeSet keeps the common sole ownership edge inline and allocates an
// overflow map only when an address is genuinely shared. Lookups stay O(1),
// unlike a linear small slice, and every userspace edge remains covered by the
// manager's maxOwnershipEdges bound.
type dnsOwnerEdgeSet struct {
	occupied       bool
	inlineKey      dnsOwnershipKey
	inlineDeadline time.Time
	inlineObserved time.Time
	overflow       map[dnsOwnershipKey]dnsOwnerEdgeState
}

type dnsOwnerEdgeState struct {
	deadline time.Time
	observed time.Time
}

func newDNSOwnerEdgeSet(key dnsOwnershipKey, deadline time.Time) dnsOwnerEdgeSet {
	return dnsOwnerEdgeSet{occupied: true, inlineKey: key, inlineDeadline: deadline}
}

func (owners dnsOwnerEdgeSet) len() int {
	if !owners.occupied {
		return 0
	}
	return 1 + len(owners.overflow)
}

func (owners dnsOwnerEdgeSet) get(key dnsOwnershipKey) (time.Time, bool) {
	if owners.occupied && owners.inlineKey == key {
		return owners.inlineDeadline, true
	}
	state, ok := owners.overflow[key]
	return state.deadline, ok
}

// putMax inserts an edge or extends its deadline. A zero deadline is
// permanent, so neither a finite refresh nor a remap collision may shorten it.
// The return value reports whether a new logical edge was inserted.
func (owners *dnsOwnerEdgeSet) putMax(key dnsOwnershipKey, deadline time.Time) bool {
	if !owners.occupied {
		owners.occupied = true
		owners.inlineKey = key
		owners.inlineDeadline = deadline
		return true
	}
	if owners.inlineKey == key {
		owners.inlineDeadline = maxDNSDeadline(owners.inlineDeadline, deadline)
		return false
	}
	if old, ok := owners.overflow[key]; ok {
		old.deadline = maxDNSDeadline(old.deadline, deadline)
		owners.overflow[key] = old
		return false
	}
	if owners.overflow == nil {
		owners.overflow = make(map[dnsOwnershipKey]dnsOwnerEdgeState)
	}
	owners.overflow[key] = dnsOwnerEdgeState{deadline: deadline}
	return true
}

// putMaxObserved extends lifetime and resolver-observed recency independently.
// Reconcile collisions keep the maximum of both so neither TTL nor LRU age is
// accidentally shortened by map iteration order.
func (owners *dnsOwnerEdgeSet) putMaxObserved(key dnsOwnershipKey, deadline, observed time.Time) bool {
	inserted := owners.putMax(key, deadline)
	owners.observe(key, observed)
	return inserted
}

func (owners *dnsOwnerEdgeSet) observe(key dnsOwnershipKey, observed time.Time) {
	if owners.occupied && owners.inlineKey == key {
		if owners.inlineObserved.Before(observed) {
			owners.inlineObserved = observed
		}
		return
	}
	state, ok := owners.overflow[key]
	if !ok {
		return
	}
	if state.observed.Before(observed) {
		state.observed = observed
		owners.overflow[key] = state
	}
}

func (owners dnsOwnerEdgeSet) observed(key dnsOwnershipKey) time.Time {
	if owners.occupied && owners.inlineKey == key {
		return owners.inlineObserved
	}
	return owners.overflow[key].observed
}

func maxDNSDeadline(old, candidate time.Time) time.Time {
	if old.IsZero() || (!candidate.IsZero() && !old.Before(candidate)) {
		return old
	}
	return candidate
}

func (owners dnsOwnerEdgeSet) each(fn func(dnsOwnershipKey, time.Time)) {
	if !owners.occupied {
		return
	}
	fn(owners.inlineKey, owners.inlineDeadline)
	for key, state := range owners.overflow {
		fn(key, state.deadline)
	}
}

func (owners dnsOwnerEdgeSet) eachObserved(fn func(dnsOwnershipKey, time.Time, time.Time)) {
	if !owners.occupied {
		return
	}
	fn(owners.inlineKey, owners.inlineDeadline, owners.inlineObserved)
	for key, state := range owners.overflow {
		fn(key, state.deadline, state.observed)
	}
}

func (owners dnsOwnerEdgeSet) clone() dnsOwnerEdgeSet {
	clone := owners
	if owners.overflow != nil {
		clone.overflow = make(map[dnsOwnershipKey]dnsOwnerEdgeState, len(owners.overflow))
		for key, state := range owners.overflow {
			clone.overflow[key] = state
		}
	}
	return clone
}

// dnsOwnerIPRefSet keeps the overwhelmingly common first address for a policy
// owner inline. The overflow map is allocated only when that owner actually
// reaches a second distinct address; reference counts still distinguish
// multiple query edges from the same matched owner to one address.
type dnsOwnerIPRefSet struct {
	firstAddr  netip.Addr
	firstCount uint64
	overflow   map[netip.Addr]uint64
}

func (refs dnsOwnerIPRefSet) uniqueLen() int {
	if refs.firstCount == 0 {
		return 0
	}
	return 1 + len(refs.overflow)
}

func (refs dnsOwnerIPRefSet) count(addr netip.Addr) uint64 {
	if refs.firstCount != 0 && refs.firstAddr == addr {
		return refs.firstCount
	}
	return refs.overflow[addr]
}

func (refs *dnsOwnerIPRefSet) increment(addr netip.Addr) {
	if refs.firstCount == 0 {
		refs.firstAddr = addr
		refs.firstCount = 1
		return
	}
	if refs.firstAddr == addr {
		refs.firstCount++
		return
	}
	if refs.overflow == nil {
		refs.overflow = make(map[netip.Addr]uint64)
	}
	refs.overflow[addr]++
}

type dnsAdmissionRecord struct {
	ip  net.IP
	ttl time.Duration
}

type dnsAdmissionRequest struct {
	queryDomain string
	owner       dnsPolicyOwner
	records     []dnsAdmissionRecord
}

type dnsAdmissionOutcome struct {
	changed          bool
	committedUnits   uint64
	resolvedPressure uint32
}

// dnsCanonicalAdmissionRequest is the trusted resolver-to-manager handoff.
// Its distinct, unexported domain types prevent the production response path
// from accidentally falling back to presentation strings after snapshotQuery
// has already wire-canonicalized both identities. Direct/leaf callers use
// dnsAdmissionRequest through admit, which performs the canonicalization.
type dnsCanonicalDomain string

type dnsCanonicalPolicyOwner struct {
	kind   dnsOwnerKind
	domain dnsCanonicalDomain
}

type dnsCanonicalAdmissionRequest struct {
	queryDomain dnsCanonicalDomain
	owner       dnsCanonicalPolicyOwner
	records     []dnsAdmissionRecord
}

func canonicalizeDNSAdmissionRequest(req dnsAdmissionRequest) (dnsCanonicalAdmissionRequest, error) {
	query, err := validateAndNormalizeDomain(req.queryDomain)
	if err != nil {
		return dnsCanonicalAdmissionRequest{}, fmt.Errorf("invalid DNS admission query domain: %w", err)
	}
	if req.owner.kind == dnsOwnerProvisional || req.owner.domain == "" {
		return dnsCanonicalAdmissionRequest{}, fmt.Errorf("invalid DNS admission policy owner")
	}
	ownerDomain, err := validateAndNormalizeDomain(req.owner.domain)
	if err != nil {
		return dnsCanonicalAdmissionRequest{}, fmt.Errorf("invalid DNS admission policy owner domain: %w", err)
	}
	return dnsCanonicalAdmissionRequest{
		queryDomain: dnsCanonicalDomain(query),
		owner: dnsCanonicalPolicyOwner{
			kind:   req.owner.kind,
			domain: dnsCanonicalDomain(ownerDomain),
		},
		records: req.records,
	}, nil
}

// dnsOwnershipResolver returns the new winning owner for a previously tracked
// query. A false result means the query is no longer locally authorized. Proxy
// policy deliberately returns false because an old per-query CP decision
// cannot be inferred from a new full desired-state generation.
type dnsOwnershipResolver func(query string) (dnsPolicyOwner, bool)

var (
	errDNSAdmissionCapacity   = errors.New("DNS admission capacity exceeded")
	errDNSAdmissionBudget     = errors.New("DNS rolling churn budget exhausted")
	errDNSAdmissionWorkBudget = errors.New("DNS rolling ownership-planning work budget exhausted")
)

func dnsCapacityError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDNSAdmissionCapacity, fmt.Sprintf(format, args...))
}

func dnsBudgetError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDNSAdmissionBudget, fmt.Sprintf(format, args...))
}

func dnsWorkBudgetError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDNSAdmissionWorkBudget, fmt.Sprintf(format, args...))
}

// dnsChurnBudget is a chronological deque of response-sized charge buckets.
// Each bucket carries a unit count, avoiding an O(active units) timestamp copy
// on every admission. Active units (and therefore active buckets) are bounded
// by the immutable daemon ceiling, not a mutable per-attachment lowering, so a
// later raise cannot forget still-active history. Events expire at exactly
// age==window; timestamps in the future after a clock rollback remain active.
type dnsChurnBucket struct {
	stamp time.Time
	units uint32
}

type dnsChurnBudget struct {
	buckets     []dnsChurnBucket
	head        int
	activeUnits uint64
	ceiling     uint32
	window      time.Duration
}

type dnsChurnReservation struct {
	stamp       time.Time
	units       uint32
	prunedHead  int
	activeUnits uint64
}

func newDNSChurnBudget(limits dnsChurnLimits) dnsChurnBudget {
	return dnsChurnBudget{ceiling: limits.maxUnits, window: limits.window}
}

func (b *dnsChurnBudget) activeAt(now time.Time) (int, uint64) {
	head := b.head
	active := b.activeUnits
	for head < len(b.buckets) {
		bucket := b.buckets[head]
		if bucket.stamp.After(now) || now.Sub(bucket.stamp) < b.window {
			break
		}
		active -= uint64(bucket.units)
		head++
	}
	return head, active
}

// reserve is allocation-free and does not mutate history. commit publishes
// the previewed expired-prefix pruning and new units only after the exact-map
// transaction succeeds.
func (b *dnsChurnBudget) reserve(now time.Time, limit uint32, units uint64) (dnsChurnReservation, error) {
	return b.reserveWithError(now, limit, units, dnsBudgetError)
}

func (b *dnsChurnBudget) reserveWork(now time.Time, limit uint32, units uint64) (dnsChurnReservation, error) {
	return b.reserveWithError(now, limit, units, dnsWorkBudgetError)
}

func (b *dnsChurnBudget) reserveWithError(now time.Time, limit uint32, units uint64, budgetError func(string, ...any) error) (dnsChurnReservation, error) {
	prunedHead, active := b.activeAt(now)
	if units != 0 && (active > uint64(limit) || units > uint64(limit)-active) {
		return dnsChurnReservation{}, budgetError("rolling window has %d active units and response needs %d, limit is %d per %s", active, units, limit, b.window)
	}
	if active > uint64(b.ceiling) || units > uint64(b.ceiling)-active {
		return dnsChurnReservation{}, budgetError("rolling history would exceed daemon ceiling %d", b.ceiling)
	}
	stamp := now
	if len(b.buckets) != prunedHead && stamp.Before(b.buckets[len(b.buckets)-1].stamp) {
		// Preserve chronological order and fail conservatively across wall-clock
		// rollback: the new units receive the latest already-observed instant.
		stamp = b.buckets[len(b.buckets)-1].stamp
	}
	return dnsChurnReservation{stamp: stamp, units: uint32(units), prunedHead: prunedHead, activeUnits: active}, nil
}

func (b *dnsChurnBudget) commit(reservation dnsChurnReservation) {
	for i := b.head; i < reservation.prunedHead; i++ {
		b.buckets[i] = dnsChurnBucket{}
	}
	b.head = reservation.prunedHead
	b.activeUnits = reservation.activeUnits
	if b.head == len(b.buckets) {
		b.buckets = b.buckets[:0]
		b.head = 0
	} else if b.head >= 64 && b.head*2 >= len(b.buckets) {
		copy(b.buckets, b.buckets[b.head:])
		b.buckets = b.buckets[:len(b.buckets)-b.head]
		b.head = 0
	}
	if reservation.units == 0 {
		return
	}
	if len(b.buckets) != b.head && b.buckets[len(b.buckets)-1].stamp.Equal(reservation.stamp) {
		b.buckets[len(b.buckets)-1].units += reservation.units
		b.activeUnits += uint64(reservation.units)
		return
	}
	// A long-lived backing slice must never accumulate more bucket slots than
	// the immutable unit ceiling merely because an expired prefix remains.
	if uint64(len(b.buckets)) >= uint64(b.ceiling) && b.head != 0 {
		copy(b.buckets, b.buckets[b.head:])
		b.buckets = b.buckets[:len(b.buckets)-b.head]
		b.head = 0
	}
	b.buckets = append(b.buckets, dnsChurnBucket{stamp: reservation.stamp, units: reservation.units})
	b.activeUnits += uint64(reservation.units)
}

// dnsOwnershipManager is a leaf object. Runtime callers serialize every
// mutation with attachmentState.mutationSerialMu, acquired by
// beginAttachmentMutation; DNSServer.mu is an additional policy/generation
// lease and its read side alone does not serialize admissions. SeedPinned is
// the constructor/startup-only exception, before attachment publication. The
// manager never acquires any outer lock itself.
type dnsOwnershipManager struct {
	filter   filter.Filter
	limits   dnsAdmissionLimits
	entries  map[netip.Addr]dnsOwnedIP
	seeded   bool
	minTTL   time.Duration
	now      func() time.Time
	capacity filter.DNSAllowOccupancy
	// policyDomains is the normalized union of configured allow/deny rule
	// domains. maxTrackedDomains bounds this union together with live query
	// domains, so the policy maps themselves cannot become an unbounded side
	// structure.
	policyDomains       map[string]struct{}
	normalIPv4          uint64
	normalIPv6          uint64
	physicalIPv4        uint64
	physicalIPv6        uint64
	edgeCount           uint64
	trackedDomains      uint64
	queryRefs           map[string]uint64
	ownerIPRefs         map[dnsPolicyOwner]dnsOwnerIPRefSet
	churnLimits         dnsChurnLimits
	churnBudget         dnsChurnBudget
	workBudget          dnsChurnBudget
	workScale           uint32
	workMaxItems        uint64
	lastClock           time.Time
	highWater4          uint32
	highWater6          uint32
	lruEvictions        uint64
	publishedCurrent4   atomic.Uint32
	publishedCurrent6   atomic.Uint32
	publishedHighWater4 atomic.Uint32
	publishedHighWater6 atomic.Uint32
	publishedEvictions  atomic.Uint64
	publishedVersion    atomic.Uint64
}

type dnsOwnershipStats struct {
	occupancy    filter.DNSAllowOccupancy
	highWater4   uint32
	highWater6   uint32
	lruEvictions uint64
}

func (m *dnsOwnershipManager) stats() dnsOwnershipStats {
	for {
		before := m.publishedVersion.Load()
		if before&1 != 0 {
			continue
		}
		stats := dnsOwnershipStats{
			occupancy: filter.DNSAllowOccupancy{
				IPv4Entries:  m.publishedCurrent4.Load(),
				IPv4Capacity: m.capacity.IPv4Capacity,
				IPv6Entries:  m.publishedCurrent6.Load(),
				IPv6Capacity: m.capacity.IPv6Capacity,
			},
			highWater4:   m.publishedHighWater4.Load(),
			highWater6:   m.publishedHighWater6.Load(),
			lruEvictions: m.publishedEvictions.Load(),
		}
		if before == m.publishedVersion.Load() {
			return stats
		}
	}
}

func (m *dnsOwnershipManager) publishStats() {
	// Production mutation paths have one writer under mutationSerialMu. The
	// version makes the independently atomic fields one coherent reader
	// snapshot without allocating or adding a mutex to the query path.
	m.publishedVersion.Add(1)
	m.publishedCurrent4.Store(saturatingDNSCount(m.physicalIPv4))
	m.publishedCurrent6.Store(saturatingDNSCount(m.physicalIPv6))
	m.publishedHighWater4.Store(m.highWater4)
	m.publishedHighWater6.Store(m.highWater6)
	m.publishedEvictions.Store(m.lruEvictions)
	m.publishedVersion.Add(1)
}

func saturatingDNSCount(value uint64) uint32 {
	if value > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

func newDNSOwnershipManager(f filter.Filter, limits dnsAdmissionLimits, minTTL time.Duration, now func() time.Time) (*dnsOwnershipManager, error) {
	return newDNSOwnershipManagerWithChurn(f, limits,
		resolveDNSChurnCeiling(0, 0), minTTL, now)
}

func newDNSOwnershipManagerWithChurn(f filter.Filter, limits dnsAdmissionLimits, churn dnsChurnLimits, minTTL time.Duration, now func() time.Time) (*dnsOwnershipManager, error) {
	if churn.maxUnits == 0 {
		return nil, fmt.Errorf("DNS max_churn_units must be positive")
	}
	if churn.window <= 0 {
		return nil, fmt.Errorf("DNS churn window must be positive")
	}
	if now == nil {
		now = time.Now
	}
	if minTTL <= 0 {
		minTTL = 60 * time.Second
	}
	m := &dnsOwnershipManager{
		filter:        f,
		limits:        limits,
		entries:       make(map[netip.Addr]dnsOwnedIP),
		policyDomains: make(map[string]struct{}),
		queryRefs:     make(map[string]uint64),
		ownerIPRefs:   make(map[dnsPolicyOwner]dnsOwnerIPRefSet),
		minTTL:        minTTL,
		now:           now,
		churnLimits:   churn,
		churnBudget:   newDNSChurnBudget(churn),
	}
	if f == nil {
		m.capacity = filter.DNSAllowOccupancy{
			IPv4Capacity: limits.maxIPsPerFamily,
			IPv6Capacity: limits.maxIPsPerFamily,
		}
		m.initializeWorkBudget(churn)
		m.publishStats()
		return m, nil
	}
	occupancy, err := f.DNSAllowOccupancy()
	if err != nil {
		return nil, fmt.Errorf("reading DNS exact-tier capacity: %w", err)
	}
	m.capacity = occupancy
	actualPerFamily := occupancy.IPv4Capacity
	if occupancy.IPv6Capacity < actualPerFamily {
		actualPerFamily = occupancy.IPv6Capacity
	}
	if m.limits.maxIPsPerFamily > actualPerFamily {
		m.limits.maxIPsPerFamily = actualPerFamily
	}
	aggregate := saturatingDouble(m.limits.maxIPsPerFamily)
	if m.limits.maxIPsPerResponse > aggregate {
		m.limits.maxIPsPerResponse = aggregate
	}
	if m.limits.maxIPsPerPolicyDomain > aggregate {
		m.limits.maxIPsPerPolicyDomain = aggregate
	}
	if m.limits.maxIPsPerResponse > m.limits.maxOwnershipEdges {
		m.limits.maxIPsPerResponse = m.limits.maxOwnershipEdges
	}
	m.initializeWorkBudget(churn)
	m.publishStats()
	return m, nil
}

func (m *dnsOwnershipManager) initializeWorkBudget(churn dnsChurnLimits) {
	m.workScale = churn.maxUnits
	if m.workScale > 1024 {
		m.workScale = 1024
	}
	// Normal physical keys are simultaneously bounded by actual map capacity,
	// the two logical family ceilings, and the fact that every normal key needs
	// at least one ownership edge. Using that tight immutable aggregate prevents
	// oversized backing maps from diluting ordinary graph-work charges. Restored
	// provisional keys above the normal bound remain in the runtime numerator
	// and therefore clamp naturally to one full-equivalent pass.
	normalPhysicalMax := uint64(m.capacity.IPv4Capacity) + uint64(m.capacity.IPv6Capacity)
	logicalPhysicalMax := uint64(m.limits.maxIPsPerFamily) * 2
	if logicalPhysicalMax < normalPhysicalMax {
		normalPhysicalMax = logicalPhysicalMax
	}
	if uint64(m.limits.maxOwnershipEdges) < normalPhysicalMax {
		normalPhysicalMax = uint64(m.limits.maxOwnershipEdges)
	}
	for _, value := range []uint64{
		normalPhysicalMax,
		uint64(m.limits.maxOwnershipEdges),
		uint64(m.limits.maxTrackedDomains),
		uint64(m.limits.maxIPsPerResponse),
	} {
		m.workMaxItems = saturatingAddUint64(m.workMaxItems, value)
	}
	if m.workMaxItems == 0 {
		m.workMaxItems = 1
	}
	ledgerCeiling := churn.maxUnits
	if ledgerCeiling < m.workScale {
		ledgerCeiling = m.workScale
	}
	m.workBudget = newDNSChurnBudget(dnsChurnLimits{maxUnits: ledgerCeiling, window: churn.window})
}

func (m *dnsOwnershipManager) validateLimits(limits dnsAdmissionLimits) error {
	if limits.maxIPsPerFamily > m.capacity.IPv4Capacity || limits.maxIPsPerFamily > m.capacity.IPv6Capacity {
		return fmt.Errorf("DNS max_ips_per_family %d exceeds actual exact-map capacities IPv4=%d IPv6=%d", limits.maxIPsPerFamily, m.capacity.IPv4Capacity, m.capacity.IPv6Capacity)
	}
	return nil
}

func (m *dnsOwnershipManager) validateChurnLimits(limits dnsChurnLimits) error {
	if limits.maxUnits == 0 || limits.maxUnits > m.churnBudget.ceiling {
		return fmt.Errorf("DNS max_churn_units %d exceeds manager ceiling %d", limits.maxUnits, m.churnBudget.ceiling)
	}
	if limits.window != m.churnBudget.window {
		return fmt.Errorf("DNS churn window %s differs from immutable manager window %s", limits.window, m.churnBudget.window)
	}
	return nil
}

// seedPinned represents every preexisting exact key with one synthetic,
// permanent edge. Provisional metadata is exempt from user-configured normal
// domain/policy/edge caps because it is bounded by the two actual HASH maps
// (at most capacity4+capacity6 edges) and must not be forgotten before an
// authoritative reconciliation proves removal safe.
func (m *dnsOwnershipManager) seedPinned() error {
	if m.seeded || m.filter == nil {
		m.seeded = true
		return nil
	}
	ips, err := m.filter.DNSAllowedIPs()
	if err != nil {
		return fmt.Errorf("listing restored DNS exact-tier keys: %w", err)
	}
	owner := dnsOwnershipKey{
		query: "__netfence_restored__",
		owner: dnsPolicyOwner{kind: dnsOwnerProvisional, domain: "__netfence_restored__"},
	}
	occupancy, err := m.filter.DNSAllowOccupancy()
	if err != nil {
		return fmt.Errorf("reading restored DNS exact-tier occupancy: %w", err)
	}
	seen := make(map[netip.Addr]struct{}, len(ips))
	seededEntries := make(map[netip.Addr]dnsOwnedIP, len(ips))
	var inventory4, inventory6 uint32
	for _, ip := range ips {
		addr, err := canonicalDNSAddr(ip)
		if err != nil {
			return fmt.Errorf("inventorying restored DNS exact-tier key: %w", err)
		}
		if _, duplicate := seen[addr]; duplicate {
			return fmt.Errorf("restored DNS exact-tier inventory contains a canonical collision at %s", addr)
		}
		seen[addr] = struct{}{}
		if addr.Is4() {
			inventory4++
		} else {
			inventory6++
		}
		seededEntries[addr] = dnsOwnedIP{addr: addr, owners: newDNSOwnerEdgeSet(owner, time.Time{})}
	}
	if inventory4 != occupancy.IPv4Entries || inventory6 != occupancy.IPv6Entries {
		return fmt.Errorf("restored DNS exact-tier inventory is ambiguous: canonical IPv4=%d IPv6=%d, map occupancy IPv4=%d IPv6=%d", inventory4, inventory6, occupancy.IPv4Entries, occupancy.IPv6Entries)
	}
	m.entries = seededEntries
	m.rebuildOwnershipIndexes()
	m.seeded = true
	return nil
}

func (m *dnsOwnershipManager) admit(req dnsAdmissionRequest) error {
	_, err := m.admitDetailed(req)
	return err
}

func (m *dnsOwnershipManager) admitDetailed(req dnsAdmissionRequest) (dnsAdmissionOutcome, error) {
	canonical, err := canonicalizeDNSAdmissionRequest(req)
	if err != nil {
		return dnsAdmissionOutcome{}, err
	}
	return m.admitCanonicalDetailed(canonical)
}

func (m *dnsOwnershipManager) admitCanonical(req dnsCanonicalAdmissionRequest) error {
	_, err := m.admitCanonicalDetailed(req)
	return err
}

func (m *dnsOwnershipManager) admitCanonicalDetailed(req dnsCanonicalAdmissionRequest) (dnsAdmissionOutcome, error) {
	query := string(req.queryDomain)
	owner := dnsPolicyOwner{kind: req.owner.kind, domain: string(req.owner.domain)}

	// Canonicalize and de-duplicate the entire response before any capacity
	// decision. Duplicate records consume one response slot/edge and extend to
	// the deterministic maximum effective deadline.
	now := m.now()
	deadlines := make(map[netip.Addr]time.Time, len(req.records))
	for _, record := range req.records {
		addr, err := canonicalDNSAddr(record.ip)
		if err != nil {
			return dnsAdmissionOutcome{}, err
		}
		ttl := record.ttl
		if ttl < m.minTTL {
			ttl = m.minTTL
		}
		deadline := now.Add(ttl)
		if old, ok := deadlines[addr]; !ok || old.Before(deadline) {
			deadlines[addr] = deadline
		}
	}
	if uint64(len(deadlines)) > uint64(m.limits.maxIPsPerResponse) {
		return dnsAdmissionOutcome{}, dnsCapacityError("response has %d unique addresses, limit is %d", len(deadlines), m.limits.maxIPsPerResponse)
	}
	if len(deadlines) == 0 {
		return dnsAdmissionOutcome{}, nil
	}
	observedAt := now
	if observedAt.Before(m.lastClock) {
		observedAt = m.lastClock
	}
	edge := dnsOwnershipKey{query: query, owner: owner}
	refreshOnly := true
	for addr := range deadlines {
		entry, exists := m.entries[addr]
		if !exists {
			refreshOnly = false
			break
		}
		deadline, owned := entry.owners.get(edge)
		if !owned || (!deadline.IsZero() && !deadline.After(now)) {
			refreshOnly = false
			break
		}
	}
	if refreshOnly {
		reservation, err := m.churnBudget.reserve(observedAt, m.churnLimits.maxUnits, 0)
		if err != nil {
			return dnsAdmissionOutcome{}, err
		}
		for addr, deadline := range deadlines {
			entry := m.entries[addr]
			entry.owners.putMaxObserved(edge, deadline, observedAt)
			entry.lastObserved = observedAt
			m.entries[addr] = entry
		}
		m.lastClock = observedAt
		m.churnBudget.commit(reservation)
		return dnsAdmissionOutcome{}, nil
	}
	if handled, committedUnits, err := m.tryAdmitWithoutPressure(deadlines, edge, observedAt); handled {
		if err != nil {
			return dnsAdmissionOutcome{}, err
		}
		var resolved uint32
		if committedUnits != 0 {
			resolved = dnsCapacityPressure | dnsBudgetPressure
		}
		return dnsAdmissionOutcome{changed: true, committedUnits: committedUnits, resolvedPressure: resolved}, nil
	}

	// Every incoming address absent from the current exact working set must add
	// one physical key if this response succeeds. Reject an already-exhausted
	// budget from this response-sized lower bound before cloning and analyzing
	// the entire ownership graph. Existing physical keys deliberately contribute
	// zero here: metadata-only pressure can be resolved without any churn units
	// and must still reach the planner.
	var guaranteedUnits uint64
	for addr := range deadlines {
		if _, exists := m.entries[addr]; !exists {
			guaranteedUnits++
		}
	}
	if guaranteedUnits != 0 {
		if _, err := m.churnBudget.reserve(observedAt, m.churnLimits.maxUnits, guaranteedUnits); err != nil {
			return dnsAdmissionOutcome{}, err
		}
	}

	// Slow planning clones and analyzes the bounded ownership graph. Account
	// for that work in a distinct, stable-unit ledger before projection so even
	// an impossible or filter-failed plan consumes its share of the rolling
	// attempt allowance. This never commits or prunes the physical mutation
	// ledger, whose reservation remains transactional with the exact-map write.
	workCost := m.slowPlanWorkCost(len(deadlines))
	workReservation, err := m.workBudget.reserveWork(observedAt, m.currentWorkLimit(), workCost)
	if err != nil {
		return dnsAdmissionOutcome{}, err
	}
	m.workBudget.commit(workReservation)

	// Expiry, incoming ownership, LRU reclamation, and the final exact-map
	// replacement are one projected transaction. A later capacity, budget, or
	// kernel failure therefore leaves every pre-call live and expired edge
	// exactly as it was; expiry itself costs no churn units on success.
	projected := projectUnexpiredDNSOwnedEntries(m.entries, now)
	incoming := make(map[netip.Addr]struct{}, len(deadlines))
	for addr := range deadlines {
		incoming[addr] = struct{}{}
		entry, physicalExists := projected[addr]
		if !physicalExists {
			entry = dnsOwnedIP{addr: addr}
		}
		entry.owners.putMaxObserved(edge, deadlines[addr], observedAt)
		entry.lastObserved = observedAt
		projected[addr] = entry
	}

	evicted, err := selectDNSLRUEvictions(projected, incoming, edge, m.limits, m.policyDomains, m.capacity)
	if err != nil {
		return dnsAdmissionOutcome{}, err
	}
	toRemove := dnsEntryDifference(m.entries, projected)
	toAdd := dnsEntryDifference(projected, m.entries)
	units := uint64(len(toAdd)) + uint64(len(evicted))
	reservation, err := m.churnBudget.reserve(observedAt, m.churnLimits.maxUnits, units)
	if err != nil {
		return dnsAdmissionOutcome{}, err
	}
	if m.filter != nil {
		switch {
		case len(toRemove) != 0:
			if err := m.filter.ReplaceDNSAllowedIPs(toRemove, toAdd); err != nil {
				return dnsAdmissionOutcome{}, err
			}
		case len(toAdd) != 0:
			if err := m.filter.AddDNSAllowedIPs(toAdd); err != nil {
				return dnsAdmissionOutcome{}, err
			}
		}
	}
	m.entries = projected
	m.lruEvictions = saturatingAddUint64(m.lruEvictions, uint64(len(evicted)))
	m.rebuildOwnershipIndexes()
	m.lastClock = observedAt
	m.churnBudget.commit(reservation)
	resolved := dnsCapacityPressure | dnsWorkPressure
	if units != 0 {
		resolved |= dnsBudgetPressure
	}
	return dnsAdmissionOutcome{changed: true, committedUnits: units, resolvedPressure: resolved}, nil
}

func (m *dnsOwnershipManager) currentWorkLimit() uint32 {
	if m.churnLimits.maxUnits > m.workScale {
		return m.churnLimits.maxUnits
	}
	return m.workScale
}

func (m *dnsOwnershipManager) slowPlanWorkCost(uniqueIncoming int) uint64 {
	items := uint64(0)
	for _, value := range []uint64{
		m.physicalIPv4,
		m.physicalIPv6,
		m.edgeCount,
		m.trackedDomains,
		uint64(uniqueIncoming),
	} {
		items = saturatingAddUint64(items, value)
	}
	if items > m.workMaxItems {
		items = m.workMaxItems
	}
	if items == 0 {
		return 1
	}
	scale := uint64(m.workScale)
	if items > ^uint64(0)/scale {
		return scale
	}
	scaled := items * scale
	cost := scaled / m.workMaxItems
	if scaled%m.workMaxItems != 0 {
		cost++
	}
	if cost == 0 {
		return 1
	}
	if cost > scale {
		return scale
	}
	return cost
}

// tryAdmitWithoutPressure preserves the ordinary cold path's O(response)
// behavior. Incremental indexes preflight every logical and physical delta;
// only an apparent cap violation falls back to the full expiry/LRU projection.
// Expired unrelated metadata may remain conservatively counted until the
// janitor unless pressure makes reclaiming it necessary.
func (m *dnsOwnershipManager) tryAdmitWithoutPressure(deadlines map[netip.Addr]time.Time, edge dnsOwnershipKey, observedAt time.Time) (bool, uint64, error) {
	projected4, projected6 := m.normalIPv4, m.normalIPv6
	physical4, physical6 := m.physicalIPv4, m.physicalIPv6
	projectedEdges := m.edgeCount
	trackedDomains := m.trackedDomains
	ownerRefs := m.ownerIPRefs[edge.owner]
	projectedOwnerIPs := uint64(ownerRefs.uniqueLen())
	newQuery := m.queryRefs[edge.query] == 0
	if newQuery {
		if _, configured := m.policyDomains[edge.query]; !configured {
			var ok bool
			trackedDomains, ok = checkedAddUint64(trackedDomains, 1)
			if !ok {
				return true, 0, dnsCapacityError("tracked-domain counter overflow")
			}
		}
	}
	toAdd := make([]net.IP, 0, len(deadlines))
	for addr := range deadlines {
		entry, physicalExists := m.entries[addr]
		if !physicalExists {
			toAdd = append(toAdd, net.IP(addr.AsSlice()))
			var ok bool
			if addr.Is4() {
				physical4, ok = checkedAddUint64(physical4, 1)
			} else {
				physical6, ok = checkedAddUint64(physical6, 1)
			}
			if !ok {
				return true, 0, dnsCapacityError("physical exact-entry counter overflow")
			}
		}
		if _, edgeExists := entry.owners.get(edge); edgeExists {
			continue
		}
		var ok bool
		projectedEdges, ok = checkedAddUint64(projectedEdges, 1)
		if !ok {
			return true, 0, dnsCapacityError("ownership edge counter overflow")
		}
		if !entryHasNormalOwner(entry) {
			if addr.Is4() {
				projected4, ok = checkedAddUint64(projected4, 1)
			} else {
				projected6, ok = checkedAddUint64(projected6, 1)
			}
			if !ok {
				return true, 0, dnsCapacityError("normal exact-entry counter overflow")
			}
		}
		if ownerRefs.count(addr) == 0 {
			projectedOwnerIPs, ok = checkedAddUint64(projectedOwnerIPs, 1)
			if !ok {
				return true, 0, dnsCapacityError("policy-owner address counter overflow")
			}
		}
	}
	if projected4 > uint64(m.limits.maxIPsPerFamily) || projected6 > uint64(m.limits.maxIPsPerFamily) ||
		physical4 > uint64(m.capacity.IPv4Capacity) || physical6 > uint64(m.capacity.IPv6Capacity) ||
		projectedEdges > uint64(m.limits.maxOwnershipEdges) || trackedDomains > uint64(m.limits.maxTrackedDomains) ||
		projectedOwnerIPs > uint64(m.limits.maxIPsPerPolicyDomain) {
		return false, 0, nil
	}
	sortIPs(toAdd)
	reservation, err := m.churnBudget.reserve(observedAt, m.churnLimits.maxUnits, uint64(len(toAdd)))
	if err != nil {
		return true, 0, err
	}
	if m.filter != nil && len(toAdd) != 0 {
		if err := m.filter.AddDNSAllowedIPs(toAdd); err != nil {
			return true, 0, err
		}
	}
	for addr, deadline := range deadlines {
		entry, physicalExists := m.entries[addr]
		if !physicalExists {
			entry = dnsOwnedIP{addr: addr}
			if addr.Is4() {
				m.physicalIPv4++
			} else {
				m.physicalIPv6++
			}
		}
		_, edgeExists := entry.owners.get(edge)
		if !edgeExists {
			if !entryHasNormalOwner(entry) {
				if addr.Is4() {
					m.normalIPv4++
				} else {
					m.normalIPv6++
				}
			}
			m.edgeCount++
			if m.queryRefs[edge.query] == 0 {
				if _, configured := m.policyDomains[edge.query]; !configured {
					m.trackedDomains++
				}
			}
			m.queryRefs[edge.query]++
			refs := m.ownerIPRefs[edge.owner]
			refs.increment(addr)
			m.ownerIPRefs[edge.owner] = refs
		}
		entry.owners.putMaxObserved(edge, deadline, observedAt)
		entry.lastObserved = observedAt
		m.entries[addr] = entry
	}
	if m.physicalIPv4 > uint64(m.highWater4) {
		m.highWater4 = saturatingDNSCount(m.physicalIPv4)
	}
	if m.physicalIPv6 > uint64(m.highWater6) {
		m.highWater6 = saturatingDNSCount(m.physicalIPv6)
	}
	m.lastClock = observedAt
	m.churnBudget.commit(reservation)
	m.publishStats()
	return true, uint64(len(toAdd)), nil
}

func checkedAddUint64(value, increment uint64) (uint64, bool) {
	if ^uint64(0)-value < increment {
		return 0, false
	}
	return value + increment, true
}

func saturatingAddUint64(value, increment uint64) uint64 {
	if ^uint64(0)-value < increment {
		return ^uint64(0)
	}
	return value + increment
}

type dnsOwnedUsage struct {
	normal4, normal6     uint64
	physical4, physical6 uint64
	edges                uint64
	domains              map[string]struct{}
	ownerIPs             map[dnsPolicyOwner]map[netip.Addr]struct{}
}

func analyzeDNSOwnedState(entries map[netip.Addr]dnsOwnedIP, policyDomains map[string]struct{}) dnsOwnedUsage {
	usage := dnsOwnedUsage{
		domains:  cloneDomainSet(policyDomains),
		ownerIPs: make(map[dnsPolicyOwner]map[netip.Addr]struct{}),
	}
	for addr, entry := range entries {
		if addr.Is4() {
			usage.physical4++
		} else {
			usage.physical6++
		}
		if entryHasNormalOwner(entry) {
			if addr.Is4() {
				usage.normal4++
			} else {
				usage.normal6++
			}
		}
		entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
			if edge.owner.kind == dnsOwnerProvisional {
				return
			}
			usage.edges++
			usage.domains[edge.query] = struct{}{}
			ips := usage.ownerIPs[edge.owner]
			if ips == nil {
				ips = make(map[netip.Addr]struct{})
				usage.ownerIPs[edge.owner] = ips
			}
			ips[addr] = struct{}{}
		})
	}
	return usage
}

type dnsOwnedViolations struct {
	ipv4, ipv6, edges, domains bool
	overOwners                 map[dnsPolicyOwner]struct{}
}

func (v dnsOwnedViolations) any() bool {
	return v.ipv4 || v.ipv6 || v.edges || v.domains || len(v.overOwners) != 0
}

func dnsUsageViolations(usage dnsOwnedUsage, limits dnsAdmissionLimits, capacity filter.DNSAllowOccupancy) dnsOwnedViolations {
	v := dnsOwnedViolations{overOwners: make(map[dnsPolicyOwner]struct{})}
	v.ipv4 = usage.normal4 > uint64(limits.maxIPsPerFamily) || usage.physical4 > uint64(capacity.IPv4Capacity)
	v.ipv6 = usage.normal6 > uint64(limits.maxIPsPerFamily) || usage.physical6 > uint64(capacity.IPv6Capacity)
	v.edges = usage.edges > uint64(limits.maxOwnershipEdges)
	v.domains = uint64(len(usage.domains)) > uint64(limits.maxTrackedDomains)
	for owner, ips := range usage.ownerIPs {
		if uint64(len(ips)) > uint64(limits.maxIPsPerPolicyDomain) {
			v.overOwners[owner] = struct{}{}
		}
	}
	return v
}

func entryHasProvisionalOwner(entry dnsOwnedIP) bool {
	has := false
	entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
		if edge.owner.kind == dnsOwnerProvisional {
			has = true
		}
	})
	return has
}

func dnsEntryLastObserved(entry dnsOwnedIP) time.Time {
	var latest time.Time
	entry.owners.eachObserved(func(edge dnsOwnershipKey, _ time.Time, observed time.Time) {
		if edge.owner.kind != dnsOwnerProvisional && latest.Before(observed) {
			latest = observed
		}
	})
	return latest
}

func dnsEntryIsLRUEligible(addr netip.Addr, entry dnsOwnedIP, incoming map[netip.Addr]struct{}) bool {
	_, isIncoming := incoming[addr]
	return !isIncoming && entryHasNormalOwner(entry) && !entryHasProvisionalOwner(entry)
}

func dnsEdgeIsIncoming(addr netip.Addr, edge, incomingEdge dnsOwnershipKey, incoming map[netip.Addr]struct{}) bool {
	_, isIncomingIP := incoming[addr]
	return isIncomingIP && edge == incomingEdge
}

type dnsQueryEvictionGroup struct {
	query              string
	addresses          []netip.Addr
	physicalCollateral int
	rankStamp          time.Time
	rankAddr           netip.Addr
}

func buildDNSQueryEvictionGroups(projected map[netip.Addr]dnsOwnedIP, incoming map[netip.Addr]struct{}, incomingEdge dnsOwnershipKey, policyDomains map[string]struct{}) []dnsQueryEvictionGroup {
	addressSets := make(map[string]map[netip.Addr]struct{})
	blocked := make(map[string]bool)
	rankStamps := make(map[string]time.Time)
	rankAddrs := make(map[string]netip.Addr)
	for addr, entry := range projected {
		entry.owners.eachObserved(func(edge dnsOwnershipKey, _ time.Time, observed time.Time) {
			if edge.owner.kind == dnsOwnerProvisional {
				return
			}
			if _, configured := policyDomains[edge.query]; configured {
				return
			}
			if dnsEdgeIsIncoming(addr, edge, incomingEdge, incoming) {
				blocked[edge.query] = true
				return
			}
			set := addressSets[edge.query]
			if set == nil {
				set = make(map[netip.Addr]struct{})
				addressSets[edge.query] = set
			}
			set[addr] = struct{}{}
			oldStamp, oldAddr := rankStamps[edge.query], rankAddrs[edge.query]
			if !oldAddr.IsValid() || oldStamp.Before(observed) || (oldStamp.Equal(observed) && addr.Less(oldAddr)) {
				rankStamps[edge.query] = observed
				rankAddrs[edge.query] = addr
			}
		})
	}
	groups := make([]dnsQueryEvictionGroup, 0, len(addressSets))
	for query, set := range addressSets {
		if blocked[query] || len(set) == 0 {
			continue
		}
		group := dnsQueryEvictionGroup{
			query: query, addresses: make([]netip.Addr, 0, len(set)),
			rankStamp: rankStamps[query], rankAddr: rankAddrs[query],
		}
		for addr := range set {
			group.addresses = append(group.addresses, addr)
			entry := projected[addr]
			if dnsMetadataRemovalDeletesPhysical(entry, func(candidate dnsOwnershipKey) bool {
				return candidate.query == query
			}) {
				group.physicalCollateral++
			}
		}
		sort.Slice(group.addresses, func(i, j int) bool { return group.addresses[i].Less(group.addresses[j]) })
		groups = append(groups, group)
	}
	// Reclaim the query whose newest required member is oldest. This avoids
	// partially destroying a multi-address query merely because its first
	// member is older than a complete, more-useful single-address group.
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].physicalCollateral != groups[j].physicalCollateral {
			return groups[i].physicalCollateral < groups[j].physicalCollateral
		}
		if !groups[i].rankStamp.Equal(groups[j].rankStamp) {
			return groups[i].rankStamp.Before(groups[j].rankStamp)
		}
		if groups[i].rankAddr != groups[j].rankAddr {
			return groups[i].rankAddr.Less(groups[j].rankAddr)
		}
		return groups[i].query < groups[j].query
	})
	return groups
}

func removeDNSOwnershipEdges(entry dnsOwnedIP, remove func(dnsOwnershipKey) bool) (dnsOwnedIP, int) {
	var owners dnsOwnerEdgeSet
	removed := 0
	entry.owners.eachObserved(func(edge dnsOwnershipKey, deadline, observed time.Time) {
		if remove(edge) {
			removed++
			return
		}
		owners.putMaxObserved(edge, deadline, observed)
	})
	entry.owners = owners
	entry.lastObserved = dnsEntryLastObserved(entry)
	return entry, removed
}

func applyDNSMetadataReclamation(projected map[netip.Addr]dnsOwnedIP, addr netip.Addr, remove func(dnsOwnershipKey) bool, physicalEvictions map[netip.Addr]struct{}) int {
	entry, ok := projected[addr]
	if !ok {
		return 0
	}
	entry, removed := removeDNSOwnershipEdges(entry, remove)
	if removed == 0 {
		return 0
	}
	if entry.owners.len() == 0 {
		delete(projected, addr)
		physicalEvictions[addr] = struct{}{}
	} else {
		projected[addr] = entry
	}
	return removed
}

type dnsOwnerIPCandidate struct {
	addr               netip.Addr
	physicalCollateral bool
	observed           time.Time
}

func dnsOwnerCandidates(projected map[netip.Addr]dnsOwnedIP, incoming map[netip.Addr]struct{}, incomingEdge dnsOwnershipKey, owner dnsPolicyOwner) []dnsOwnerIPCandidate {
	var candidates []dnsOwnerIPCandidate
	for addr, entry := range projected {
		found := false
		protected := false
		var observed time.Time
		entry.owners.eachObserved(func(edge dnsOwnershipKey, _ time.Time, edgeObserved time.Time) {
			if edge.owner != owner {
				return
			}
			if dnsEdgeIsIncoming(addr, edge, incomingEdge, incoming) || edge.owner.kind == dnsOwnerProvisional {
				protected = true
				return
			}
			found = true
			if observed.Before(edgeObserved) {
				observed = edgeObserved
			}
		})
		if found && !protected {
			collateral := dnsMetadataRemovalDeletesPhysical(entry, func(edge dnsOwnershipKey) bool {
				return edge.owner == owner
			})
			candidates = append(candidates, dnsOwnerIPCandidate{addr: addr, physicalCollateral: collateral, observed: observed})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].physicalCollateral != candidates[j].physicalCollateral {
			return !candidates[i].physicalCollateral
		}
		if !candidates[i].observed.Equal(candidates[j].observed) {
			return candidates[i].observed.Before(candidates[j].observed)
		}
		return candidates[i].addr.Less(candidates[j].addr)
	})
	return candidates
}

type dnsEdgeCandidate struct {
	addr     netip.Addr
	edge     dnsOwnershipKey
	observed time.Time
}

func lessDNSEdgeCandidate(a, b dnsEdgeCandidate) bool {
	if !a.observed.Equal(b.observed) {
		return a.observed.Before(b.observed)
	}
	if a.addr != b.addr {
		return a.addr.Less(b.addr)
	}
	if a.edge.query != b.edge.query {
		return a.edge.query < b.edge.query
	}
	if a.edge.owner.kind != b.edge.owner.kind {
		return a.edge.owner.kind < b.edge.owner.kind
	}
	return a.edge.owner.domain < b.edge.owner.domain
}

// dnsEdgeCandidates returns zero-collateral candidates separately from the
// last removable edge at each otherwise-unprotected physical key. Within one
// key the oldest k-1 edges are logical-only removals; its newest edge is the
// possible whole-key removal. Sorting both global pools once preserves
// deterministic LRU while avoiding per-edge graph rescans under pressure.
func dnsEdgeCandidates(projected map[netip.Addr]dnsOwnedIP, incoming map[netip.Addr]struct{}, incomingEdge dnsOwnershipKey) (zeroCollateral, physicalCollateral []dnsEdgeCandidate) {
	for addr, entry := range projected {
		var first dnsEdgeCandidate
		var perEntry []dnsEdgeCandidate
		eligible := 0
		entry.owners.eachObserved(func(edge dnsOwnershipKey, _ time.Time, observed time.Time) {
			if edge.owner.kind != dnsOwnerProvisional && !dnsEdgeIsIncoming(addr, edge, incomingEdge, incoming) {
				candidate := dnsEdgeCandidate{addr: addr, edge: edge, observed: observed}
				switch eligible {
				case 0:
					first = candidate
				case 1:
					perEntry = make([]dnsEdgeCandidate, 0, entry.owners.len())
					perEntry = append(perEntry, first, candidate)
				default:
					perEntry = append(perEntry, candidate)
				}
				eligible++
			}
		})
		if eligible == 0 {
			continue
		}
		if eligible == 1 {
			if entry.owners.len() == 1 {
				physicalCollateral = append(physicalCollateral, first)
			} else {
				zeroCollateral = append(zeroCollateral, first)
			}
			continue
		}
		sort.Slice(perEntry, func(i, j int) bool { return lessDNSEdgeCandidate(perEntry[i], perEntry[j]) })
		if len(perEntry) < entry.owners.len() {
			zeroCollateral = append(zeroCollateral, perEntry...)
			continue
		}
		zeroCollateral = append(zeroCollateral, perEntry[:len(perEntry)-1]...)
		physicalCollateral = append(physicalCollateral, perEntry[len(perEntry)-1])
	}
	sort.Slice(zeroCollateral, func(i, j int) bool { return lessDNSEdgeCandidate(zeroCollateral[i], zeroCollateral[j]) })
	sort.Slice(physicalCollateral, func(i, j int) bool { return lessDNSEdgeCandidate(physicalCollateral[i], physicalCollateral[j]) })
	return zeroCollateral, physicalCollateral
}

func dnsMetadataRemovalDeletesPhysical(entry dnsOwnedIP, remove func(dnsOwnershipKey) bool) bool {
	removed := false
	remaining := false
	entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
		if remove(edge) {
			removed = true
		} else {
			remaining = true
		}
	})
	return removed && !remaining
}

func selectDNSLRUEvictions(projected map[netip.Addr]dnsOwnedIP, incoming map[netip.Addr]struct{}, incomingEdge dnsOwnershipKey, limits dnsAdmissionLimits, policyDomains map[string]struct{}, capacity filter.DNSAllowOccupancy) ([]net.IP, error) {
	usage := analyzeDNSOwnedState(projected, policyDomains)
	evictedSet := make(map[netip.Addr]struct{})

	if uint64(len(usage.domains)) > uint64(limits.maxTrackedDomains) {
		excess := uint64(len(usage.domains)) - uint64(limits.maxTrackedDomains)
		groups := buildDNSQueryEvictionGroups(projected, incoming, incomingEdge, policyDomains)
		// A valid prestate plus one response can introduce at most one query
		// domain. A larger excess indicates an inconsistent caller-owned graph;
		// reject it rather than doing response-sized repeated full scans.
		if excess != 1 || len(groups) == 0 {
			return nil, dnsUsageCapacityError(usage, limits, capacity)
		}
		group := groups[0]
		for _, addr := range group.addresses {
			applyDNSMetadataReclamation(projected, addr,
				func(edge dnsOwnershipKey) bool {
					return edge.query == group.query && !dnsEdgeIsIncoming(addr, edge, incomingEdge, incoming)
				}, evictedSet)
		}
		usage = analyzeDNSOwnedState(projected, policyDomains)
	}

	type ownerUsage struct {
		owner dnsPolicyOwner
		count int
	}
	var overOwners []ownerUsage
	for owner, ips := range usage.ownerIPs {
		if uint64(len(ips)) > uint64(limits.maxIPsPerPolicyDomain) {
			overOwners = append(overOwners, ownerUsage{owner: owner, count: len(ips)})
		}
	}
	sort.Slice(overOwners, func(i, j int) bool {
		if overOwners[i].owner.kind != overOwners[j].owner.kind {
			return overOwners[i].owner.kind < overOwners[j].owner.kind
		}
		return overOwners[i].owner.domain < overOwners[j].owner.domain
	})
	if len(overOwners) > 1 || (len(overOwners) == 1 && overOwners[0].owner != incomingEdge.owner) {
		// A cap-valid prestate can only be pushed over this limit by the one
		// incoming owner. Reject inconsistent synthetic/corrupt state without
		// multiplying a full candidate scan by attacker-controlled owner count.
		return nil, dnsUsageCapacityError(usage, limits, capacity)
	}
	if len(overOwners) != 0 {
		for _, over := range overOwners {
			excess := uint64(over.count) - uint64(limits.maxIPsPerPolicyDomain)
			candidates := dnsOwnerCandidates(projected, incoming, incomingEdge, over.owner)
			if uint64(len(candidates)) < excess {
				return nil, dnsUsageCapacityError(usage, limits, capacity)
			}
			for _, candidate := range candidates[:excess] {
				applyDNSMetadataReclamation(projected, candidate.addr,
					func(edge dnsOwnershipKey) bool {
						return edge.owner == over.owner && !dnsEdgeIsIncoming(candidate.addr, edge, incomingEdge, incoming)
					}, evictedSet)
			}
		}
		usage = analyzeDNSOwnedState(projected, policyDomains)
	}
	if usage.edges > uint64(limits.maxOwnershipEdges) {
		excess := usage.edges - uint64(limits.maxOwnershipEdges)
		zeroCollateral, physicalCollateral := dnsEdgeCandidates(projected, incoming, incomingEdge)
		if uint64(len(zeroCollateral))+uint64(len(physicalCollateral)) < excess {
			return nil, dnsUsageCapacityError(usage, limits, capacity)
		}
		selected := make(map[netip.Addr]map[dnsOwnershipKey]struct{})
		remaining := excess
		for _, pool := range [][]dnsEdgeCandidate{zeroCollateral, physicalCollateral} {
			for _, candidate := range pool {
				if remaining == 0 {
					break
				}
				remove := selected[candidate.addr]
				if remove == nil {
					remove = make(map[dnsOwnershipKey]struct{})
					selected[candidate.addr] = remove
				}
				remove[candidate.edge] = struct{}{}
				remaining--
			}
		}
		for addr, remove := range selected {
			applyDNSMetadataReclamation(projected, addr,
				func(edge dnsOwnershipKey) bool {
					_, ok := remove[edge]
					return ok
				}, evictedSet)
		}
		usage = analyzeDNSOwnedState(projected, policyDomains)
	}

	normalNeed4 := uint64(0)
	if usage.normal4 > uint64(limits.maxIPsPerFamily) {
		normalNeed4 = usage.normal4 - uint64(limits.maxIPsPerFamily)
	}
	normalNeed6 := uint64(0)
	if usage.normal6 > uint64(limits.maxIPsPerFamily) {
		normalNeed6 = usage.normal6 - uint64(limits.maxIPsPerFamily)
	}
	// A provisional edge protects its restored physical key until an
	// authoritative reconciliation, but normal resolver metadata sharing that
	// key remains reclaimable. Strip the oldest such normal ownership first to
	// satisfy the logical per-family ceiling without a syscall or churn unit.
	if normalNeed4 != 0 || normalNeed6 != 0 {
		provisionalNormal := make([]dnsOwnedIP, 0)
		for addr, entry := range projected {
			_, isIncoming := incoming[addr]
			if !isIncoming && entryHasProvisionalOwner(entry) && entryHasNormalOwner(entry) {
				provisionalNormal = append(provisionalNormal, entry)
			}
		}
		sort.Slice(provisionalNormal, func(i, j int) bool {
			if !provisionalNormal[i].lastObserved.Equal(provisionalNormal[j].lastObserved) {
				return provisionalNormal[i].lastObserved.Before(provisionalNormal[j].lastObserved)
			}
			return provisionalNormal[i].addr.Less(provisionalNormal[j].addr)
		})
		removedNormal := false
		for _, candidate := range provisionalNormal {
			if (candidate.addr.Is4() && normalNeed4 == 0) || (candidate.addr.Is6() && normalNeed6 == 0) {
				continue
			}
			entry, removed := removeDNSOwnershipEdges(projected[candidate.addr], func(edge dnsOwnershipKey) bool {
				return edge.owner.kind != dnsOwnerProvisional
			})
			if removed == 0 {
				continue
			}
			projected[candidate.addr] = entry
			removedNormal = true
			if candidate.addr.Is4() {
				normalNeed4--
			} else {
				normalNeed6--
			}
			if normalNeed4 == 0 && normalNeed6 == 0 {
				break
			}
		}
		if removedNormal {
			usage = analyzeDNSOwnedState(projected, policyDomains)
		}
	}

	need4 := maxUint64Deficit(usage.normal4, uint64(limits.maxIPsPerFamily), usage.physical4, uint64(capacity.IPv4Capacity))
	need6 := maxUint64Deficit(usage.normal6, uint64(limits.maxIPsPerFamily), usage.physical6, uint64(capacity.IPv6Capacity))
	if need4 != 0 || need6 != 0 {
		candidates := make([]dnsOwnedIP, 0, len(projected))
		for addr, entry := range projected {
			if dnsEntryIsLRUEligible(addr, entry, incoming) {
				candidates = append(candidates, entry)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			if !candidates[i].lastObserved.Equal(candidates[j].lastObserved) {
				return candidates[i].lastObserved.Before(candidates[j].lastObserved)
			}
			return candidates[i].addr.Less(candidates[j].addr)
		})
		for _, candidate := range candidates {
			if (candidate.addr.Is4() && need4 == 0) || (candidate.addr.Is6() && need6 == 0) {
				continue
			}
			delete(projected, candidate.addr)
			evictedSet[candidate.addr] = struct{}{}
			if candidate.addr.Is4() {
				need4--
			} else {
				need6--
			}
			if need4 == 0 && need6 == 0 {
				break
			}
		}
	}
	if need4 != 0 || need6 != 0 {
		return nil, dnsUsageCapacityError(analyzeDNSOwnedState(projected, policyDomains), limits, capacity)
	}
	usage = analyzeDNSOwnedState(projected, policyDomains)
	if dnsUsageViolations(usage, limits, capacity).any() {
		return nil, dnsUsageCapacityError(usage, limits, capacity)
	}
	if err := validateDNSOwnedState(projected, limits, policyDomains, true); err != nil {
		return nil, err
	}
	evicted := make([]net.IP, 0, len(evictedSet))
	for addr := range evictedSet {
		evicted = append(evicted, net.IP(addr.AsSlice()))
	}
	sortIPs(evicted)
	return evicted, nil
}

func maxUint64Deficit(a, aLimit, b, bLimit uint64) uint64 {
	var aDeficit, bDeficit uint64
	if a > aLimit {
		aDeficit = a - aLimit
	}
	if b > bLimit {
		bDeficit = b - bLimit
	}
	if aDeficit > bDeficit {
		return aDeficit
	}
	return bDeficit
}

func dnsUsageCapacityError(usage dnsOwnedUsage, limits dnsAdmissionLimits, capacity filter.DNSAllowOccupancy) error {
	if usage.physical4 > uint64(capacity.IPv4Capacity) || usage.physical6 > uint64(capacity.IPv6Capacity) {
		return dnsCapacityError("exact maps would use IPv4=%d/%d IPv6=%d/%d and no eligible DNS key can be reclaimed", usage.physical4, capacity.IPv4Capacity, usage.physical6, capacity.IPv6Capacity)
	}
	if usage.normal4 > uint64(limits.maxIPsPerFamily) || usage.normal6 > uint64(limits.maxIPsPerFamily) {
		return dnsCapacityError("exact working set would use IPv4=%d IPv6=%d, per-family limit is %d, and no eligible DNS key can be reclaimed", usage.normal4, usage.normal6, limits.maxIPsPerFamily)
	}
	if uint64(len(usage.domains)) > uint64(limits.maxTrackedDomains) {
		return dnsCapacityError("ownership would track %d total policy/query domains, limit is %d, and no complete query owner can be reclaimed", len(usage.domains), limits.maxTrackedDomains)
	}
	if usage.edges > uint64(limits.maxOwnershipEdges) {
		return dnsCapacityError("ownership would use %d edges, limit is %d, and no eligible DNS key can be reclaimed", usage.edges, limits.maxOwnershipEdges)
	}
	type ownerUsage struct {
		owner dnsPolicyOwner
		count int
	}
	var over []ownerUsage
	for owner, ips := range usage.ownerIPs {
		if uint64(len(ips)) > uint64(limits.maxIPsPerPolicyDomain) {
			over = append(over, ownerUsage{owner: owner, count: len(ips)})
		}
	}
	sort.Slice(over, func(i, j int) bool {
		if over[i].owner.kind != over[j].owner.kind {
			return over[i].owner.kind < over[j].owner.kind
		}
		return over[i].owner.domain < over[j].owner.domain
	})
	if len(over) != 0 {
		return dnsCapacityError("policy owner %q would own %d unique addresses, limit is %d, and no eligible DNS key can be reclaimed", over[0].owner.domain, over[0].count, limits.maxIPsPerPolicyDomain)
	}
	return dnsCapacityError("projected DNS state exceeds a bounded capacity and no eligible DNS key can be reclaimed")
}

func entryHasNormalOwner(entry dnsOwnedIP) bool {
	if entry.owners.occupied && entry.owners.inlineKey.owner.kind != dnsOwnerProvisional {
		return true
	}
	for edge := range entry.owners.overflow {
		if edge.owner.kind != dnsOwnerProvisional {
			return true
		}
	}
	return false
}

func projectUnexpiredDNSOwnedEntries(entries map[netip.Addr]dnsOwnedIP, now time.Time) map[netip.Addr]dnsOwnedIP {
	projected := make(map[netip.Addr]dnsOwnedIP, len(entries))
	for addr, entry := range entries {
		var owners dnsOwnerEdgeSet
		entry.owners.eachObserved(func(edge dnsOwnershipKey, deadline, observed time.Time) {
			if deadline.IsZero() || deadline.After(now) {
				owners.putMaxObserved(edge, deadline, observed)
			}
		})
		if owners.len() != 0 {
			projectedEntry := dnsOwnedIP{addr: addr, owners: owners}
			projectedEntry.lastObserved = dnsEntryLastObserved(projectedEntry)
			projected[addr] = projectedEntry
		}
	}
	return projected
}

// reconcile atomically moves all surviving normal edges to their new winning
// owner, removes blocked/expired/provisional ownership, preflights the complete
// projected metadata (including many-child -> one-wildcard remaps), then
// transactionally removes zero-owner kernel keys before publishing state.
func (m *dnsOwnershipManager) reconcile(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	return m.reconcileWithChurn(limits, m.churnLimits, policyDomains, resolve, authoritative)
}

func (m *dnsOwnershipManager) reconcileWithChurn(limits dnsAdmissionLimits, churn dnsChurnLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	if err := m.validateLimits(limits); err != nil {
		return err
	}
	if err := m.validateChurnLimits(churn); err != nil {
		return err
	}
	projected, err := m.projectReconcile(limits, policyDomains, resolve, authoritative)
	if err != nil {
		return err
	}
	toRemove := dnsEntryDifference(m.entries, projected)
	if m.filter != nil && len(toRemove) != 0 {
		if err := m.filter.RemoveDNSAllowedIPs(toRemove); err != nil {
			return err
		}
	}
	m.entries = projected
	m.limits = limits
	m.churnLimits = churn
	m.policyDomains = cloneDomainSet(policyDomains)
	m.rebuildOwnershipIndexes()
	return nil
}

func (m *dnsOwnershipManager) preflightReconcile(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	return m.preflightReconcileWithChurn(limits, m.churnLimits, policyDomains, resolve, authoritative)
}

func (m *dnsOwnershipManager) preflightReconcileWithChurn(limits dnsAdmissionLimits, churn dnsChurnLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	if err := m.validateLimits(limits); err != nil {
		return err
	}
	if err := m.validateChurnLimits(churn); err != nil {
		return err
	}
	_, err := m.projectReconcile(limits, policyDomains, resolve, authoritative)
	return err
}

func (m *dnsOwnershipManager) projectReconcile(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) (map[netip.Addr]dnsOwnedIP, error) {
	now := m.now()
	projected := make(map[netip.Addr]dnsOwnedIP, len(m.entries))
	for addr, entry := range m.entries {
		var owners dnsOwnerEdgeSet
		entry.owners.eachObserved(func(edge dnsOwnershipKey, deadline, observed time.Time) {
			if edge.owner.kind == dnsOwnerProvisional {
				if !authoritative {
					owners.putMaxObserved(edge, deadline, observed)
				}
				return
			}
			if !deadline.IsZero() && !deadline.After(now) {
				return
			}
			newOwner, ok := resolve(edge.query)
			if !ok {
				return
			}
			newEdge := dnsOwnershipKey{query: edge.query, owner: newOwner}
			owners.putMaxObserved(newEdge, deadline, observed)
		})
		if owners.len() != 0 {
			projectedEntry := dnsOwnedIP{addr: addr, owners: owners}
			projectedEntry.lastObserved = dnsEntryLastObserved(projectedEntry)
			projected[addr] = projectedEntry
		}
	}
	if err := validateDNSOwnedState(projected, limits, policyDomains, !authoritative); err != nil {
		return nil, fmt.Errorf("new DNS limits/policy cannot represent retained ownership atomically: %w", err)
	}
	return projected, nil
}

func (m *dnsOwnershipManager) expire(now time.Time) error {
	// The janitor runs every second while ordinary DNS lifetimes are at least
	// the configured floor (60s by default). Avoid cloning the full ownership
	// graph and rebuilding every reverse index on the overwhelmingly common
	// no-op ticks.
	needsExpiry := false
	for _, entry := range m.entries {
		entry.owners.each(func(_ dnsOwnershipKey, deadline time.Time) {
			if !deadline.IsZero() && !deadline.After(now) {
				needsExpiry = true
			}
		})
		if needsExpiry {
			break
		}
	}
	if !needsExpiry {
		return nil
	}

	projected := make(map[netip.Addr]dnsOwnedIP, len(m.entries))
	for addr, entry := range m.entries {
		var owners dnsOwnerEdgeSet
		entry.owners.eachObserved(func(edge dnsOwnershipKey, deadline, observed time.Time) {
			if deadline.IsZero() || deadline.After(now) {
				owners.putMaxObserved(edge, deadline, observed)
			}
		})
		if owners.len() != 0 {
			projectedEntry := dnsOwnedIP{addr: addr, owners: owners}
			projectedEntry.lastObserved = dnsEntryLastObserved(projectedEntry)
			projected[addr] = projectedEntry
		}
	}
	toRemove := dnsEntryDifference(m.entries, projected)
	if m.filter != nil && len(toRemove) != 0 {
		if err := m.filter.RemoveDNSAllowedIPs(toRemove); err != nil {
			return err
		}
	}
	m.entries = projected
	m.rebuildOwnershipIndexes()
	return nil
}

func (m *dnsOwnershipManager) rebuildOwnershipIndexes() {
	m.normalIPv4, m.normalIPv6, m.physicalIPv4, m.physicalIPv6, m.edgeCount = 0, 0, 0, 0, 0
	m.queryRefs = make(map[string]uint64)
	m.ownerIPRefs = make(map[dnsPolicyOwner]dnsOwnerIPRefSet)
	var physical4, physical6 uint64
	for addr, entry := range m.entries {
		if addr.Is4() {
			physical4++
		} else {
			physical6++
		}
		if entryHasNormalOwner(entry) {
			if addr.Is4() {
				m.normalIPv4++
			} else {
				m.normalIPv6++
			}
		}
		entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
			if edge.owner.kind == dnsOwnerProvisional {
				return
			}
			m.edgeCount++
			m.queryRefs[edge.query]++
			ownerRefs := m.ownerIPRefs[edge.owner]
			ownerRefs.increment(addr)
			m.ownerIPRefs[edge.owner] = ownerRefs
		})
	}
	m.physicalIPv4, m.physicalIPv6 = physical4, physical6
	domains := cloneDomainSet(m.policyDomains)
	for query := range m.queryRefs {
		domains[query] = struct{}{}
	}
	m.trackedDomains = uint64(len(domains))
	if physical4 > uint64(m.highWater4) {
		m.highWater4 = saturatingDNSCount(physical4)
	}
	if physical6 > uint64(m.highWater6) {
		m.highWater6 = saturatingDNSCount(physical6)
	}
	m.publishStats()
}

func validateDNSOwnedState(entries map[netip.Addr]dnsOwnedIP, limits dnsAdmissionLimits, policyDomains map[string]struct{}, allowProvisional bool) error {
	var ipv4, ipv6 uint64
	domains := cloneDomainSet(policyDomains)
	policyIPs := make(map[dnsPolicyOwner]map[netip.Addr]struct{})
	var edges uint64
	for addr, entry := range entries {
		countsAsNormalIP := false
		entry.owners.each(func(edge dnsOwnershipKey, _ time.Time) {
			if edge.owner.kind == dnsOwnerProvisional && allowProvisional {
				return
			}
			countsAsNormalIP = true
			edges++
			domains[edge.query] = struct{}{}
			set := policyIPs[edge.owner]
			if set == nil {
				set = make(map[netip.Addr]struct{})
				policyIPs[edge.owner] = set
			}
			set[addr] = struct{}{}
		})
		if countsAsNormalIP {
			if addr.Is4() {
				ipv4++
			} else {
				ipv6++
			}
		}
	}
	if ipv4 > uint64(limits.maxIPsPerFamily) || ipv6 > uint64(limits.maxIPsPerFamily) {
		return dnsCapacityError("exact working set would use IPv4=%d IPv6=%d, per-family limit is %d", ipv4, ipv6, limits.maxIPsPerFamily)
	}
	if uint64(len(domains)) > uint64(limits.maxTrackedDomains) {
		return dnsCapacityError("ownership would track %d total policy/query domains, limit is %d", len(domains), limits.maxTrackedDomains)
	}
	if edges > uint64(limits.maxOwnershipEdges) {
		return dnsCapacityError("ownership would use %d edges, limit is %d", edges, limits.maxOwnershipEdges)
	}
	type ownerUsage struct {
		owner dnsPolicyOwner
		count int
	}
	var overLimit []ownerUsage
	for owner, ips := range policyIPs {
		if uint64(len(ips)) > uint64(limits.maxIPsPerPolicyDomain) {
			overLimit = append(overLimit, ownerUsage{owner: owner, count: len(ips)})
		}
	}
	if len(overLimit) != 0 {
		sort.Slice(overLimit, func(i, j int) bool {
			if overLimit[i].owner.kind != overLimit[j].owner.kind {
				return overLimit[i].owner.kind < overLimit[j].owner.kind
			}
			return overLimit[i].owner.domain < overLimit[j].owner.domain
		})
		violation := overLimit[0]
		return dnsCapacityError("policy owner %q would own %d unique addresses, limit is %d", violation.owner.domain, violation.count, limits.maxIPsPerPolicyDomain)
	}
	return nil
}

func cloneDomainSet(domains map[string]struct{}) map[string]struct{} {
	clone := make(map[string]struct{}, len(domains))
	for domain := range domains {
		clone[domain] = struct{}{}
	}
	return clone
}

func cloneDNSOwnedEntries(entries map[netip.Addr]dnsOwnedIP) map[netip.Addr]dnsOwnedIP {
	clone := make(map[netip.Addr]dnsOwnedIP, len(entries))
	for addr, entry := range entries {
		clone[addr] = dnsOwnedIP{addr: entry.addr, owners: entry.owners.clone(), lastObserved: entry.lastObserved}
	}
	return clone
}

func dnsEntryDifference(before, after map[netip.Addr]dnsOwnedIP) []net.IP {
	removed := make([]net.IP, 0)
	for addr := range before {
		if _, ok := after[addr]; !ok {
			removed = append(removed, net.IP(addr.AsSlice()))
		}
	}
	sortIPs(removed)
	return removed
}

func sortIPs(ips []net.IP) {
	if len(ips) < 2 {
		return
	}
	sort.Slice(ips, func(i, j int) bool {
		a, _ := netip.AddrFromSlice(ips[i])
		b, _ := netip.AddrFromSlice(ips[j])
		a, b = a.Unmap(), b.Unmap()
		if a.Is4() != b.Is4() {
			return a.Is4()
		}
		return a.Less(b)
	})
}

func canonicalDNSAddr(ip net.IP) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid resolved IP %q", ip)
	}
	return addr.Unmap(), nil
}
