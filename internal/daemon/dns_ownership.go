package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

const (
	defaultDNSMaxIPsPerFamily       uint32 = 4096
	defaultDNSMaxIPsPerResponse     uint32 = 64
	defaultDNSMaxIPsPerPolicyDomain uint32 = 1024
	defaultDNSMaxTrackedDomains     uint32 = 1024
	defaultDNSMaxOwnershipEdges     uint32 = 8192
)

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
	addr   netip.Addr
	owners dnsOwnerEdgeSet
}

// dnsOwnerEdgeSet keeps the common sole ownership edge inline and allocates an
// overflow map only when an address is genuinely shared. Lookups stay O(1),
// unlike a linear small slice, and every userspace edge remains covered by the
// manager's maxOwnershipEdges bound.
type dnsOwnerEdgeSet struct {
	occupied       bool
	inlineKey      dnsOwnershipKey
	inlineDeadline time.Time
	overflow       map[dnsOwnershipKey]time.Time
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
	deadline, ok := owners.overflow[key]
	return deadline, ok
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
		owners.overflow[key] = maxDNSDeadline(old, deadline)
		return false
	}
	if owners.overflow == nil {
		owners.overflow = make(map[dnsOwnershipKey]time.Time)
	}
	owners.overflow[key] = deadline
	return true
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
	for key, deadline := range owners.overflow {
		fn(key, deadline)
	}
}

func (owners dnsOwnerEdgeSet) clone() dnsOwnerEdgeSet {
	clone := owners
	if owners.overflow != nil {
		clone.overflow = make(map[dnsOwnershipKey]time.Time, len(owners.overflow))
		for key, deadline := range owners.overflow {
			clone.overflow[key] = deadline
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
	errDNSAdmissionCapacity = errors.New("DNS admission capacity exceeded")
)

func dnsCapacityError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDNSAdmissionCapacity, fmt.Sprintf(format, args...))
}

// dnsOwnershipManager is a leaf object. Callers serialize it under the
// DNSServer policy lock, after acquiring the attachment mutation barrier.
// It never acquires either outer lock itself.
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
	policyDomains map[string]struct{}
	normalIPv4    uint64
	normalIPv6    uint64
	edgeCount     uint64
	queryRefs     map[string]uint64
	ownerIPRefs   map[dnsPolicyOwner]dnsOwnerIPRefSet
}

func newDNSOwnershipManager(f filter.Filter, limits dnsAdmissionLimits, minTTL time.Duration, now func() time.Time) (*dnsOwnershipManager, error) {
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
	}
	if f == nil {
		m.capacity = filter.DNSAllowOccupancy{
			IPv4Capacity: limits.maxIPsPerFamily,
			IPv6Capacity: limits.maxIPsPerFamily,
		}
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
	return m, nil
}

func (m *dnsOwnershipManager) validateLimits(limits dnsAdmissionLimits) error {
	if limits.maxIPsPerFamily > m.capacity.IPv4Capacity || limits.maxIPsPerFamily > m.capacity.IPv6Capacity {
		return fmt.Errorf("DNS max_ips_per_family %d exceeds actual exact-map capacities IPv4=%d IPv6=%d", limits.maxIPsPerFamily, m.capacity.IPv4Capacity, m.capacity.IPv6Capacity)
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
	canonical, err := canonicalizeDNSAdmissionRequest(req)
	if err != nil {
		return err
	}
	return m.admitCanonical(canonical)
}

func (m *dnsOwnershipManager) admitCanonical(req dnsCanonicalAdmissionRequest) error {
	query := string(req.queryDomain)
	owner := dnsPolicyOwner{kind: req.owner.kind, domain: string(req.owner.domain)}

	// Canonicalize and de-duplicate the entire response before any capacity
	// decision. Duplicate records consume one response slot/edge and extend to
	// the deterministic maximum effective deadline.
	now := m.now()
	deadlines := make(map[netip.Addr]time.Time, len(req.records))
	var onlyAddr netip.Addr
	var onlyIP net.IP
	for _, record := range req.records {
		addr, err := canonicalDNSAddr(record.ip)
		if err != nil {
			return err
		}
		ttl := record.ttl
		if ttl < m.minTTL {
			ttl = m.minTTL
		}
		deadline := now.Add(ttl)
		if old, ok := deadlines[addr]; !ok || old.Before(deadline) {
			deadlines[addr] = deadline
		}
		switch len(deadlines) {
		case 1:
			onlyAddr = addr
			onlyIP = normalizeIP(record.ip)
		default:
			onlyIP = nil
		}
	}
	if uint64(len(deadlines)) > uint64(m.limits.maxIPsPerResponse) {
		return dnsCapacityError("response has %d unique addresses, limit is %d", len(deadlines), m.limits.maxIPsPerResponse)
	}
	if len(deadlines) == 0 {
		return nil
	}
	edge := dnsOwnershipKey{query: query, owner: owner}
	refreshOnly := true
	for addr := range deadlines {
		entry, exists := m.entries[addr]
		if !exists {
			refreshOnly = false
			break
		}
		if _, owned := entry.owners.get(edge); !owned {
			refreshOnly = false
			break
		}
	}
	if refreshOnly {
		for addr, deadline := range deadlines {
			entry := m.entries[addr]
			old, _ := entry.owners.get(edge)
			if old != maxDNSDeadline(old, deadline) {
				entry.owners.putMax(edge, deadline)
				m.entries[addr] = entry
			}
		}
		return nil
	}

	projected4, projected6 := m.normalIPv4, m.normalIPv6
	projectedEdges := m.edgeCount
	newQueryDomain := m.queryRefs[query] == 0
	trackedDomains := uint64(len(m.policyDomains))
	for existingQuery := range m.queryRefs {
		if _, isPolicy := m.policyDomains[existingQuery]; !isPolicy {
			trackedDomains++
		}
	}
	if newQueryDomain {
		if _, isPolicy := m.policyDomains[query]; !isPolicy {
			trackedDomains++
		}
	}
	ownerIPs := m.ownerIPRefs[owner]
	projectedOwnerIPs := ownerIPs.uniqueLen()
	var toAdd []net.IP
	for addr := range deadlines {
		entry, physicalExists := m.entries[addr]
		if !physicalExists {
			ip := onlyIP
			if len(deadlines) != 1 || addr != onlyAddr {
				ip = net.IP(addr.AsSlice())
			}
			toAdd = append(toAdd, ip)
		}
		if _, edgeExists := entry.owners.get(edge); edgeExists {
			continue
		}
		projectedEdges++
		if !entryHasNormalOwner(entry) {
			if addr.Is4() {
				projected4++
			} else {
				projected6++
			}
		}
		if ownerIPs.count(addr) == 0 {
			projectedOwnerIPs++
		}
	}
	if projected4 > uint64(m.limits.maxIPsPerFamily) || projected6 > uint64(m.limits.maxIPsPerFamily) {
		return dnsCapacityError("exact working set would use IPv4=%d IPv6=%d, per-family limit is %d", projected4, projected6, m.limits.maxIPsPerFamily)
	}
	if trackedDomains > uint64(m.limits.maxTrackedDomains) {
		return dnsCapacityError("ownership would track %d total policy/query domains, limit is %d", trackedDomains, m.limits.maxTrackedDomains)
	}
	if projectedEdges > uint64(m.limits.maxOwnershipEdges) {
		return dnsCapacityError("ownership would use %d edges, limit is %d", projectedEdges, m.limits.maxOwnershipEdges)
	}
	if uint64(projectedOwnerIPs) > uint64(m.limits.maxIPsPerPolicyDomain) {
		return dnsCapacityError("policy owner %q would own %d unique addresses, limit is %d", owner.domain, projectedOwnerIPs, m.limits.maxIPsPerPolicyDomain)
	}
	sortIPs(toAdd)
	if m.filter != nil && len(toAdd) != 0 {
		if err := m.filter.AddDNSAllowedIPs(toAdd); err != nil {
			return err
		}
	}
	for addr, deadline := range deadlines {
		entry, exists := m.entries[addr]
		if !exists {
			entry = dnsOwnedIP{addr: addr}
		}
		// The manager has not published any userspace change yet: the whole
		// preflight and exact-map add above completed against m.entries as it
		// stood on entry. Rechecking that unchanged entry avoids a redundant
		// per-response new-edge map while preserving the same projected counts.
		_, edgeExists := entry.owners.get(edge)
		isNewEdge := !edgeExists
		if isNewEdge {
			if !entryHasNormalOwner(entry) {
				if addr.Is4() {
					m.normalIPv4++
				} else {
					m.normalIPv6++
				}
			}
			m.edgeCount++
			m.queryRefs[query]++
			ownerRefs := m.ownerIPRefs[owner]
			ownerRefs.increment(addr)
			m.ownerIPRefs[owner] = ownerRefs
		}
		entry.owners.putMax(edge, deadline)
		m.entries[addr] = entry
	}
	return nil
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

// reconcile atomically moves all surviving normal edges to their new winning
// owner, removes blocked/expired/provisional ownership, preflights the complete
// projected metadata (including many-child -> one-wildcard remaps), then
// transactionally removes zero-owner kernel keys before publishing state.
func (m *dnsOwnershipManager) reconcile(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	if err := m.validateLimits(limits); err != nil {
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
	m.policyDomains = cloneDomainSet(policyDomains)
	m.rebuildOwnershipIndexes()
	return nil
}

func (m *dnsOwnershipManager) preflightReconcile(limits dnsAdmissionLimits, policyDomains map[string]struct{}, resolve dnsOwnershipResolver, authoritative bool) error {
	if err := m.validateLimits(limits); err != nil {
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
		entry.owners.each(func(edge dnsOwnershipKey, deadline time.Time) {
			if edge.owner.kind == dnsOwnerProvisional {
				if !authoritative {
					owners.putMax(edge, deadline)
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
			owners.putMax(newEdge, deadline)
		})
		if owners.len() != 0 {
			projected[addr] = dnsOwnedIP{addr: addr, owners: owners}
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
		entry.owners.each(func(edge dnsOwnershipKey, deadline time.Time) {
			if deadline.IsZero() || deadline.After(now) {
				owners.putMax(edge, deadline)
			}
		})
		if owners.len() != 0 {
			projected[addr] = dnsOwnedIP{addr: addr, owners: owners}
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
	m.normalIPv4, m.normalIPv6, m.edgeCount = 0, 0, 0
	m.queryRefs = make(map[string]uint64)
	m.ownerIPRefs = make(map[dnsPolicyOwner]dnsOwnerIPRefSet)
	for addr, entry := range m.entries {
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
		clone[addr] = dnsOwnedIP{addr: entry.addr, owners: entry.owners.clone()}
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
