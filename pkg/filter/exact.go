package filter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
)

type exactIPFamily uint8

const (
	exactIPv4 exactIPFamily = 4
	exactIPv6 exactIPFamily = 6
)

// exactIPKey is the architecture-independent userspace transaction key. The
// BPF adapter converts it to the exact native key layout used by each map.
type exactIPKey struct {
	family exactIPFamily
	addr   [16]byte
}

func (k exactIPKey) ip() net.IP {
	if k.family == exactIPv4 {
		return net.IPv4(k.addr[0], k.addr[1], k.addr[2], k.addr[3]).To4()
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip, k.addr[:])
	return ip
}

// exactDNSBackend is deliberately tiny so the all-or-rollback transaction
// can be exhaustively failure-injected without requiring a BPF-capable host.
// Production calls it while holding the concrete filter mutex; BPF never
// writes these userspace-owned maps.
type exactDNSBackend interface {
	keys(exactIPFamily) ([]exactIPKey, error)
	capacity(exactIPFamily) (uint32, error)
	put(exactIPKey) error
	delete(exactIPKey) error
}

func canonicalExactIPKeys(ips []net.IP) ([]exactIPKey, error) {
	seen := make(map[exactIPKey]struct{}, len(ips))
	for i, ip := range ips {
		if ip == nil {
			return nil, fmt.Errorf("DNS exact allow IP %d is nil", i)
		}
		var key exactIPKey
		if ip4 := ip.To4(); ip4 != nil {
			key.family = exactIPv4
			copy(key.addr[:4], ip4)
		} else if ip16 := ip.To16(); ip16 != nil {
			key.family = exactIPv6
			copy(key.addr[:], ip16)
		} else {
			return nil, fmt.Errorf("DNS exact allow IP %d is invalid: %q", i, ip.String())
		}
		seen[key] = struct{}{}
	}
	keys := make([]exactIPKey, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sortExactIPKeys(keys)
	return keys, nil
}

func sortExactIPKeys(keys []exactIPKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].family != keys[j].family {
			return keys[i].family < keys[j].family
		}
		return bytes.Compare(keys[i].addr[:], keys[j].addr[:]) < 0
	})
}

func snapshotExactDNS(b exactDNSBackend) (map[exactIPKey]struct{}, DNSAllowOccupancy, error) {
	snapshot := make(map[exactIPKey]struct{})
	var occupancy DNSAllowOccupancy
	for _, family := range []exactIPFamily{exactIPv4, exactIPv6} {
		keys, err := b.keys(family)
		if err != nil {
			return nil, occupancy, fmt.Errorf("listing DNS exact IPv%d allows: %w", family, err)
		}
		for _, key := range keys {
			if key.family != family {
				return nil, occupancy, fmt.Errorf("DNS exact IPv%d backend returned an IPv%d key", family, key.family)
			}
			snapshot[key] = struct{}{}
		}
		capacity, err := b.capacity(family)
		if err != nil {
			return nil, occupancy, fmt.Errorf("reading DNS exact IPv%d capacity: %w", family, err)
		}
		if family == exactIPv4 {
			occupancy.IPv4Entries = uint32(len(keys))
			occupancy.IPv4Capacity = capacity
		} else {
			occupancy.IPv6Entries = uint32(len(keys))
			occupancy.IPv6Capacity = capacity
		}
	}
	return snapshot, occupancy, nil
}

func addExactDNSIPs(b exactDNSBackend, ips []net.IP) error {
	keys, err := canonicalExactIPKeys(ips)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	before, occupancy, err := snapshotExactDNS(b)
	if err != nil {
		return err
	}
	var add4, add6 uint32
	for _, key := range keys {
		if _, exists := before[key]; exists {
			continue
		}
		if key.family == exactIPv4 {
			add4++
		} else {
			add6++
		}
	}
	if uint64(occupancy.IPv4Entries)+uint64(add4) > uint64(occupancy.IPv4Capacity) {
		return fmt.Errorf("%w: IPv4 map has %d/%d entries and batch needs %d new entries", ErrDNSAllowCapacity, occupancy.IPv4Entries, occupancy.IPv4Capacity, add4)
	}
	if uint64(occupancy.IPv6Entries)+uint64(add6) > uint64(occupancy.IPv6Capacity) {
		return fmt.Errorf("%w: IPv6 map has %d/%d entries and batch needs %d new entries", ErrDNSAllowCapacity, occupancy.IPv6Entries, occupancy.IPv6Capacity, add6)
	}
	for _, key := range keys {
		if _, exists := before[key]; exists {
			continue
		}
		if err := b.put(key); err != nil {
			return exactMutationFailure(b, before, fmt.Errorf("adding DNS exact allow %s: %w", key.ip(), err))
		}
	}
	return nil
}

func removeExactDNSIPs(b exactDNSBackend, ips []net.IP) error {
	keys, err := canonicalExactIPKeys(ips)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	before, _, err := snapshotExactDNS(b)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, exists := before[key]; !exists {
			continue
		}
		if err := b.delete(key); err != nil {
			return exactMutationFailure(b, before, fmt.Errorf("removing DNS exact allow %s: %w", key.ip(), err))
		}
	}
	return nil
}

// replaceExactDNSIPs applies one final-state transaction. Deletions happen
// before insertions so a full map can exchange keys, but every validation and
// final-capacity check happens before the first syscall. A key present in both
// sets remains present and is not touched.
func replaceExactDNSIPs(b exactDNSBackend, remove, add []net.IP) error {
	removeKeys, err := canonicalExactIPKeys(remove)
	if err != nil {
		return err
	}
	addKeys, err := canonicalExactIPKeys(add)
	if err != nil {
		return err
	}
	if len(removeKeys) == 0 && len(addKeys) == 0 {
		return nil
	}
	before, occupancy, err := snapshotExactDNS(b)
	if err != nil {
		return err
	}
	desired := make(map[exactIPKey]struct{}, len(before)+len(addKeys))
	for key := range before {
		desired[key] = struct{}{}
	}
	for _, key := range removeKeys {
		delete(desired, key)
	}
	for _, key := range addKeys {
		desired[key] = struct{}{}
	}
	var final4, final6 uint64
	for key := range desired {
		if key.family == exactIPv4 {
			final4++
		} else {
			final6++
		}
	}
	if final4 > uint64(occupancy.IPv4Capacity) {
		return fmt.Errorf("%w: replacement would use %d/%d IPv4 entries", ErrDNSAllowCapacity, final4, occupancy.IPv4Capacity)
	}
	if final6 > uint64(occupancy.IPv6Capacity) {
		return fmt.Errorf("%w: replacement would use %d/%d IPv6 entries", ErrDNSAllowCapacity, final6, occupancy.IPv6Capacity)
	}

	for _, key := range removeKeys {
		if _, existed := before[key]; !existed {
			continue
		}
		if _, keep := desired[key]; keep {
			continue
		}
		if err := b.delete(key); err != nil {
			return exactMutationFailure(b, before, fmt.Errorf("removing DNS exact allow %s during replacement: %w", key.ip(), err))
		}
	}
	for _, key := range addKeys {
		if _, existed := before[key]; existed {
			continue
		}
		if err := b.put(key); err != nil {
			return exactMutationFailure(b, before, fmt.Errorf("adding DNS exact allow %s during replacement: %w", key.ip(), err))
		}
	}
	return nil
}

func exactMutationFailure(b exactDNSBackend, before map[exactIPKey]struct{}, mutationErr error) error {
	if rollbackErr := restoreExactDNSSnapshot(b, before); rollbackErr != nil {
		return errors.Join(mutationErr, fmt.Errorf("%w: caller must fail closed/quarantine until exact-tier reconciliation: %w", ErrDNSAllowRollback, rollbackErr))
	}
	return mutationErr
}

// restoreExactDNSSnapshot restores the whole exact tier, not just successful
// syscalls recorded by the caller. That also covers an ambiguous failing
// syscall which may have reached the kernel before returning an error.
func restoreExactDNSSnapshot(b exactDNSBackend, want map[exactIPKey]struct{}) error {
	current, err := currentExactDNSKeys(b)
	if err != nil {
		return err
	}
	var errs []error
	var residual []exactIPKey
	for key := range current {
		if _, keep := want[key]; keep {
			continue
		}
		residual = append(residual, key)
	}
	sortExactIPKeys(residual)
	for _, key := range residual {
		if err := b.delete(key); err != nil {
			errs = append(errs, fmt.Errorf("deleting residual %s: %w", key.ip(), err))
		}
	}
	var missing []exactIPKey
	for key := range want {
		if _, present := current[key]; present {
			continue
		}
		missing = append(missing, key)
	}
	sortExactIPKeys(missing)
	for _, key := range missing {
		if err := b.put(key); err != nil {
			errs = append(errs, fmt.Errorf("restoring removed %s: %w", key.ip(), err))
		}
	}
	got, verifyErr := currentExactDNSKeys(b)
	if verifyErr == nil && exactSnapshotsEqual(want, got) {
		// A syscall may report an ambiguous failure after the kernel completed
		// it. The authoritative post-rollback snapshot, not the intermediate
		// errno, decides whether the pre-state is proven restored.
		return nil
	}
	if verifyErr != nil {
		errs = append(errs, fmt.Errorf("verifying rollback snapshot: %w", verifyErr))
	} else {
		errs = append(errs, fmt.Errorf("rollback snapshot differs: want %d keys, got %d", len(want), len(got)))
	}
	return errors.Join(errs...)
}

func currentExactDNSKeys(b exactDNSBackend) (map[exactIPKey]struct{}, error) {
	current := make(map[exactIPKey]struct{})
	for _, family := range []exactIPFamily{exactIPv4, exactIPv6} {
		keys, err := b.keys(family)
		if err != nil {
			return nil, fmt.Errorf("listing DNS exact IPv%d allows: %w", family, err)
		}
		for _, key := range keys {
			current[key] = struct{}{}
		}
	}
	return current, nil
}

func exactSnapshotsEqual(a, b map[exactIPKey]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

func listExactDNSIPs(b exactDNSBackend) ([]net.IP, error) {
	snapshot, _, err := snapshotExactDNS(b)
	if err != nil {
		return nil, err
	}
	keys := make([]exactIPKey, 0, len(snapshot))
	for key := range snapshot {
		keys = append(keys, key)
	}
	sortExactIPKeys(keys)
	ips := make([]net.IP, 0, len(keys))
	for _, key := range keys {
		ips = append(ips, key.ip())
	}
	return ips, nil
}

func exactDNSOccupancy(b exactDNSBackend) (DNSAllowOccupancy, error) {
	_, occupancy, err := snapshotExactDNS(b)
	return occupancy, err
}
