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
	contains(exactIPKey) (bool, error)
	put(exactIPKey) error
	delete(exactIPKey) error
}

func canonicalExactIPKey(ip net.IP) (exactIPKey, error) {
	var key exactIPKey
	if ip4 := ip.To4(); ip4 != nil {
		key.family = exactIPv4
		copy(key.addr[:4], ip4)
	} else if ip16 := ip.To16(); ip16 != nil {
		key.family = exactIPv6
		copy(key.addr[:], ip16)
	} else {
		return key, fmt.Errorf("DNS exact allow IP is invalid: %q", ip.String())
	}
	return key, nil
}

func sortExactIPKeys(keys []exactIPKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].family != keys[j].family {
			return keys[i].family < keys[j].family
		}
		return bytes.Compare(keys[i].addr[:], keys[j].addr[:]) < 0
	})
}

func inventoryExactDNS(b exactDNSBackend) ([]exactIPKey, DNSAllowOccupancy, error) {
	var inventory []exactIPKey
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
		}
		inventory = append(inventory, keys...)
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
	return inventory, occupancy, nil
}

// exactDNSState caches counts, not membership. A concrete filter is the sole
// writer and holds its mutex across lookup, mutation, rollback and publication.
// Pinned adoption inventories once; successful transactions touch only their keys.
type exactDNSState struct {
	initialized bool
	occupancy   DNSAllowOccupancy
}

func (s *exactDNSState) usage(b exactDNSBackend) (DNSAllowOccupancy, error) {
	if !s.initialized {
		_, occupancy, err := inventoryExactDNS(b)
		if err != nil {
			return DNSAllowOccupancy{}, err
		}
		s.occupancy, s.initialized = occupancy, true
	}
	return s.occupancy, nil
}

type exactChange struct {
	key           exactIPKey
	before, after bool
}

func (s *exactDNSState) replace(b exactDNSBackend, remove, add []net.IP) error {
	if len(remove)+len(add) == 0 {
		return nil
	}
	// Validate and deduplicate once. Adding wins overlap, preserving survivors.
	wanted := make(map[exactIPKey]bool, len(remove)+len(add))
	for adding, ips := range [][]net.IP{remove, add} {
		for _, ip := range ips {
			key, err := canonicalExactIPKey(ip)
			if err != nil {
				return err
			}
			wanted[key] = adding == 1
		}
	}
	occupancy, err := s.usage(b)
	if err != nil {
		return err
	}
	keys := make([]exactIPKey, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	sortExactIPKeys(keys)
	changes := make([]exactChange, 0, len(keys))
	final4, final6 := int64(occupancy.IPv4Entries), int64(occupancy.IPv6Entries)
	for _, key := range keys {
		before, err := b.contains(key)
		if err != nil {
			return fmt.Errorf("looking up DNS exact allow %s: %w", key.ip(), err)
		}
		after := wanted[key]
		if before == after {
			continue
		}
		changes = append(changes, exactChange{key, before, after})
		delta := int64(-1)
		if after {
			delta = 1
		}
		if key.family == exactIPv4 {
			final4 += delta
		} else {
			final6 += delta
		}
	}
	if final4 < 0 || final6 < 0 {
		s.initialized = false
		return fmt.Errorf("DNS exact occupancy changed outside the filter owner")
	}
	if final4 > int64(occupancy.IPv4Capacity) || final6 > int64(occupancy.IPv6Capacity) {
		return fmt.Errorf("%w: replacement uses IPv4 %d/%d, IPv6 %d/%d", ErrDNSAllowCapacity, final4, occupancy.IPv4Capacity, final6, occupancy.IPv6Capacity)
	}
	// Delete first so replacements fit a full map; overlap/survivors are untouched.
	for _, adding := range []bool{false, true} {
		for _, change := range changes {
			if change.after != adding {
				continue
			}
			if adding {
				err = b.put(change.key)
			} else {
				err = b.delete(change.key)
			}
			if err != nil {
				mutationErr := fmt.Errorf("mutating DNS exact allow %s: %w", change.key.ip(), err)
				if rollbackErr := restoreExactChanges(b, changes); rollbackErr != nil {
					s.initialized = false
					return errors.Join(mutationErr, fmt.Errorf("%w: %w", ErrDNSAllowRollback, rollbackErr))
				}
				return mutationErr
			}
		}
	}
	s.occupancy.IPv4Entries, s.occupancy.IPv6Entries = uint32(final4), uint32(final6)
	return nil
}

// Every syscall can affect only its named key. Restore all changed preimages,
// including the failing syscall's key; verify actual membership rather than
// interpreting intermediate errno values. Unrelated keys never need a snapshot.
func restoreExactChanges(b exactDNSBackend, changes []exactChange) error {
	var errs []error
	for _, restoring := range []bool{false, true} {
		for _, change := range changes {
			if change.before != restoring {
				continue
			}
			present, err := b.contains(change.key)
			if err == nil && present == change.before {
				continue
			}
			if restoring {
				err = b.put(change.key)
			} else {
				err = b.delete(change.key)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	proven := true
	for _, change := range changes {
		present, err := b.contains(change.key)
		if err != nil || present != change.before {
			proven = false
			errs = append(errs, fmt.Errorf("rollback cannot prove pre-state for %s: present=%t want=%t error=%v", change.key.ip(), present, change.before, err))
		}
	}
	if proven {
		return nil
	}
	return errors.Join(errs...)
}

func listExactDNSIPs(b exactDNSBackend) ([]net.IP, error) {
	keys, _, err := inventoryExactDNS(b)
	if err != nil {
		return nil, err
	}
	sortExactIPKeys(keys)
	ips := make([]net.IP, 0, len(keys))
	for _, key := range keys {
		ips = append(ips, key.ip())
	}
	return ips, nil
}
