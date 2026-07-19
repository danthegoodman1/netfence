package filter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
)

type protectedRuleBucket uint8

const (
	protectedAllowedIPv4 protectedRuleBucket = iota
	protectedAllowedIPv6
	protectedDeniedIPv4
	protectedDeniedIPv6
)

var protectedRuleBuckets = [...]protectedRuleBucket{
	protectedAllowedIPv4,
	protectedAllowedIPv6,
	protectedDeniedIPv4,
	protectedDeniedIPv6,
}

func (b protectedRuleBucket) String() string {
	switch b {
	case protectedAllowedIPv4:
		return "allowed IPv4"
	case protectedAllowedIPv6:
		return "allowed IPv6"
	case protectedDeniedIPv4:
		return "denied IPv4"
	case protectedDeniedIPv6:
		return "denied IPv6"
	default:
		return fmt.Sprintf("unknown protected bucket %d", b)
	}
}

type protectedRuleKey struct {
	bucket    protectedRuleBucket
	prefixLen uint32
	addr      [16]byte
}

func (k protectedRuleKey) cidr() *net.IPNet {
	if k.bucket == protectedAllowedIPv4 || k.bucket == protectedDeniedIPv4 {
		ip := net.IPv4(k.addr[0], k.addr[1], k.addr[2], k.addr[3]).To4()
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(k.prefixLen), 32)}
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip, k.addr[:])
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(k.prefixLen), 128)}
}

// protectedRuleBackend is implemented by the concrete eBPF adapter and a
// fault-injectable unit-test backend. Production holds the concrete filter
// mutex for the complete transaction; these LPM maps have no other writer.
type protectedRuleBackend interface {
	keys(protectedRuleBucket) ([]protectedRuleKey, error)
	count(protectedRuleBucket) (uint32, error)
	capacity(protectedRuleBucket) (uint32, error)
	put(protectedRuleKey) error
	delete(protectedRuleKey) error
	mode() (PolicyMode, error)
	setMode(PolicyMode) error
}

func canonicalProtectedRuleKeys(allowed, denied []*net.IPNet) ([]protectedRuleKey, error) {
	keys := make(map[protectedRuleKey]struct{}, len(allowed)+len(denied))
	appendList := func(cidrs []*net.IPNet, deniedList bool) error {
		for i, cidr := range cidrs {
			if cidr == nil || cidr.IP == nil || cidr.Mask == nil {
				return fmt.Errorf("protected CIDR %d is nil", i)
			}
			ones, bits := cidr.Mask.Size()
			if ones < 0 || (bits != 32 && bits != 128) {
				return fmt.Errorf("protected CIDR %d has an invalid mask", i)
			}
			var key protectedRuleKey
			key.prefixLen = uint32(ones)
			switch bits {
			case 32:
				ip4 := cidr.IP.To4()
				if ip4 == nil {
					return fmt.Errorf("protected CIDR %d has a 32-bit mask but is not IPv4", i)
				}
				if deniedList {
					key.bucket = protectedDeniedIPv4
				} else {
					key.bucket = protectedAllowedIPv4
				}
				copy(key.addr[:4], ip4.Mask(cidr.Mask))
			case 128:
				ip16 := cidr.IP.To16()
				if ip16 == nil {
					return fmt.Errorf("protected CIDR %d has a 128-bit mask but is not IPv6", i)
				}
				if deniedList {
					key.bucket = protectedDeniedIPv6
				} else {
					key.bucket = protectedAllowedIPv6
				}
				copy(key.addr[:], ip16.Mask(cidr.Mask))
			default:
				return fmt.Errorf("protected CIDR %d has unsupported address width %d", i, bits)
			}
			keys[key] = struct{}{}
		}
		return nil
	}
	if err := appendList(allowed, false); err != nil {
		return nil, fmt.Errorf("canonicalizing allowed rules: %w", err)
	}
	if err := appendList(denied, true); err != nil {
		return nil, fmt.Errorf("canonicalizing denied rules: %w", err)
	}
	out := make([]protectedRuleKey, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sortProtectedRuleKeys(out)
	return out, nil
}

func sortProtectedRuleKeys(keys []protectedRuleKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].bucket != keys[j].bucket {
			return keys[i].bucket < keys[j].bucket
		}
		if keys[i].prefixLen != keys[j].prefixLen {
			return keys[i].prefixLen < keys[j].prefixLen
		}
		return bytes.Compare(keys[i].addr[:], keys[j].addr[:]) < 0
	})
}

func snapshotProtectedRules(b protectedRuleBackend) (map[protectedRuleKey]struct{}, ProtectedRuleOccupancy, error) {
	snapshot := make(map[protectedRuleKey]struct{})
	var occupancy ProtectedRuleOccupancy
	for _, bucket := range protectedRuleBuckets {
		keys, err := b.keys(bucket)
		if err != nil {
			return nil, occupancy, fmt.Errorf("%w: listing %s rules: %v", ErrProtectedRuleSnapshot, bucket, err)
		}
		for _, key := range keys {
			if key.bucket != bucket {
				return nil, occupancy, fmt.Errorf("%w: %s backend returned key for %s", ErrProtectedRuleSnapshot, bucket, key.bucket)
			}
			if err := validateProtectedRuleKey(key); err != nil {
				return nil, occupancy, fmt.Errorf("%w: invalid %s key: %v", ErrProtectedRuleSnapshot, bucket, err)
			}
			snapshot[key] = struct{}{}
		}
		capacity, err := b.capacity(bucket)
		if err != nil {
			return nil, occupancy, fmt.Errorf("%w: reading %s capacity: %v", ErrProtectedRuleSnapshot, bucket, err)
		}
		if uint64(len(keys)) > uint64(capacity) {
			return nil, occupancy, fmt.Errorf("%w: %s inventory has %d entries above capacity %d", ErrProtectedRuleSnapshot, bucket, len(keys), capacity)
		}
		setProtectedUsage(&occupancy, bucket, RuleMapUsage{Entries: uint32(len(keys)), Capacity: capacity})
	}
	return snapshot, occupancy, nil
}

func validateProtectedRuleKey(key protectedRuleKey) error {
	bits := uint32(128)
	if key.bucket == protectedAllowedIPv4 || key.bucket == protectedDeniedIPv4 {
		bits = 32
		for _, b := range key.addr[4:] {
			if b != 0 {
				return fmt.Errorf("IPv4 key has non-zero trailing bytes")
			}
		}
	}
	if key.prefixLen > bits {
		return fmt.Errorf("prefix %d exceeds address width %d", key.prefixLen, bits)
	}
	byteLen := int(bits / 8)
	fullBytes := int(key.prefixLen / 8)
	partialBits := key.prefixLen % 8
	if partialBits != 0 {
		mask := byte(0xff << (8 - partialBits))
		if key.addr[fullBytes]&^mask != 0 {
			return fmt.Errorf("address has host bits set after prefix %d", key.prefixLen)
		}
		fullBytes++
	}
	for _, b := range key.addr[fullBytes:byteLen] {
		if b != 0 {
			return fmt.Errorf("address has host bytes set after prefix %d", key.prefixLen)
		}
	}
	return nil
}

func setProtectedUsage(occupancy *ProtectedRuleOccupancy, bucket protectedRuleBucket, usage RuleMapUsage) {
	switch bucket {
	case protectedAllowedIPv4:
		occupancy.AllowedIPv4 = usage
	case protectedAllowedIPv6:
		occupancy.AllowedIPv6 = usage
	case protectedDeniedIPv4:
		occupancy.DeniedIPv4 = usage
	case protectedDeniedIPv6:
		occupancy.DeniedIPv6 = usage
	}
}

func protectedUsage(occupancy ProtectedRuleOccupancy, bucket protectedRuleBucket) RuleMapUsage {
	switch bucket {
	case protectedAllowedIPv4:
		return occupancy.AllowedIPv4
	case protectedAllowedIPv6:
		return occupancy.AllowedIPv6
	case protectedDeniedIPv4:
		return occupancy.DeniedIPv4
	default:
		return occupancy.DeniedIPv6
	}
}

func setAndProveProtectedMode(b protectedRuleBackend, want PolicyMode) error {
	writeErr := b.setMode(want)
	got, readErr := b.mode()
	if readErr == nil && got == want {
		// The authoritative read-back resolves an ambiguous write error.
		return nil
	}
	var errs []error
	if writeErr != nil {
		errs = append(errs, fmt.Errorf("writing policy mode %s: %w", want, writeErr))
	}
	if readErr != nil {
		errs = append(errs, fmt.Errorf("reading policy mode after writing %s: %w", want, readErr))
	} else if got != want {
		errs = append(errs, fmt.Errorf("policy mode write was not effective: want %s, got %s", want, got))
	}
	return errors.Join(errs...)
}

// replaceProtectedRules applies one complete final state and policy mode across
// all four maps. It preflights before every mutation, preserves survivors, and
// orders active/inert lists so ordinary reconciliation has no fail-open window.
// BLOCK_ALL is staged only when an active deny map lacks add-first headroom or
// while rolling a failed transaction back to its exact prior map inventory.
// A proven rollback may deliberately leave mode BLOCK_ALL instead of restoring
// the pre-call mode; callers must reconcile before reactivation.
func replaceProtectedRules(b protectedRuleBackend, allowed, denied []*net.IPNet, targetMode PolicyMode) error {
	if targetMode != ModeDisabled && targetMode != ModeAllowlist && targetMode != ModeBlockAll && targetMode != ModeDenylist {
		return fmt.Errorf("invalid protected-rule target mode %d", targetMode)
	}
	desiredKeys, err := canonicalProtectedRuleKeys(allowed, denied)
	if err != nil {
		return err
	}
	before, occupancy, err := snapshotProtectedRules(b)
	if err != nil {
		return err
	}
	desired := make(map[protectedRuleKey]struct{}, len(desiredKeys))
	var final [4]uint64
	for _, key := range desiredKeys {
		desired[key] = struct{}{}
		final[key.bucket]++
	}
	for _, bucket := range protectedRuleBuckets {
		usage := protectedUsage(occupancy, bucket)
		if final[bucket] > uint64(usage.Capacity) {
			return fmt.Errorf("%w: final %s state needs %d/%d entries", ErrProtectedRuleCapacity, bucket, final[bucket], usage.Capacity)
		}
	}
	oldMode, err := b.mode()
	if err != nil {
		return fmt.Errorf("%w: reading protected policy mode: %w", ErrProtectedRuleSnapshot, err)
	}
	if oldMode != ModeDisabled && oldMode != ModeAllowlist && oldMode != ModeBlockAll && oldMode != ModeDenylist {
		return fmt.Errorf("%w: invalid current protected policy mode %d", ErrProtectedRuleSnapshot, oldMode)
	}

	type bucketDelta struct {
		bucket   protectedRuleBucket
		remove   []protectedRuleKey
		add      []protectedRuleKey
		addFirst bool
	}
	deltas := make(map[protectedRuleBucket]bucketDelta, len(protectedRuleBuckets))
	for _, bucket := range protectedRuleBuckets {
		delta := bucketDelta{bucket: bucket}
		for key := range before {
			if key.bucket == bucket {
				if _, keep := desired[key]; !keep {
					delta.remove = append(delta.remove, key)
				}
			}
		}
		for key := range desired {
			if key.bucket == bucket {
				if _, present := before[key]; !present {
					delta.add = append(delta.add, key)
				}
			}
		}
		sortProtectedRuleKeys(delta.remove)
		sortProtectedRuleKeys(delta.add)
		usage := protectedUsage(occupancy, bucket)
		delta.addFirst = uint64(usage.Entries)+uint64(len(delta.add)) <= uint64(usage.Capacity)
		deltas[bucket] = delta
	}

	mapAttempted := false
	applyDelta := func(delta bucketDelta) error {
		applyAdd := func() error {
			for _, key := range delta.add {
				mapAttempted = true
				if err := b.put(key); err != nil {
					return fmt.Errorf("adding protected %s rule %s: %w", key.bucket, key.cidr(), err)
				}
			}
			return nil
		}
		applyRemove := func() error {
			for _, key := range delta.remove {
				mapAttempted = true
				if err := b.delete(key); err != nil {
					return fmt.Errorf("removing protected %s rule %s: %w", key.bucket, key.cidr(), err)
				}
			}
			return nil
		}
		if delta.addFirst {
			if err := applyAdd(); err != nil {
				return err
			}
			return applyRemove()
		}
		if err := applyRemove(); err != nil {
			return err
		}
		return applyAdd()
	}
	applyList := func(denyList bool) error {
		if denyList {
			if err := applyDelta(deltas[protectedDeniedIPv4]); err != nil {
				return err
			}
			return applyDelta(deltas[protectedDeniedIPv6])
		}
		if err := applyDelta(deltas[protectedAllowedIPv4]); err != nil {
			return err
		}
		return applyDelta(deltas[protectedAllowedIPv6])
	}
	listChanged := func(denyList bool) bool {
		buckets := []protectedRuleBucket{protectedAllowedIPv4, protectedAllowedIPv6}
		if denyList {
			buckets = []protectedRuleBucket{protectedDeniedIPv4, protectedDeniedIPv6}
		}
		for _, bucket := range buckets {
			d := deltas[bucket]
			if len(d.add) != 0 || len(d.remove) != 0 {
				return true
			}
		}
		return false
	}
	activeDenyNeedsBlockAll := oldMode == ModeDenylist && targetMode == ModeDenylist &&
		((len(deltas[protectedDeniedIPv4].add) != 0 && !deltas[protectedDeniedIPv4].addFirst) ||
			(len(deltas[protectedDeniedIPv6].add) != 0 && !deltas[protectedDeniedIPv6].addFirst))
	mutated := false
	fail := func(forwardErr error) error {
		return protectedMutationFailure(b, before, oldMode, mapAttempted, forwardErr)
	}
	apply := func(denyList bool) error {
		if !listChanged(denyList) {
			return nil
		}
		mutated = true
		return applyList(denyList)
	}
	setMode := func(mode PolicyMode) error {
		if oldMode == mode && !mutated {
			return nil
		}
		if err := setAndProveProtectedMode(b, mode); err != nil {
			return fmt.Errorf("setting protected policy mode to %s: %w", mode, err)
		}
		mutated = true
		return nil
	}

	switch {
	case oldMode == targetMode:
		// Inert list first; the active map is always the last map mutation.
		if targetMode == ModeAllowlist {
			if err := apply(true); err != nil {
				return fail(err)
			}
			if err := apply(false); err != nil {
				return fail(err)
			}
		} else if targetMode == ModeDenylist {
			if err := apply(false); err != nil {
				return fail(err)
			}
			if activeDenyNeedsBlockAll {
				if err := setAndProveProtectedMode(b, ModeBlockAll); err != nil {
					return fail(fmt.Errorf("staging BLOCK_ALL for full active deny exchange: %w", err))
				}
				mutated = true
			}
			if err := apply(true); err != nil {
				return fail(err)
			}
			if activeDenyNeedsBlockAll {
				if err := setAndProveProtectedMode(b, targetMode); err != nil {
					return fail(fmt.Errorf("restoring target mode after full active deny exchange: %w", err))
				}
			}
		} else {
			if err := apply(false); err != nil {
				return fail(err)
			}
			if err := apply(true); err != nil {
				return fail(err)
			}
		}
	case targetMode == ModeAllowlist:
		if err := apply(false); err != nil {
			return fail(err)
		}
		if err := setMode(targetMode); err != nil {
			return fail(err)
		}
		if err := apply(true); err != nil {
			return fail(err)
		}
	case targetMode == ModeDenylist:
		if err := apply(true); err != nil {
			return fail(err)
		}
		if err := setMode(targetMode); err != nil {
			return fail(err)
		}
		if err := apply(false); err != nil {
			return fail(err)
		}
	case targetMode == ModeBlockAll:
		if err := setMode(targetMode); err != nil {
			return fail(err)
		}
		if err := apply(false); err != nil {
			return fail(err)
		}
		if err := apply(true); err != nil {
			return fail(err)
		}
	default: // target disabled: publish intended open posture, then both maps are inert.
		if oldMode != targetMode {
			if err := setMode(targetMode); err != nil {
				return fail(err)
			}
		}
		if err := apply(false); err != nil {
			return fail(err)
		}
		if err := apply(true); err != nil {
			return fail(err)
		}
	}
	return nil
}

func protectedMutationFailure(b protectedRuleBackend, before map[protectedRuleKey]struct{}, oldMode PolicyMode, mapAttempted bool, mutationErr error) error {
	if rollbackErr := restoreProtectedRuleSnapshot(b, before, oldMode, mapAttempted); rollbackErr != nil {
		if errors.Is(rollbackErr, ErrProtectedRuleModeAmbiguous) {
			return errors.Join(mutationErr, rollbackErr)
		}
		return errors.Join(mutationErr, fmt.Errorf("%w: attachment must remain BLOCK_ALL until authoritative reconciliation: %w", ErrProtectedRuleRollback, rollbackErr))
	}
	return mutationErr
}

func restoreProtectedRuleSnapshot(b protectedRuleBackend, want map[protectedRuleKey]struct{}, oldMode PolicyMode, mapAttempted bool) error {
	if err := setAndProveProtectedMode(b, ModeBlockAll); err != nil {
		if !mapAttempted {
			// No map syscall happened. This is a clean map rollback only when a
			// read-back proves either the exact old posture or fail-closed posture.
			got, readErr := b.mode()
			if readErr == nil && (got == oldMode || got == ModeBlockAll) {
				return nil
			}
			return fmt.Errorf("%w: mode after failed staging is not provably old=%s or BLOCK_ALL: %v", ErrProtectedRuleModeAmbiguous, oldMode, errors.Join(err, readErr))
		}
		return fmt.Errorf("cannot safely restore protected maps without proven BLOCK_ALL: %w", err)
	}
	var operationErrs []error
	current, err := currentProtectedRuleKeys(b)
	if err != nil {
		return err
	}
	remove := make([]protectedRuleKey, 0)
	for key := range current {
		if _, keep := want[key]; !keep {
			remove = append(remove, key)
		}
	}
	sortProtectedRuleKeys(remove)
	for _, key := range remove {
		if err := b.delete(key); err != nil {
			operationErrs = append(operationErrs, fmt.Errorf("deleting residual %s %s: %w", key.bucket, key.cidr(), err))
		}
	}
	add := make([]protectedRuleKey, 0)
	for key := range want {
		if _, present := current[key]; !present {
			add = append(add, key)
		}
	}
	sortProtectedRuleKeys(add)
	for _, key := range add {
		if err := b.put(key); err != nil {
			operationErrs = append(operationErrs, fmt.Errorf("restoring %s %s: %w", key.bucket, key.cidr(), err))
		}
	}
	got, verifyErr := currentProtectedRuleKeys(b)
	if verifyErr != nil {
		return errors.Join(append(operationErrs, fmt.Errorf("verifying protected rollback snapshot: %w", verifyErr))...)
	} else if !protectedSnapshotsEqual(want, got) {
		return errors.Join(append(operationErrs, fmt.Errorf("protected rollback snapshot differs: want %d keys, got %d", len(want), len(got)))...)
	}
	// Ambiguous restore syscalls are resolved by the authoritative final
	// inventory. Once exact equality is proven, their errno values are incident
	// detail only and do not make rollback ambiguous.
	if err := setAndProveProtectedMode(b, ModeBlockAll); err != nil {
		got, readErr := b.mode()
		if readErr != nil || (got != oldMode && got != ModeBlockAll) {
			return fmt.Errorf("%w: mode after exact map rollback is not provably old=%s or BLOCK_ALL: %v", ErrProtectedRuleModeAmbiguous, oldMode, errors.Join(err, readErr))
		}
	}
	// A proven rollback deliberately remains BLOCK_ALL. The authoritative
	// caller persists degraded state before any later reconcile may reopen it.
	return nil
}

func currentProtectedRuleKeys(b protectedRuleBackend) (map[protectedRuleKey]struct{}, error) {
	out := make(map[protectedRuleKey]struct{})
	for _, bucket := range protectedRuleBuckets {
		keys, err := b.keys(bucket)
		if err != nil {
			return nil, fmt.Errorf("listing %s rules: %w", bucket, err)
		}
		for _, key := range keys {
			if key.bucket != bucket {
				return nil, fmt.Errorf("%s backend returned key for %s", bucket, key.bucket)
			}
			if err := validateProtectedRuleKey(key); err != nil {
				return nil, fmt.Errorf("invalid %s rollback-inventory key: %w", bucket, err)
			}
			if _, duplicate := out[key]; duplicate {
				return nil, fmt.Errorf("duplicate %s rollback-inventory key %s", bucket, key.cidr())
			}
			out[key] = struct{}{}
		}
	}
	return out, nil
}

func protectedSnapshotsEqual(a, b map[protectedRuleKey]struct{}) bool {
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

func protectedRuleOccupancy(b protectedRuleBackend) (ProtectedRuleOccupancy, error) {
	var occupancy ProtectedRuleOccupancy
	for _, bucket := range protectedRuleBuckets {
		entries, err := b.count(bucket)
		if err != nil {
			return ProtectedRuleOccupancy{}, fmt.Errorf("counting %s rules: %w", bucket, err)
		}
		capacity, err := b.capacity(bucket)
		if err != nil {
			return ProtectedRuleOccupancy{}, fmt.Errorf("reading %s capacity: %w", bucket, err)
		}
		if entries > capacity {
			return ProtectedRuleOccupancy{}, fmt.Errorf("%s count %d exceeds capacity %d", bucket, entries, capacity)
		}
		setProtectedUsage(&occupancy, bucket, RuleMapUsage{Entries: entries, Capacity: capacity})
	}
	return occupancy, nil
}
