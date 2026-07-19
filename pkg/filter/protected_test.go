package filter

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

type fakeProtectedBackend struct {
	entries            map[protectedRuleKey]struct{}
	caps               [4]uint32
	current            PolicyMode
	ops                []string
	putN               int
	deleteN            int
	failPut            map[int]bool
	failDelete         map[int]bool
	mutateFailedPut    bool
	mutateFailedDelete bool
	keysErr            map[protectedRuleBucket]error
	capacityErr        map[protectedRuleBucket]error
	countErr           map[protectedRuleBucket]error
	countOverride      map[protectedRuleBucket]uint32
	keysN              int
	keysErrAt          map[int]error
	keysOverrideAt     map[int][]protectedRuleKey
	modeReadErr        error
	modeWriteErr       map[PolicyMode]error
	mutateFailedMode   bool
	modeReadN          int
	modeWriteN         int
	modeReadErrAt      map[int]error
	modeReadValueAt    map[int]PolicyMode
	modeWriteErrAt     map[int]error
	modeWriteMutateAt  map[int]bool
}

func newFakeProtectedBackend(capacity uint32, mode PolicyMode, allowed, denied []string) *fakeProtectedBackend {
	b := &fakeProtectedBackend{
		entries:           make(map[protectedRuleKey]struct{}),
		caps:              [4]uint32{capacity, capacity, capacity, capacity},
		current:           mode,
		failPut:           make(map[int]bool),
		failDelete:        make(map[int]bool),
		keysErr:           make(map[protectedRuleBucket]error),
		capacityErr:       make(map[protectedRuleBucket]error),
		countErr:          make(map[protectedRuleBucket]error),
		countOverride:     make(map[protectedRuleBucket]uint32),
		keysErrAt:         make(map[int]error),
		keysOverrideAt:    make(map[int][]protectedRuleKey),
		modeWriteErr:      make(map[PolicyMode]error),
		modeReadErrAt:     make(map[int]error),
		modeReadValueAt:   make(map[int]PolicyMode),
		modeWriteErrAt:    make(map[int]error),
		modeWriteMutateAt: make(map[int]bool),
	}
	keys, err := canonicalProtectedRuleKeys(parseProtectedTestCIDRs(allowed), parseProtectedTestCIDRs(denied))
	if err != nil {
		panic(err)
	}
	for _, key := range keys {
		b.entries[key] = struct{}{}
	}
	return b
}

func parseProtectedTestCIDRs(raw []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raw))
	for _, value := range raw {
		cidr, err := ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		out = append(out, cidr)
	}
	return out
}

func (b *fakeProtectedBackend) keys(bucket protectedRuleBucket) ([]protectedRuleKey, error) {
	b.keysN++
	if err := b.keysErrAt[b.keysN]; err != nil {
		return nil, err
	}
	if override, ok := b.keysOverrideAt[b.keysN]; ok {
		return append([]protectedRuleKey(nil), override...), nil
	}
	if err := b.keysErr[bucket]; err != nil {
		return nil, err
	}
	var out []protectedRuleKey
	for key := range b.entries {
		if key.bucket == bucket {
			out = append(out, key)
		}
	}
	sortProtectedRuleKeys(out)
	return out, nil
}

func (b *fakeProtectedBackend) count(bucket protectedRuleBucket) (uint32, error) {
	if err := b.countErr[bucket]; err != nil {
		return 0, err
	}
	if count, ok := b.countOverride[bucket]; ok {
		return count, nil
	}
	var count uint32
	for key := range b.entries {
		if key.bucket == bucket {
			count++
		}
	}
	return count, nil
}

func (b *fakeProtectedBackend) capacity(bucket protectedRuleBucket) (uint32, error) {
	if err := b.capacityErr[bucket]; err != nil {
		return 0, err
	}
	return b.caps[bucket], nil
}

func (b *fakeProtectedBackend) put(key protectedRuleKey) error {
	b.putN++
	b.ops = append(b.ops, "put "+key.bucket.String()+" "+key.cidr().String())
	if b.failPut[b.putN] {
		if b.mutateFailedPut {
			b.entries[key] = struct{}{}
		}
		return syscall.EIO
	}
	b.entries[key] = struct{}{}
	return nil
}

func (b *fakeProtectedBackend) delete(key protectedRuleKey) error {
	b.deleteN++
	b.ops = append(b.ops, "delete "+key.bucket.String()+" "+key.cidr().String())
	if b.failDelete[b.deleteN] {
		if b.mutateFailedDelete {
			delete(b.entries, key)
		}
		return syscall.EIO
	}
	delete(b.entries, key)
	return nil
}

func (b *fakeProtectedBackend) mode() (PolicyMode, error) {
	b.modeReadN++
	if err := b.modeReadErrAt[b.modeReadN]; err != nil {
		return ModeDisabled, err
	}
	if mode, ok := b.modeReadValueAt[b.modeReadN]; ok {
		return mode, nil
	}
	if b.modeReadErr != nil {
		return ModeDisabled, b.modeReadErr
	}
	return b.current, nil
}

func (b *fakeProtectedBackend) setMode(mode PolicyMode) error {
	b.modeWriteN++
	b.ops = append(b.ops, "mode "+mode.String())
	if err := b.modeWriteErrAt[b.modeWriteN]; err != nil {
		if b.modeWriteMutateAt[b.modeWriteN] {
			b.current = mode
		}
		return err
	}
	if err := b.modeWriteErr[mode]; err != nil {
		if b.mutateFailedMode {
			b.current = mode
		}
		return err
	}
	b.current = mode
	return nil
}

func protectedBackendStrings(b *fakeProtectedBackend) (allowed, denied []string) {
	keys := make([]protectedRuleKey, 0, len(b.entries))
	for key := range b.entries {
		keys = append(keys, key)
	}
	sortProtectedRuleKeys(keys)
	for _, key := range keys {
		if key.bucket == protectedAllowedIPv4 || key.bucket == protectedAllowedIPv6 {
			allowed = append(allowed, key.cidr().String())
		} else {
			denied = append(denied, key.cidr().String())
		}
	}
	return
}

func TestProtectedCanonicalUsesMaskWidthForIPv4MappedIPv6(t *testing.T) {
	cidr := &net.IPNet{IP: net.ParseIP("::ffff:192.0.2.1"), Mask: net.CIDRMask(128, 128)}
	keys, err := canonicalProtectedRuleKeys([]*net.IPNet{cidr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].bucket != protectedAllowedIPv6 || keys[0].prefixLen != 128 {
		t.Fatalf("mapped IPv6 /128 was misclassified: %+v", keys)
	}
}

func TestProtectedReplacementPreflightsEveryFinalMapBeforeMutation(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeAllowlist, []string{"10.0.0.0/8"}, []string{"2001:db8::/32"})
	b.caps[protectedDeniedIPv6] = 1
	err := replaceProtectedRules(b,
		parseProtectedTestCIDRs([]string{"10.0.0.0/8", "192.0.2.0/24"}),
		parseProtectedTestCIDRs([]string{"2001:db8::/32", "2001:db9::/32"}),
		ModeDenylist,
	)
	if !errors.Is(err, ErrProtectedRuleCapacity) {
		t.Fatalf("want capacity error, got %v", err)
	}
	if len(b.ops) != 0 {
		t.Fatalf("preflight failure mutated backend: %v", b.ops)
	}
	allowed, denied := protectedBackendStrings(b)
	if !reflect.DeepEqual(allowed, []string{"10.0.0.0/8"}) || !reflect.DeepEqual(denied, []string{"2001:db8::/32"}) {
		t.Fatalf("preflight changed snapshot: allow=%v deny=%v", allowed, denied)
	}
}

func TestProtectedModeFlipPreparesTargetListThenMutatesOldListInert(t *testing.T) {
	b := newFakeProtectedBackend(4, ModeAllowlist,
		[]string{"10.0.0.0/8", "172.16.0.0/12"}, []string{"192.0.2.0/24"})
	err := replaceProtectedRules(b,
		parseProtectedTestCIDRs([]string{"10.0.0.0/8"}),
		parseProtectedTestCIDRs([]string{"198.51.100.0/24"}),
		ModeDenylist,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"put denied IPv4 198.51.100.0/24",
		"delete denied IPv4 192.0.2.0/24",
		"mode denylist",
		"delete allowed IPv4 172.16.0.0/12",
	}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("unsafe/non-deterministic flip order:\nwant %v\n got %v", want, b.ops)
	}
}

func TestProtectedActiveDenyUsesHeadroomWithoutBlockAll(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeDenylist, nil, []string{"192.0.2.0/24"})
	err := replaceProtectedRules(b, nil, parseProtectedTestCIDRs([]string{"198.51.100.0/24"}), ModeDenylist)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"put denied IPv4 198.51.100.0/24", "delete denied IPv4 192.0.2.0/24"}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("headroom exchange should not stage BLOCK_ALL: want %v got %v", want, b.ops)
	}
}

func TestProtectedFullActiveDenyExchangeProvesBlockAll(t *testing.T) {
	b := newFakeProtectedBackend(1, ModeDenylist, nil, []string{"192.0.2.0/24"})
	err := replaceProtectedRules(b, nil, parseProtectedTestCIDRs([]string{"198.51.100.0/24"}), ModeDenylist)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mode block_all",
		"delete denied IPv4 192.0.2.0/24",
		"put denied IPv4 198.51.100.0/24",
		"mode denylist",
	}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("full active deny exchange order: want %v got %v", want, b.ops)
	}
}

func TestProtectedDenylistToDisabledMakesMapsInertFirst(t *testing.T) {
	b := newFakeProtectedBackend(1, ModeDenylist, nil, []string{"192.0.2.0/24"})
	err := replaceProtectedRules(b, nil, parseProtectedTestCIDRs([]string{"198.51.100.0/24"}), ModeDisabled)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mode disabled",
		"delete denied IPv4 192.0.2.0/24",
		"put denied IPv4 198.51.100.0/24",
	}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("deny->disabled must make maps inert first: want %v got %v", want, b.ops)
	}
}

func TestProtectedRollbackErrorsAfterEffectAreResolvedByExactInventory(t *testing.T) {
	b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
	b.failPut[1], b.failPut[2] = true, true
	b.failDelete[2] = true
	b.mutateFailedPut, b.mutateFailedDelete = true, true
	err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("want original forward failure, got %v", err)
	}
	if errors.Is(err, ErrProtectedRuleRollback) {
		t.Fatalf("exact final inventory must resolve ambiguous restore syscalls: %v", err)
	}
	allowed, _ := protectedBackendStrings(b)
	if !reflect.DeepEqual(allowed, []string{"192.0.2.1/32"}) || b.current != ModeBlockAll {
		t.Fatalf("rollback not exact/fail-closed: allow=%v mode=%v ops=%v", allowed, b.current, b.ops)
	}
}

func TestProtectedRollbackResidualIsTypedAmbiguity(t *testing.T) {
	b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
	b.failPut[1] = true
	b.mutateFailedPut = true
	b.failDelete[2] = true // rollback cannot remove ambiguously-added key
	err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
	if !errors.Is(err, ErrProtectedRuleRollback) {
		t.Fatalf("residual map state must be typed rollback ambiguity: %v", err)
	}
}

func TestProtectedSnapshotRejectsNonCanonicalBackendKey(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeAllowlist, nil, nil)
	bad := protectedRuleKey{bucket: protectedAllowedIPv4, prefixLen: 24}
	copy(bad.addr[:4], net.ParseIP("192.0.2.9").To4())
	b.entries[bad] = struct{}{}
	err := replaceProtectedRules(b, nil, nil, ModeAllowlist)
	if !errors.Is(err, ErrProtectedRuleSnapshot) {
		t.Fatalf("non-canonical physical key must make snapshot unprovable: %v", err)
	}
	if len(b.ops) != 0 {
		t.Fatalf("invalid snapshot mutated backend: %v", b.ops)
	}
}

func TestProtectedAllModePairsConvergeWithoutUnnecessaryBlockAll(t *testing.T) {
	modes := []PolicyMode{ModeDisabled, ModeAllowlist, ModeBlockAll, ModeDenylist}
	for _, oldMode := range modes {
		for _, targetMode := range modes {
			t.Run(oldMode.String()+"_to_"+targetMode.String(), func(t *testing.T) {
				b := newFakeProtectedBackend(4, oldMode,
					[]string{"10.0.0.0/8"}, []string{"192.0.2.0/24"})
				err := replaceProtectedRules(b,
					parseProtectedTestCIDRs([]string{"10.0.0.0/8", "2001:db8::/32"}),
					parseProtectedTestCIDRs([]string{"192.0.2.0/24", "2001:db9::/32"}),
					targetMode)
				if err != nil {
					t.Fatal(err)
				}
				if b.current != targetMode {
					t.Fatalf("mode did not converge: want %s got %s", targetMode, b.current)
				}
				allowed, denied := protectedBackendStrings(b)
				if !reflect.DeepEqual(allowed, []string{"10.0.0.0/8", "2001:db8::/32"}) ||
					!reflect.DeepEqual(denied, []string{"192.0.2.0/24", "2001:db9::/32"}) {
					t.Fatalf("wrong final projection: allow=%v deny=%v", allowed, denied)
				}
				if targetMode != ModeBlockAll {
					for _, op := range b.ops {
						if op == "mode block_all" {
							t.Fatalf("headroom transition staged unnecessary BLOCK_ALL: %v", b.ops)
						}
					}
				}
			})
		}
	}
}

func TestProtectedSameModeAllowFullExchangeIsFailClosedWithoutModeWrite(t *testing.T) {
	b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
	err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"delete allowed IPv4 192.0.2.1/32", "put allowed IPv4 192.0.2.2/32"}
	if !reflect.DeepEqual(b.ops, want) {
		t.Fatalf("active allow full exchange should be remove/add without mode churn: %v", b.ops)
	}
}

func TestProtectedNoopDedupesCanonicalAliasesAndNeverTouchesSurvivor(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeAllowlist, []string{"192.0.2.0/24"}, []string{"2001:db8::/32"})
	alias := &net.IPNet{IP: net.ParseIP("192.0.2.99"), Mask: net.CIDRMask(24, 32)}
	err := replaceProtectedRules(b,
		[]*net.IPNet{alias, parseProtectedTestCIDRs([]string{"192.0.2.0/24"})[0]},
		[]*net.IPNet{parseProtectedTestCIDRs([]string{"2001:db8::1/32"})[0]},
		ModeAllowlist)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.ops) != 0 {
		t.Fatalf("canonical overlap/no-op touched survivors: %v", b.ops)
	}
}

func TestProtectedInvalidInputIsTrueNoop(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeAllowlist, []string{"192.0.2.0/24"}, nil)
	err := replaceProtectedRules(b, []*net.IPNet{nil}, nil, ModeDenylist)
	if err == nil {
		t.Fatal("nil CIDR must fail validation")
	}
	if len(b.ops) != 0 || b.keysN != 0 || b.current != ModeAllowlist {
		t.Fatalf("invalid pre-projection input mutated/read backend: ops=%v keys=%d mode=%s", b.ops, b.keysN, b.current)
	}
}

func TestProtectedCrossFamilyForwardFailureRollsBackWholeSnapshot(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeAllowlist, nil, nil)
	b.failPut[2] = true // IPv4 add succeeds; IPv6 add fails.
	err := replaceProtectedRules(b,
		parseProtectedTestCIDRs([]string{"192.0.2.1/32", "2001:db8::1/128"}), nil, ModeAllowlist)
	if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrProtectedRuleRollback) {
		t.Fatalf("want proven cross-family rollback of original failure, got %v", err)
	}
	allowed, denied := protectedBackendStrings(b)
	if len(allowed) != 0 || len(denied) != 0 || b.current != ModeBlockAll {
		t.Fatalf("cross-family rollback leaked state: allow=%v deny=%v mode=%s", allowed, denied, b.current)
	}
}

func TestProtectedAmbiguousAppliedDeleteRestoresProvenSnapshot(t *testing.T) {
	b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
	b.failDelete[1] = true
	b.mutateFailedDelete = true
	err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
	if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrProtectedRuleRollback) {
		t.Fatalf("ambiguous applied delete should restore cleanly: %v", err)
	}
	allowed, _ := protectedBackendStrings(b)
	if !reflect.DeepEqual(allowed, []string{"192.0.2.1/32"}) || b.current != ModeBlockAll {
		t.Fatalf("ambiguous delete rollback wrong: allow=%v mode=%s", allowed, b.current)
	}
}

func TestProtectedSnapshotFailuresAreTypedAndMutationFree(t *testing.T) {
	tests := []struct {
		name string
		prep func(*fakeProtectedBackend)
	}{
		{name: "keys", prep: func(b *fakeProtectedBackend) { b.keysErr[protectedAllowedIPv6] = syscall.EIO }},
		{name: "capacity", prep: func(b *fakeProtectedBackend) { b.capacityErr[protectedDeniedIPv4] = syscall.EIO }},
		{name: "mode", prep: func(b *fakeProtectedBackend) { b.modeReadErr = syscall.EIO }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(2, ModeAllowlist, nil, nil)
			tc.prep(b)
			err := replaceProtectedRules(b, nil, nil, ModeDenylist)
			if !errors.Is(err, ErrProtectedRuleSnapshot) {
				t.Fatalf("want typed snapshot failure, got %v", err)
			}
			if len(b.ops) != 0 {
				t.Fatalf("snapshot failure mutated backend: %v", b.ops)
			}
		})
	}
}

func TestProtectedAmbiguousTargetModeWriteResolvedByReadback(t *testing.T) {
	b := newFakeProtectedBackend(2, ModeAllowlist, nil, []string{"192.0.2.0/24"})
	b.modeWriteErrAt[1] = syscall.EIO
	b.modeWriteMutateAt[1] = true
	err := replaceProtectedRules(b, nil, parseProtectedTestCIDRs([]string{"198.51.100.0/24"}), ModeDenylist)
	if err != nil {
		t.Fatalf("target mode readback should resolve ambiguous write: %v", err)
	}
	if b.current != ModeDenylist {
		t.Fatalf("target mode not effective: %s", b.current)
	}
}

func TestProtectedActiveDenyBlockAllWriteMustBeProvenBeforeMapMutation(t *testing.T) {
	t.Run("readback_old", func(t *testing.T) {
		b := newFakeProtectedBackend(1, ModeDenylist, nil, []string{"192.0.2.0/24"})
		b.modeWriteErrAt[1] = syscall.EIO // BLOCK_ALL did not apply.
		err := replaceProtectedRules(b, nil, parseProtectedTestCIDRs([]string{"198.51.100.0/24"}), ModeDenylist)
		if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrProtectedRuleRollback) {
			t.Fatalf("untouched maps should return staging error without map rollback sentinel: %v", err)
		}
		for _, op := range b.ops {
			if strings.HasPrefix(op, "delete ") || strings.HasPrefix(op, "put ") {
				t.Fatalf("map mutated without proven BLOCK_ALL: %v", b.ops)
			}
		}
	})
	t.Run("ambiguous_applied", func(t *testing.T) {
		b := newFakeProtectedBackend(1, ModeDenylist, nil, []string{"192.0.2.0/24"})
		b.modeWriteErrAt[1] = syscall.EIO
		b.modeWriteMutateAt[1] = true
		if err := replaceProtectedRules(b, nil, parseProtectedTestCIDRs([]string{"198.51.100.0/24"}), ModeDenylist); err != nil {
			t.Fatalf("BLOCK_ALL readback should resolve ambiguous staging: %v", err)
		}
	})
}

func TestProtectedRollbackInventoryValidationCannotFalseProve(t *testing.T) {
	tests := []struct {
		name string
		key  protectedRuleKey
	}{
		{name: "wrong_bucket", key: protectedRuleKey{bucket: protectedDeniedIPv4, prefixLen: 32, addr: [16]byte{192, 0, 2, 1}}},
		{name: "host_bits", key: protectedRuleKey{bucket: protectedAllowedIPv4, prefixLen: 24, addr: [16]byte{192, 0, 2, 9}}},
		{name: "invalid_prefix", key: protectedRuleKey{bucket: protectedAllowedIPv4, prefixLen: 33, addr: [16]byte{192, 0, 2, 1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
			b.failPut[1] = true
			// Calls 1-4 are initial snapshot; call 5 is rollback allowed-v4 inventory.
			b.keysOverrideAt[5] = []protectedRuleKey{tc.key}
			err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
			if !errors.Is(err, ErrProtectedRuleRollback) {
				t.Fatalf("invalid rollback inventory must be typed ambiguity: %v", err)
			}
		})
	}
}

func TestProtectedTargetModeFailureAlwaysRollsBackPreparedMap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readback PolicyMode
	}{
		{name: "old", readback: ModeAllowlist},
		{name: "third", readback: ModeDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(2, ModeAllowlist,
				[]string{"10.0.0.0/8"}, []string{"192.0.2.0/24"})
			b.modeWriteErrAt[1] = syscall.EIO
			b.modeReadValueAt[2] = tc.readback
			err := replaceProtectedRules(b,
				parseProtectedTestCIDRs([]string{"10.0.0.0/8"}),
				parseProtectedTestCIDRs([]string{"198.51.100.0/24"}),
				ModeDenylist)
			if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrProtectedRuleRollback) || errors.Is(err, ErrProtectedRuleModeAmbiguous) {
				t.Fatalf("target-mode failure should retain original error after exact rollback: %v", err)
			}
			allowed, denied := protectedBackendStrings(b)
			if !reflect.DeepEqual(allowed, []string{"10.0.0.0/8"}) ||
				!reflect.DeepEqual(denied, []string{"192.0.2.0/24"}) || b.current != ModeBlockAll {
				t.Fatalf("target-mode rollback wrong: allow=%v deny=%v mode=%s ops=%v", allowed, denied, b.current, b.ops)
			}
		})
	}
}

func TestProtectedFailedBlockAllStagingAfterInertMutationRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readback PolicyMode
		readErr  error
	}{
		{name: "old", readback: ModeDenylist},
		{name: "third", readback: ModeDisabled},
		{name: "read_error", readErr: syscall.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(1, ModeDenylist,
				[]string{"10.0.0.0/8"}, []string{"192.0.2.0/24"})
			b.modeWriteErrAt[1] = syscall.EIO
			if tc.readErr != nil {
				b.modeReadErrAt[2] = tc.readErr
			} else {
				b.modeReadValueAt[2] = tc.readback
			}
			err := replaceProtectedRules(b,
				parseProtectedTestCIDRs([]string{"172.16.0.0/12"}),
				parseProtectedTestCIDRs([]string{"198.51.100.0/24"}),
				ModeDenylist)
			if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrProtectedRuleRollback) || errors.Is(err, ErrProtectedRuleModeAmbiguous) {
				t.Fatalf("failed staging should be recovered by a separately proven rollback hold: %v", err)
			}
			allowed, denied := protectedBackendStrings(b)
			if !reflect.DeepEqual(allowed, []string{"10.0.0.0/8"}) ||
				!reflect.DeepEqual(denied, []string{"192.0.2.0/24"}) || b.current != ModeBlockAll {
				t.Fatalf("staging rollback wrong: allow=%v deny=%v mode=%s ops=%v", allowed, denied, b.current, b.ops)
			}
		})
	}
}

func TestProtectedRollbackRefusesMapMutationUntilBlockAllIsProven(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readback PolicyMode
		readErr  error
	}{
		{name: "old", readback: ModeDenylist},
		{name: "third", readback: ModeDisabled},
		{name: "read_error", readErr: syscall.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(1, ModeDenylist,
				[]string{"10.0.0.0/8"}, []string{"192.0.2.0/24"})
			// The first failed write is the active-deny staging attempt after the
			// inert allow map changed. The second is rollback's independent hold.
			b.modeWriteErrAt[1], b.modeWriteErrAt[2] = syscall.EIO, syscall.EIO
			b.modeReadValueAt[2] = ModeDenylist
			if tc.readErr != nil {
				b.modeReadErrAt[3] = tc.readErr
			} else {
				b.modeReadValueAt[3] = tc.readback
			}
			err := replaceProtectedRules(b,
				parseProtectedTestCIDRs([]string{"172.16.0.0/12"}),
				parseProtectedTestCIDRs([]string{"198.51.100.0/24"}),
				ModeDenylist)
			if !errors.Is(err, ErrProtectedRuleRollback) {
				t.Fatalf("unproven rollback hold must be typed rollback ambiguity: %v", err)
			}
			mapOps := 0
			for _, op := range b.ops {
				if strings.HasPrefix(op, "put ") || strings.HasPrefix(op, "delete ") {
					mapOps++
				}
			}
			if mapOps != 2 {
				t.Fatalf("rollback touched maps without proven BLOCK_ALL: ops=%v", b.ops)
			}
		})
	}
}

func TestProtectedExactRollbackFinalModeReadbackMatrix(t *testing.T) {
	for _, tc := range []struct {
		name        string
		final       PolicyMode
		wantModeErr bool
	}{
		{name: "old", final: ModeAllowlist},
		{name: "block_all", final: ModeBlockAll},
		{name: "third", final: ModeDisabled, wantModeErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
			b.failPut[1] = true
			// write/read #1 stages rollback BLOCK_ALL. The final write is #2;
			// make its direct read fail and exercise the explicit fallback read.
			b.modeWriteErrAt[2] = syscall.EIO
			b.modeReadErrAt[3] = syscall.EIO
			b.modeReadValueAt[4] = tc.final
			err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
			if tc.wantModeErr {
				if !errors.Is(err, ErrProtectedRuleModeAmbiguous) || errors.Is(err, ErrProtectedRuleRollback) {
					t.Fatalf("third posture must be typed mode ambiguity only: %v", err)
				}
			} else if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrProtectedRuleRollback) || errors.Is(err, ErrProtectedRuleModeAmbiguous) {
				t.Fatalf("old/BLOCK_ALL fallback proves safe exact rollback: %v", err)
			}
			allowed, _ := protectedBackendStrings(b)
			if !reflect.DeepEqual(allowed, []string{"192.0.2.1/32"}) {
				t.Fatalf("final-mode ambiguity changed exact map rollback: %v", allowed)
			}
		})
	}
}

func TestProtectedRollbackFinalInventoryCannotFalseProve(t *testing.T) {
	oldKeys, err := canonicalProtectedRuleKeys(parseProtectedTestCIDRs([]string{"192.0.2.1/32"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		prep func(*fakeProtectedBackend)
	}{
		{name: "read_error", prep: func(b *fakeProtectedBackend) { b.keysErrAt[9] = syscall.EIO }},
		{name: "mismatch", prep: func(b *fakeProtectedBackend) { b.keysOverrideAt[9] = nil }},
		{name: "duplicate", prep: func(b *fakeProtectedBackend) {
			b.keysOverrideAt[9] = []protectedRuleKey{oldKeys[0], oldKeys[0]}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(1, ModeAllowlist, []string{"192.0.2.1/32"}, nil)
			b.failPut[1] = true
			tc.prep(b)
			err := replaceProtectedRules(b, parseProtectedTestCIDRs([]string{"192.0.2.2/32"}), nil, ModeAllowlist)
			if !errors.Is(err, ErrProtectedRuleRollback) {
				t.Fatalf("unprovable final rollback inventory must be typed ambiguity: %v", err)
			}
		})
	}
}

func TestProtectedRuleOccupancyFaultsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(*fakeProtectedBackend)
	}{
		{name: "count", prep: func(b *fakeProtectedBackend) { b.countErr[protectedAllowedIPv6] = syscall.EIO }},
		{name: "capacity", prep: func(b *fakeProtectedBackend) { b.capacityErr[protectedDeniedIPv4] = syscall.EIO }},
		{name: "over_capacity", prep: func(b *fakeProtectedBackend) {
			b.countOverride[protectedDeniedIPv6] = 3
			b.caps[protectedDeniedIPv6] = 2
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeProtectedBackend(2, ModeAllowlist, []string{"192.0.2.0/24"}, []string{"2001:db8::/32"})
			tc.prep(b)
			if _, err := protectedRuleOccupancy(b); err == nil {
				t.Fatal("invalid occupancy snapshot unexpectedly succeeded")
			}
		})
	}

	b := newFakeProtectedBackend(7, ModeAllowlist,
		[]string{"192.0.2.0/24", "2001:db8::/32"},
		[]string{"198.51.100.0/24", "2001:db9::/32"})
	got, err := protectedRuleOccupancy(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, usage := range []RuleMapUsage{got.AllowedIPv4, got.AllowedIPv6, got.DeniedIPv4, got.DeniedIPv6} {
		if usage.Entries != 1 || usage.Capacity != 7 {
			t.Fatalf("wrong per-map occupancy: %+v", got)
		}
	}
}
