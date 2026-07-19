package daemon

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

// ttlEffectFilter models the two ambiguous syscall outcomes the ordinary fake
// cannot: a returned error after the map changed, and an ambiguous full replace.
type ttlEffectFilter struct {
	*fakeFilter
	afterAdd, afterRemove, afterReplace error
	replaceAmbiguous                    bool
}

func (f *ttlEffectFilter) AllowIP(cidr *net.IPNet) error {
	if err := f.fakeFilter.AllowIP(cidr); err != nil {
		return err
	}
	return f.afterAdd
}

func (f *ttlEffectFilter) DenyIP(cidr *net.IPNet) error {
	if err := f.fakeFilter.DenyIP(cidr); err != nil {
		return err
	}
	return f.afterAdd
}

func (f *ttlEffectFilter) RemoveAllowedIP(cidr *net.IPNet) error {
	if err := f.fakeFilter.RemoveAllowedIP(cidr); err != nil {
		return err
	}
	return f.afterRemove
}

func (f *ttlEffectFilter) RemoveDeniedIP(cidr *net.IPNet) error {
	if err := f.fakeFilter.RemoveDeniedIP(cidr); err != nil {
		return err
	}
	return f.afterRemove
}

func (f *ttlEffectFilter) ReplaceProtectedRules(allow, deny []*net.IPNet, mode filter.PolicyMode) error {
	beforeMode, beforeAllow, beforeDeny, _ := f.snapshot()
	if err := f.fakeFilter.ReplaceProtectedRules(allow, deny, mode); err != nil || f.afterReplace == nil {
		return err
	}
	if f.replaceAmbiguous {
		return errors.Join(f.afterReplace, filter.ErrProtectedRuleRollback)
	}
	f.mu.Lock()
	f.mode, f.allowed, f.denied = beforeMode, beforeAllow, beforeDeny
	f.mu.Unlock()
	return f.afterReplace
}

func ttlEntryFor(t testing.TB, reg *ttlRegistry, cidr *net.IPNet, list ruleList) (protectedEntry, bool) {
	t.Helper()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	entry, ok := reg.entries[ttlKey{cidr: cidr.String(), list: list}]
	return entry, ok
}

func allowedRules(f *fakeFilter) []string {
	_, allowed, _, _ := f.snapshot()
	return allowed
}

func TestTTLProvisionalAndFailedExplicitRemove(t *testing.T) {
	cidr := mustCIDR(t, "192.0.2.90/32")
	base := &fakeFilter{allowed: []string{cidr.String()}}
	ff := &ttlEffectFilter{fakeFilter: base}
	reg := newTTLRegistry()
	require.NoError(t, reg.seedAdopted([]*net.IPNet{cidr}, nil))

	rules := reg.snapshotRules()
	require.Len(t, rules, 1)
	assert.True(t, rules[0].policyOwned)
	assert.True(t, rules[0].provisional)
	assert.Zero(t, reg.pendingLen())

	require.NoError(t, reg.addCP(ff, cidr, listAllow, time.Minute, time.Unix(100, 0)))
	entry, ok := ttlEntryFor(t, reg, cidr, listAllow)
	require.True(t, ok)
	assert.Equal(t, cpPermanent, entry.cp, "finite add cannot demote an adopted pin")

	ff.afterRemove = syscall.EIO
	require.ErrorIs(t, reg.remove(ff, cidr, listAllow), syscall.EIO)
	entry, ok = ttlEntryFor(t, reg, cidr, listAllow)
	require.True(t, ok)
	assert.Equal(t, cpPermanent, entry.cp, "failed explicit remove retains prior CP ownership")
	assert.True(t, entry.registryPresent)
	assertProtectedCurrent(t, reg, 1, 0, 0, 0)
	assert.Empty(t, allowedRules(base), "after-effect error may diverge from registry belief")
}

func TestTTLFailedOwnerClearingBecomesSourceLessRetry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, op := range []string{"clear", "expiry", "remove-system"} {
		t.Run(op, func(t *testing.T) {
			cidr := mustCIDR(t, "198.51.100.90/32")
			base := &fakeFilter{}
			ff := &ttlEffectFilter{fakeFilter: base}
			reg := newTTLRegistry()
			switch op {
			case "clear":
				require.NoError(t, reg.addCP(ff, cidr, listAllow, 0, now))
			case "expiry":
				require.NoError(t, reg.addCP(ff, cidr, listAllow, time.Second, now))
			case "remove-system":
				require.NoError(t, reg.addSystem(ff, cidr, listAllow))
			}

			ff.afterRemove = syscall.EIO
			var err error
			switch op {
			case "clear":
				err = reg.clear(ff)
			case "expiry":
				err = reg.expire(ff, now.Add(time.Second))[0].err
			case "remove-system":
				err = reg.removeSystem(ff, cidr, listAllow)
			}
			require.ErrorIs(t, err, syscall.EIO)
			entry, ok := ttlEntryFor(t, reg, cidr, listAllow)
			require.True(t, ok)
			assert.Equal(t, cpNone, entry.cp)
			assert.False(t, entry.system)
			assert.True(t, entry.registryPresent)

			ff.afterRemove = nil
			swept := reg.expire(ff, now.Add(2*time.Second))
			require.Len(t, swept, 1)
			require.NoError(t, swept[0].err)
			_, ok = ttlEntryFor(t, reg, cidr, listAllow)
			assert.False(t, ok)
			assertProtectedCurrent(t, reg, 0, 0, 0, 0)
		})
	}
}

func TestTTLIncrementalErrorKeepsPreState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cidr := mustCIDR(t, "203.0.113.91/32")
	base := &fakeFilter{}
	ff := &ttlEffectFilter{fakeFilter: base, afterAdd: errors.Join(syscall.ENOSPC, syscall.E2BIG)}
	reg := newTTLRegistry()
	require.Error(t, reg.addCP(ff, cidr, listAllow, time.Minute, now))
	_, ok := ttlEntryFor(t, reg, cidr, listAllow)
	assert.False(t, ok)
	assert.Equal(t, uint64(1), reg.mapFullCount(), "joined capacity markers count once")
	assert.Equal(t, []string{cidr.String()}, allowedRules(base))

	reg = newTTLRegistry()
	require.NoError(t, reg.addCP(nil, cidr, listAllow, time.Minute, now))
	before, _ := ttlEntryFor(t, reg, cidr, listAllow)
	ff = &ttlEffectFilter{fakeFilter: &fakeFilter{}, afterAdd: syscall.EIO}
	require.ErrorIs(t, reg.addCP(ff, cidr, listAllow, 2*time.Minute, now), syscall.EIO)
	after, _ := ttlEntryFor(t, reg, cidr, listAllow)
	assert.Equal(t, before, after)
	assertProtectedCurrent(t, reg, 0, 0, 0, 0)
}

func TestTTLAuthoritativeErrorPublishesOnlyProvenOutcome(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	oldCIDR, newCIDR := mustCIDR(t, "192.0.2.92/32"), mustCIDR(t, "192.0.2.93/32")
	for _, tt := range []struct {
		name      string
		ambiguous bool
		physical  string
	}{
		{name: "verified-rollback", physical: oldCIDR.String()},
		{name: "typed-ambiguity", ambiguous: true, physical: newCIDR.String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeFilter{allowed: []string{oldCIDR.String()}, mode: filter.ModeAllowlist}
			ff := &ttlEffectFilter{fakeFilter: base, afterReplace: syscall.EIO, replaceAmbiguous: tt.ambiguous}
			reg := newTTLRegistry()
			require.NoError(t, reg.seedAdopted([]*net.IPNet{oldCIDR}, nil))
			err := reg.reconcileAuthoritative(ff, filter.ModeAllowlist, []parsedCIDR{{cidr: newCIDR}}, nil, now)
			require.ErrorIs(t, err, syscall.EIO)
			if tt.ambiguous {
				require.ErrorIs(t, err, filter.ErrProtectedRuleRollback)
			}
			_, oldOK := ttlEntryFor(t, reg, oldCIDR, listAllow)
			_, newOK := ttlEntryFor(t, reg, newCIDR, listAllow)
			assert.True(t, oldOK)
			assert.False(t, newOK)
			assert.Equal(t, []string{tt.physical}, allowedRules(base))
			assertProtectedCurrent(t, reg, 1, 0, 0, 0)
		})
	}

	base := &fakeFilter{allowed: []string{oldCIDR.String()}}
	ff := &ttlEffectFilter{fakeFilter: base, afterReplace: errors.Join(filter.ErrProtectedRuleCapacity, syscall.ENOSPC), replaceAmbiguous: true}
	reg := newTTLRegistry()
	require.NoError(t, reg.seedAdopted([]*net.IPNet{oldCIDR}, nil))
	require.Error(t, reg.reconcileAuthoritative(ff, filter.ModeAllowlist, []parsedCIDR{{cidr: newCIDR}}, nil, now))
	assert.Equal(t, uint64(1), reg.mapFullCount())
}

func TestTTLSeedRequiresEmptyRegistry(t *testing.T) {
	reg := newTTLRegistry()
	first, second := mustCIDR(t, "192.0.2.94/32"), mustCIDR(t, "192.0.2.95/32")
	require.NoError(t, reg.seedAdopted([]*net.IPNet{first}, nil))
	before := reg.snapshotRules()
	require.Error(t, reg.seedAdopted([]*net.IPNet{second}, nil))
	assert.Equal(t, before, reg.snapshotRules())
}
