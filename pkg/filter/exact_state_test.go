package filter

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

type countingExactBackend struct {
	*fakeExactBackend
	inventories, lookups int
	lookupErr            error
}

func (b *countingExactBackend) keys(f exactIPFamily) ([]exactIPKey, error) {
	b.inventories++
	return b.fakeExactBackend.keys(f)
}

func (b *countingExactBackend) contains(key exactIPKey) (bool, error) {
	b.lookups++
	if b.lookupErr != nil {
		return false, b.lookupErr
	}
	return b.fakeExactBackend.contains(key)
}

func TestExactStateNormalMutationsNeverInventoryWorkingSet(t *testing.T) {
	for _, count := range []int{0, 4095} {
		b := &countingExactBackend{fakeExactBackend: newFakeExactBackend(4096)}
		for i := 0; i < count; i++ {
			key, err := canonicalExactIPKeys([]net.IP{net.IPv4(10, 0, byte(i>>8), byte(i))})
			require.NoError(t, err)
			b.entries[key[0]] = struct{}{}
		}
		state := &exactDNSState{}
		usage, err := state.usage(b)
		require.NoError(t, err)
		require.Equal(t, uint32(count), usage.IPv4Entries)
		require.Equal(t, 2, b.inventories)
		ips := []net.IP{net.ParseIP("192.0.2.1")}
		for i := 0; i < 10; i++ {
			require.NoError(t, state.replace(b, nil, ips))
			require.NoError(t, state.replace(b, ips, nil))
		}
		require.Equal(t, 2, b.inventories, "only adoption may scan")
		require.Equal(t, 20, b.lookups, "one lookup per touched key")
		require.Equal(t, uint32(count), state.occupancy.IPv4Entries)
	}
}

func TestExactStateRollbackInvalidatesOnlyUnprovenCounts(t *testing.T) {
	b := &countingExactBackend{fakeExactBackend: newFakeExactBackend(1)}
	s := &exactDNSState{}
	ips := []net.IP{net.ParseIP("192.0.2.1")}
	key, err := canonicalExactIPKeys(ips)
	require.NoError(t, err)
	b.failPutAt, b.mutateOnPut = 1, true
	b.failDelete[key[0]] = syscall.EBUSY
	require.ErrorIs(t, s.replace(b, nil, ips), ErrDNSAllowRollback)
	require.False(t, s.initialized)
	delete(b.failDelete, key[0])
	usage, err := s.usage(b)
	require.NoError(t, err)
	require.Equal(t, uint32(1), usage.IPv4Entries, "reinventory observes ambiguous residual")
	require.ErrorIs(t, s.replace(b, nil, []net.IP{net.ParseIP("192.0.2.2")}), ErrDNSAllowCapacity)
	b.failDeleteAt, b.mutateOnDelete = b.deleteCount+1, true
	require.ErrorIs(t, s.replace(b, ips, nil), syscall.EIO)
	require.True(t, s.initialized, "verified rollback retains valid counts")
	require.Equal(t, uint32(1), s.occupancy.IPv4Entries)
}

func TestExactStateLookupFailureDoesNotMutate(t *testing.T) {
	b := &countingExactBackend{fakeExactBackend: newFakeExactBackend(8), lookupErr: syscall.EIO}
	s := &exactDNSState{}
	require.ErrorIs(t, s.replace(b, nil, []net.IP{net.ParseIP("192.0.2.1")}), syscall.EIO)
	require.Empty(t, b.ops)
	require.Empty(t, b.entries)
}
