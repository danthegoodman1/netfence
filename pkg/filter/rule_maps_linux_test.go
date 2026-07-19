//go:build linux

package filter

import (
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLPMKeysUseNetworkOrderByteArrayABI(t *testing.T) {
	assert.Equal(t, uintptr(8), unsafe.Sizeof(IPv4LPMKey{}))
	assert.Equal(t, uintptr(20), unsafe.Sizeof(IPv6LPMKey{}))

	v4, err := ParseCIDR("192.0.2.129/25")
	require.NoError(t, err)
	v4Key := ipv4CIDRToKey(v4)
	assert.Equal(t, uint32(25), v4Key.Prefixlen)
	assert.Equal(t, [4]byte{192, 0, 2, 128}, v4Key.Addr)
	assert.Equal(t, "192.0.2.128/25", keyToIPv4CIDR(v4Key).String())

	v6, err := ParseCIDR("2001:db8:1234::1/48")
	require.NoError(t, err)
	v6Key := ipv6CIDRToKey(v6)
	assert.Equal(t, uint32(48), v6Key.Prefixlen)
	assert.Equal(t, net.ParseIP("2001:db8:1234::").To16(), net.IP(v6Key.Addr[:]))
	assert.Equal(t, "2001:db8:1234::/48", keyToIPv6CIDR(v6Key).String())
}

func TestConcreteFiltersShareSixMapClearRules(t *testing.T) {
	constructors := map[string]func(ruleMapHandles) interface{ ClearRules() error }{
		"cgroup": func(m ruleMapHandles) interface{ ClearRules() error } {
			f := &CgroupFilter{}
			f.setRuleMaps(m)
			return f
		},
		"tc": func(m ruleMapHandles) interface{ ClearRules() error } {
			f := &TCFilter{}
			f.setRuleMaps(m)
			return f
		},
	}
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			maps, keys := newSeededClearRulesMaps(t)
			require.NoError(t, construct(maps).ClearRules())
			assertClearRulesKeysMissing(t, maps, keys)
		})
	}
}

func TestConcreteFiltersClearRulesRejectClosedHandles(t *testing.T) {
	for name, f := range map[string]interface{ ClearRules() error }{
		"cgroup": &CgroupFilter{},
		"tc":     &TCFilter{},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, f.ClearRules(), "filter handles are closed")
		})
	}
}

func TestClearRulesPreflightsAllHandlesBeforeMutation(t *testing.T) {
	maps, keys := newSeededClearRulesMaps(t)
	maps.exact6 = nil
	f := &CgroupFilter{}
	f.setRuleMaps(maps)
	require.ErrorContains(t, f.ClearRules(), "filter handles are closed")
	var value uint8
	require.NoError(t, maps.allowed4.Lookup(keys.allowed4, &value), "an incomplete handle set must not partially clear earlier maps")
}

type clearRulesKeys struct {
	allowed4 IPv4LPMKey
	allowed6 IPv6LPMKey
	denied4  IPv4LPMKey
	denied6  IPv6LPMKey
	exact4   [4]byte
	exact6   [16]byte
}

func newSeededClearRulesMaps(t *testing.T) (ruleMapHandles, clearRulesKeys) {
	t.Helper()
	newMap := func(spec *ebpf.MapSpec) *ebpf.Map {
		t.Helper()
		m, err := ebpf.NewMap(spec)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, m.Close()) })
		return m
	}
	lpm := func(name string, keySize uint32) *ebpf.Map {
		return newMap(&ebpf.MapSpec{Name: name, Type: ebpf.LPMTrie, KeySize: keySize, ValueSize: 1, MaxEntries: 8, Flags: unix.BPF_F_NO_PREALLOC})
	}
	exact := func(name string, keySize uint32) *ebpf.Map {
		return newMap(&ebpf.MapSpec{Name: name, Type: ebpf.Hash, KeySize: keySize, ValueSize: 1, MaxEntries: 8})
	}
	maps := ruleMapHandles{
		allowed4: lpm("clr_allow4", 8),
		allowed6: lpm("clr_allow6", 20),
		denied4:  lpm("clr_deny4", 8),
		denied6:  lpm("clr_deny6", 20),
		exact4:   exact("clr_exact4", 4),
		exact6:   exact("clr_exact6", 16),
	}
	keys := clearRulesKeys{
		allowed4: IPv4LPMKey{Prefixlen: 24, Addr: [4]byte{192, 0, 2, 0}},
		allowed6: IPv6LPMKey{Prefixlen: 64, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8}},
		denied4:  IPv4LPMKey{Prefixlen: 24, Addr: [4]byte{198, 51, 100, 0}},
		denied6:  IPv6LPMKey{Prefixlen: 64, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb9}},
		exact4:   [4]byte{203, 0, 113, 7},
		exact6:   [16]byte{0x20, 0x01, 0x0d, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7},
	}
	value := uint8(1)
	require.NoError(t, maps.allowed4.Put(keys.allowed4, value))
	require.NoError(t, maps.allowed6.Put(keys.allowed6, value))
	require.NoError(t, maps.denied4.Put(keys.denied4, value))
	require.NoError(t, maps.denied6.Put(keys.denied6, value))
	require.NoError(t, maps.exact4.Put(keys.exact4, value))
	require.NoError(t, maps.exact6.Put(keys.exact6, value))
	return maps, keys
}

func assertClearRulesKeysMissing(t *testing.T, maps ruleMapHandles, keys clearRulesKeys) {
	t.Helper()
	var value uint8
	require.ErrorIs(t, maps.allowed4.Lookup(keys.allowed4, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.allowed6.Lookup(keys.allowed6, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.denied4.Lookup(keys.denied4, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.denied6.Lookup(keys.denied6, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.exact4.Lookup(keys.exact4, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.exact6.Lookup(keys.exact6, &value), ebpf.ErrKeyNotExist)
}
