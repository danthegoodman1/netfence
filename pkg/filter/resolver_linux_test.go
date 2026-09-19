//go:build linux

package filter

import (
	"encoding/binary"
	"net/netip"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolverEndpointPinnedRestoreAndSchemaOnePreservation(t *testing.T) {
	root := pinTestRoot(t)
	const iface = "nf-res-pin"
	out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput()
	require.NoError(t, err, "%s", out)
	t.Cleanup(func() { exec.Command("ip", "link", "del", iface).Run() })
	pinDir := filepath.Join(root, "attachment")
	f, err := NewTCFilterWithOptions(iface, ModeAllowlist, DirectionEgress, DefaultCarveouts(), Options{PinDir: pinDir})
	require.NoError(t, err)
	endpoint := ResolverEndpoint{Address: netip.MustParseAddr("127.0.0.1"), PortMin: 11000, PortMax: 11500, Port: 11001}
	require.NoError(t, f.SetResolverEndpoint(endpoint))
	require.NoError(t, f.Close())
	state, err := InspectPinnedSchema(pinDir)
	require.NoError(t, err)
	require.Equal(t, PinnedSchemaCurrent, state)
	restored, err := LoadPinnedTCFilter(iface, DirectionEgress, pinDir)
	require.NoError(t, err)
	t.Cleanup(func() { restored.Close() })
	require.NoError(t, restored.SetResolverEndpoint(endpoint))
	endpoint.Port++
	require.ErrorIs(t, restored.SetResolverEndpoint(endpoint), ErrPinnedSchemaIncompatible)
	var config resolverEndpointConfig
	require.NoError(t, restored.objs.ResolverEndpoint.Lookup(uint32(0), &config))
	require.Equal(t, uint16(11001), config.Port, "failed reconfiguration must leave enforcement unchanged")
	// Version 1 must be rejected before examining or changing any live objects.
	require.NoError(t, writePinSchemaVersion(restored.objs.PinSchemaVersion, 1))
	beforeNames := pinDirectoryNames(t, pinDir)
	beforeProgram := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkTCX))
	_, err = LoadPinnedTCFilterWithOptions(iface, DirectionEgress, pinDir, DefaultCarveouts(), Options{})
	require.ErrorIs(t, err, ErrPinnedSchemaUpgradeRequired)
	require.Equal(t, beforeNames, pinDirectoryNames(t, pinDir))
	require.Equal(t, beforeProgram, pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkTCX)))
}

func TestTCResolverGuardPrecedesCarveoutsAndHandlesAmbiguousPackets(t *testing.T) {
	objs := &tcObjects{}
	require.NoError(t, loadTcObjects(objs, nil))
	t.Cleanup(func() { objs.Close() })
	f := &TCFilter{objs: objs}
	f.syncRuleMaps()
	for _, v6 := range []bool{false, true} {
		addr := netip.MustParseAddr("127.0.0.1")
		if v6 {
			addr = netip.MustParseAddr("::1")
		}
		// A new attachment's immutable configuration is tested for each family.
		require.NoError(t, objs.ResolverEndpoint.Put(uint32(0), resolverEndpointConfig{}))
		require.NoError(t, f.SetResolverEndpoint(ResolverEndpoint{Address: addr, PortMin: 11000, PortMax: 11500, Port: 11001}))
		for _, mode := range []PolicyMode{ModeDisabled, ModeAllowlist, ModeDenylist} {
			require.NoError(t, f.SetMode(mode))
			for _, proto := range []byte{6, 17} {
				for _, port := range []uint16{11001, 11002, 53} {
					packet := resolverTestPacket(v6, proto, port)
					verdict, _, err := objs.FilterEgress.Test(packet)
					require.NoError(t, err)
					want := uint32(0)
					if port == 11002 {
						want = 2
					}
					require.Equal(t, want, verdict, "v6=%t mode=%s proto=%d port=%d", v6, mode, proto, port)
				}
			}
			packet := resolverTestPacket(v6, 17, 11001)
			if v6 {
				packet[14+6] = 44
			} else {
				packet[14+6] = 0x20
			}
			verdict, _, err := objs.FilterEgress.Test(packet)
			require.NoError(t, err)
			require.Equal(t, uint32(2), verdict, "fragment cannot establish destination port")
			packet = resolverTestPacket(v6, 17, 11001)
			packet = packet[:len(packet)-20]
			verdict, _, err = objs.FilterEgress.Test(packet)
			require.NoError(t, err)
			require.Equal(t, uint32(2), verdict, "missing transport header must fail closed")
		}
	}
}

func resolverTestPacket(v6 bool, proto byte, port uint16) []byte {
	size := 20
	if v6 {
		size = 40
	}
	p := make([]byte, 14+size+20)
	if v6 {
		binary.BigEndian.PutUint16(p[12:14], 0x86dd)
		p[14] = 0x60
		p[20] = proto
		p[21] = 64
		binary.BigEndian.PutUint16(p[18:20], 20)
		p[14+23] = 1
		p[14+39] = 1
	} else {
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14] = 0x45
		p[22] = 64
		p[23] = proto
		binary.BigEndian.PutUint16(p[16:18], 40)
		copy(p[26:30], []byte{127, 0, 0, 1})
		copy(p[30:34], []byte{127, 0, 0, 1})
	}
	binary.BigEndian.PutUint16(p[14+size:16+size], 12345)
	binary.BigEndian.PutUint16(p[16+size:18+size], port)
	return p
}
