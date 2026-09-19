package filter

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCIDRIdentityPreservesFamilyAndMasksHostBits(t *testing.T) {
	for _, input := range []string{"192.0.2.1/32", "::ffff:192.0.2.1/128", "2001:db8::/32"} {
		cidr, err := ParseCIDR(input)
		require.NoError(t, err)
		require.Equal(t, input, CIDRString(cidr))
	}
	require.Equal(t, "192.0.2.0/24", CIDRString(&net.IPNet{IP: net.ParseIP("192.0.2.129"), Mask: net.CIDRMask(24, 32)}))
	for _, cidr := range []*net.IPNet{nil, {}, {IP: net.IPv4(1, 2, 3, 4), Mask: net.IPMask{255, 0, 255, 0}}, {IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(24, 32)}} {
		_, err := CIDRPrefix(cidr)
		require.Error(t, err)
	}
}
