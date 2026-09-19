package filter

import (
	"fmt"
	"net"
	"net/netip"
)

// CIDRPrefix is the canonical identity used by both incremental and bulk
// operations. Mask width defines the family; mapped IPv6 stays IPv6.
func CIDRPrefix(cidr *net.IPNet) (netip.Prefix, error) {
	if cidr == nil {
		return netip.Prefix{}, fmt.Errorf("CIDR is nil")
	}
	ones, bits := cidr.Mask.Size()
	var ip net.IP
	switch bits {
	case 32:
		ip = cidr.IP.To4()
	case 128:
		ip = cidr.IP.To16()
	default:
		return netip.Prefix{}, fmt.Errorf("CIDR has an invalid mask")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("CIDR address does not match its %d-bit mask", bits)
	}
	return netip.PrefixFrom(addr, ones).Masked(), nil
}

// CIDRString preserves family, unlike net.IPNet.String for mapped IPv6.
// Invalid input has no identity and must be rejected before mutation.
func CIDRString(cidr *net.IPNet) string {
	prefix, err := CIDRPrefix(cidr)
	if err != nil {
		return ""
	}
	return prefix.String()
}
