package filter

import "net/netip"

// ResolverEndpoint restricts the reserved Netfence port range at Address to
// this filter's assigned Port. Other services at the address retain IP policy.
type ResolverEndpoint struct {
	Address                netip.Addr
	PortMin, PortMax, Port uint16
}
