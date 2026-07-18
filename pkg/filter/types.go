package filter

import (
	"fmt"
	"net"
)

// PolicyMode defines the filtering behavior
type PolicyMode uint8

const (
	// ModeDisabled allows all traffic
	ModeDisabled PolicyMode = 0
	// ModeAllowlist only allows traffic to IPs in the allowlist
	ModeAllowlist PolicyMode = 1
	// ModeBlockAll blocks all outbound traffic
	ModeBlockAll PolicyMode = 2
	// ModeDenylist blocks traffic to IPs in the denylist, allows all others
	ModeDenylist PolicyMode = 3
)

func (m PolicyMode) String() string {
	switch m {
	case ModeDisabled:
		return "disabled"
	case ModeAllowlist:
		return "allowlist"
	case ModeBlockAll:
		return "block_all"
	case ModeDenylist:
		return "denylist"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// Carve-out flag bits. Must match the CARVEOUT_* macros in
// bpf/filter_cgroup.c and bpf/filter_tc.c.
const (
	carveoutLocalhostV4 uint32 = 1 << 0
	carveoutLocalhostV6 uint32 = 1 << 1
	carveoutLinkLocalV4 uint32 = 1 << 2
	carveoutLinkLocalV6 uint32 = 1 << 3
	carveoutMulticastV6 uint32 = 1 << 4
)

// Carveouts configures destination ranges that are always allowed regardless
// of allowlist/denylist policy (block-all mode still blocks everything).
// The flags are baked into the BPF program as a load-time constant, so they
// are per-attachment and have zero per-packet cost.
type Carveouts struct {
	// LocalhostV4 always allows 127.0.0.0/8.
	LocalhostV4 bool
	// LocalhostV6 always allows ::1.
	LocalhostV6 bool
	// LinkLocalV4 always allows 169.254.0.0/16. OFF by default: this range
	// includes 169.254.169.254, the cloud metadata service — a
	// credential-theft target that sandboxing policies must be able to
	// block. Workloads that need it can simply allowlist it.
	LinkLocalV4 bool
	// LinkLocalV6 always allows fe80::/10 (required for NDP; without it
	// IPv6 allowlist connectivity breaks).
	LinkLocalV6 bool
	// MulticastV6 always allows ff02::/16 (link-local scope multicast,
	// used by NDP neighbor/router solicitation).
	MulticastV6 bool
}

// DefaultCarveouts returns the default carve-out posture: localhost and the
// IPv6 neighbor-discovery ranges allowed, IPv4 link-local (metadata service)
// subject to policy.
func DefaultCarveouts() Carveouts {
	return Carveouts{
		LocalhostV4: true,
		LocalhostV6: true,
		LinkLocalV4: false,
		LinkLocalV6: true,
		MulticastV6: true,
	}
}

// flags encodes the carve-outs as the BPF-side bitmask.
func (c Carveouts) flags() uint32 {
	var f uint32
	if c.LocalhostV4 {
		f |= carveoutLocalhostV4
	}
	if c.LocalhostV6 {
		f |= carveoutLocalhostV6
	}
	if c.LinkLocalV4 {
		f |= carveoutLinkLocalV4
	}
	if c.LinkLocalV6 {
		f |= carveoutLinkLocalV6
	}
	if c.MulticastV6 {
		f |= carveoutMulticastV6
	}
	return f
}

// Options holds optional load-time filter tuning. The zero value keeps the
// compiled-in defaults.
type Options struct {
	// MaxRuleEntries sets max_entries for each of the four LPM rule maps
	// (allowed/denied, IPv4/IPv6) at program load time. 0 keeps the
	// compiled-in default (4096). This is pure map sizing: the BPF program
	// bytes and per-packet lookup cost are unchanged (LPM trie lookups are
	// bounded by key length, not capacity).
	MaxRuleEntries uint32
}

// Stats holds the filter statistics
type Stats struct {
	Allowed uint64
	Blocked uint64
}

// ParseCIDR is a helper that parses a CIDR string (or single IP)
func ParseCIDR(s string) (*net.IPNet, error) {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %s", s)
		}
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	return cidr, nil
}
