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
