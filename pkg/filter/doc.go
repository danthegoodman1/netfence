// Package filter provides eBPF-based network filtering for containers and interfaces.
//
// This package supports two types of filters:
//
// # CgroupFilter
//
// Attaches to a cgroup and filters outbound connections at the socket level.
// Best for container/cgroup-based isolation where you want to control which
// IPs a container can connect to.
//
// # TCFilter
//
// Attaches to a network interface and filters packets at the TC (Traffic Control)
// layer. Best for per-interface filtering such as VM tap devices.
//
// # Policy Modes
//
// Both filters support four policy modes:
//   - ModeDisabled (0): Allow all traffic
//   - ModeAllowlist (1): Only allow IPs in the allowlist
//   - ModeBlockAll (2): Block all outbound traffic
//   - ModeDenylist (3): Block IPs in the denylist, allow all others
//
// # CIDR Support
//
// Both filters support CIDR notation for IP ranges (e.g., 10.0.0.0/8, 192.168.1.0/24).
// Use ParseCIDR to convert strings to *net.IPNet for use with Allow/Deny methods.
//
// # Carve-outs
//
// Destinations like localhost are carved out of policy enforcement via
// Carveouts (see DefaultCarveouts). By default IPv4 link-local
// (169.254.0.0/16, which includes the cloud metadata service) is NOT carved
// out and is subject to policy.
//
// # Example
//
//	// Create a cgroup filter in allowlist mode with default carve-outs
//	f, err := filter.NewCgroupFilter("/sys/fs/cgroup/my-container", filter.ModeAllowlist, filter.DefaultCarveouts())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer f.Close()
//
//	// Allow a specific IP
//	cidr, _ := filter.ParseCIDR("93.184.216.34")
//	f.AllowIP(cidr)
//
//	// Allow a CIDR range
//	cidr, _ = filter.ParseCIDR("10.0.0.0/8")
//	f.AllowIP(cidr)
package filter

import "net"

// Filter is the common interface implemented by both CgroupFilter and TCFilter.
// It provides methods for managing IP allowlists/denylists and controlling the filter mode.
//
// Teardown has two distinct paths:
//
//   - Close releases the userspace file descriptors only. For a filter
//     created with Options.PinDir set, the bpffs pins keep the links attached
//     and the rule maps populated, so the kernel KEEPS ENFORCING after Close
//     (and after the process exits). This is the daemon-stop / keep-enforcing
//     path; a later LoadPinned*Filter re-adopts the state.
//   - Detach removes the bpffs pin directory and closes everything, dropping
//     the last kernel references: enforcement stops and no state survives.
//     For an unpinned filter Detach is equivalent to Close.
//
// New*FilterWithOptions may return a non-nil Filter together with an error
// only when construction cleanup is ambiguous. Callers must treat that value
// as owned live state and retain target ownership while retrying or otherwise
// resolving cleanup rather than discarding it.
type Filter interface {
	SetMode(PolicyMode) error
	GetMode() (PolicyMode, error)
	AllowIP(cidr *net.IPNet) error
	DenyIP(cidr *net.IPNet) error
	RemoveAllowedIP(cidr *net.IPNet) error
	RemoveDeniedIP(cidr *net.IPNet) error
	// AddDNSAllowedIPs atomically-at-the-API-boundary adds canonical host
	// addresses to the separately bounded DNS exact tier. Inputs are fully
	// validated and per-family capacity is preflighted before mutation. On a
	// kernel mutation failure the implementation restores the exact pre-call
	// state or returns an error wrapping ErrDNSAllowRollback.
	AddDNSAllowedIPs(ips []net.IP) error
	// RemoveDNSAllowedIPs is the inverse transactional batch operation.
	RemoveDNSAllowedIPs(ips []net.IP) error
	// ReplaceDNSAllowedIPs atomically removes and adds exact DNS keys as one
	// transaction. Capacity is checked against the final state, so a caller may
	// replace an entry in a full map without a fail-open remove/add gap. On any
	// mutation failure the complete pre-call snapshot is restored or the error
	// wraps ErrDNSAllowRollback.
	ReplaceDNSAllowedIPs(remove, add []net.IP) error
	// DNSAllowedIPs lists canonical, sorted exact-tier host addresses.
	DNSAllowedIPs() ([]net.IP, error)
	// DNSAllowOccupancy reports exact-tier per-family occupancy and capacity.
	DNSAllowOccupancy() (DNSAllowOccupancy, error)
	ClearRules() error
	GetStats() (Stats, error)
	Close() error
	Detach() error
}
