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
// # Example
//
//	// Create a cgroup filter in allowlist mode
//	f, err := filter.NewCgroupFilter("/sys/fs/cgroup/my-container", filter.ModeAllowlist)
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
