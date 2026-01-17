//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" cgroup ../../bpf/filter_cgroup.c -- -I/usr/include/bpf -I/usr/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tc ../../bpf/filter_tc.c -- -I/usr/include/bpf -I/usr/include

package filter

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// IPv4LPMKey is the key structure for IPv4 LPM trie lookups
type IPv4LPMKey struct {
	Prefixlen uint32
	Addr      uint32
}

// IPv6LPMKey is the key structure for IPv6 LPM trie lookups
type IPv6LPMKey struct {
	Prefixlen uint32
	Addr      [4]uint32
}

// Stats holds the filter statistics
type Stats struct {
	Allowed uint64
	Blocked uint64
}

func ipv4CIDRToKey(cidr *net.IPNet) IPv4LPMKey {
	ones, _ := cidr.Mask.Size()
	ip := cidr.IP.To4()
	// Use LittleEndian so the bytes end up in network order when cilium/ebpf
	// marshals the uint32 in native (little) endian on x86/arm64.
	// This ensures the LPM trie prefix matching works correctly.
	return IPv4LPMKey{
		Prefixlen: uint32(ones),
		Addr:      binary.LittleEndian.Uint32(ip),
	}
}

func ipv6CIDRToKey(cidr *net.IPNet) IPv6LPMKey {
	ones, _ := cidr.Mask.Size()
	ip := cidr.IP.To16()
	key := IPv6LPMKey{
		Prefixlen: uint32(ones),
	}
	// Use LittleEndian for the same reason as IPv4
	key.Addr[0] = binary.LittleEndian.Uint32(ip[0:4])
	key.Addr[1] = binary.LittleEndian.Uint32(ip[4:8])
	key.Addr[2] = binary.LittleEndian.Uint32(ip[8:12])
	key.Addr[3] = binary.LittleEndian.Uint32(ip[12:16])
	return key
}

// ParseCIDR is a helper that parses a CIDR string (or single IP)
func ParseCIDR(s string) (*net.IPNet, error) {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		// Try parsing as single IP
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

// GetCgroupPath returns the container's cgroup path based on its ID
// This works for containerd containers using the systemd cgroup driver
func GetCgroupPath(containerID string) (string, error) {
	// Try common cgroup v2 paths
	paths := []string{
		// Containerd with systemd cgroup driver
		filepath.Join("/sys/fs/cgroup/system.slice", fmt.Sprintf("containerd-%s.scope", containerID)),
		// Containerd default
		filepath.Join("/sys/fs/cgroup/default", containerID),
		// Docker-style
		filepath.Join("/sys/fs/cgroup/docker", containerID),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("cgroup path not found for container %s", containerID)
}

// FindCgroupByPID finds the cgroup path for a process ID
func FindCgroupByPID(pid int) (string, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", fmt.Errorf("reading cgroup file: %w", err)
	}

	// Parse cgroup file - each line is "hierarchy-ID:controller-list:cgroup-path"
	// For cgroup v2 unified hierarchy: "0::/path"
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			// cgroup v2 unified hierarchy has hierarchy-ID=0 and empty controller-list
			if parts[0] == "0" && parts[1] == "" {
				cgroupPath := parts[2]
				if cgroupPath != "" && cgroupPath != "/" {
					fullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)
					if _, err := os.Stat(fullPath); err == nil {
						return fullPath, nil
					}
				}
			}
		}
	}

	// Fallback: try the root cgroup for the process
	rootCgroup := "/sys/fs/cgroup"
	if _, err := os.Stat(rootCgroup); err == nil {
		return rootCgroup, nil
	}

	return "", fmt.Errorf("cgroup path not found for PID %d", pid)
}
