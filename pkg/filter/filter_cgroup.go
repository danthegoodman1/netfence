//go:build linux

// Package filter provides eBPF-based network filtering for containers and interfaces.
package filter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// CgroupFilter manages the cgroup-based BPF filter
type CgroupFilter struct {
	mu          sync.Mutex
	objs        *cgroupObjects
	cgroupPath  string
	cgroupLink4 link.Link
	cgroupLink6 link.Link
}

// NewCgroupFilter creates a new cgroup-based filter attached to the specified cgroup path
func NewCgroupFilter(cgroupPath string, mode PolicyMode) (*CgroupFilter, error) {
	// Verify cgroup path exists
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cgroup path does not exist: %s", cgroupPath)
	}

	// Load the eBPF objects
	objs := &cgroupObjects{}
	if err := loadCgroupObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading cgroup BPF objects: %w", err)
	}

	// Set the policy mode
	if err := objs.PolicyMode.Put(uint32(0), uint8(mode)); err != nil {
		objs.Close()
		return nil, fmt.Errorf("setting policy mode: %w", err)
	}

	// Attach IPv4 filter to the cgroup
	link4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictConnect4,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching IPv4 filter to cgroup: %w", err)
	}

	// Attach IPv6 filter to the cgroup
	link6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictConnect6,
		Attach:  ebpf.AttachCGroupInet6Connect,
	})
	if err != nil {
		link4.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching IPv6 filter to cgroup: %w", err)
	}

	return &CgroupFilter{
		objs:        objs,
		cgroupPath:  cgroupPath,
		cgroupLink4: link4,
		cgroupLink6: link6,
	}, nil
}

// Close releases the BPF resources
func (f *CgroupFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var errs []error

	if f.cgroupLink4 != nil {
		if err := f.cgroupLink4.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing IPv4 cgroup link: %w", err))
		}
	}

	if f.cgroupLink6 != nil {
		if err := f.cgroupLink6.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing IPv6 cgroup link: %w", err))
		}
	}

	if f.objs != nil {
		if err := f.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}
	return nil
}

// SetMode sets the policy mode
func (f *CgroupFilter) SetMode(mode PolicyMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objs.PolicyMode.Put(uint32(0), uint8(mode))
}

// GetMode gets the current policy mode
func (f *CgroupFilter) GetMode() (PolicyMode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var mode uint8
	if err := f.objs.PolicyMode.Lookup(uint32(0), &mode); err != nil {
		return ModeDisabled, err
	}
	return PolicyMode(mode), nil
}

// AllowIP adds an IP address or CIDR to the allowlist
func (f *CgroupFilter) AllowIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if cidr.IP.To4() != nil {
		key := ipv4CIDRToKey(cidr)
		return f.objs.AllowedIpv4.Put(key, uint8(1))
	}
	key := ipv6CIDRToKey(cidr)
	return f.objs.AllowedIpv6.Put(key, uint8(1))
}

// DenyIP adds an IP address or CIDR to the denylist
func (f *CgroupFilter) DenyIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if cidr.IP.To4() != nil {
		key := ipv4CIDRToKey(cidr)
		return f.objs.DeniedIpv4.Put(key, uint8(1))
	}
	key := ipv6CIDRToKey(cidr)
	return f.objs.DeniedIpv6.Put(key, uint8(1))
}

// RemoveAllowedIP removes an IP address or CIDR from the allowlist
func (f *CgroupFilter) RemoveAllowedIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if cidr.IP.To4() != nil {
		key := ipv4CIDRToKey(cidr)
		if err := f.objs.AllowedIpv4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}
	key := ipv6CIDRToKey(cidr)
	if err := f.objs.AllowedIpv6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// RemoveDeniedIP removes an IP address or CIDR from the denylist
func (f *CgroupFilter) RemoveDeniedIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if cidr.IP.To4() != nil {
		key := ipv4CIDRToKey(cidr)
		if err := f.objs.DeniedIpv4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}
	key := ipv6CIDRToKey(cidr)
	if err := f.objs.DeniedIpv6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// ClearRules removes all configured allowlist and denylist entries.
func (f *CgroupFilter) ClearRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := clearMap[IPv4LPMKey](f.objs.AllowedIpv4); err != nil {
		return fmt.Errorf("clearing allowed IPv4 rules: %w", err)
	}
	if err := clearMap[IPv6LPMKey](f.objs.AllowedIpv6); err != nil {
		return fmt.Errorf("clearing allowed IPv6 rules: %w", err)
	}
	if err := clearMap[IPv4LPMKey](f.objs.DeniedIpv4); err != nil {
		return fmt.Errorf("clearing denied IPv4 rules: %w", err)
	}
	if err := clearMap[IPv6LPMKey](f.objs.DeniedIpv6); err != nil {
		return fmt.Errorf("clearing denied IPv6 rules: %w", err)
	}
	return nil
}

// GetStats returns the current filter statistics
func (f *CgroupFilter) GetStats() (Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var stats Stats
	allowed, err := sumPerCPUCounter(f.objs.Stats, 0)
	if err != nil {
		return stats, fmt.Errorf("reading allowed count: %w", err)
	}
	blocked, err := sumPerCPUCounter(f.objs.Stats, 1)
	if err != nil {
		return stats, fmt.Errorf("reading blocked count: %w", err)
	}
	stats.Allowed = allowed
	stats.Blocked = blocked
	return stats, nil
}

// CgroupPath returns the cgroup path this filter is attached to
func (f *CgroupFilter) CgroupPath() string {
	return f.cgroupPath
}
