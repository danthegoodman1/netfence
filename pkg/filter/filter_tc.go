//go:build linux

package filter

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TCFilter manages the TC-based BPF filter
type TCFilter struct {
	mu        sync.Mutex
	objs      *tcObjects
	ifaceName string
	tcLink    link.Link
}

// NewTCFilter creates a new TC-based filter attached to the specified interface
func NewTCFilter(ifaceName string, mode PolicyMode) (*TCFilter, error) {
	// Load the eBPF objects
	objs := &tcObjects{}
	if err := loadTcObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading TC BPF objects: %w", err)
	}

	// Set the policy mode
	if err := objs.PolicyMode.Put(uint32(0), uint8(mode)); err != nil {
		objs.Close()
		return nil, fmt.Errorf("setting policy mode: %w", err)
	}

	// Attach to interface using TCX (modern TC attachment)
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.FilterEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching TC filter to interface %s: %w", ifaceName, err)
	}

	return &TCFilter{
		objs:      objs,
		ifaceName: ifaceName,
		tcLink:    tcLink,
	}, nil
}

// Close releases the BPF resources
func (f *TCFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var errs []error

	if f.tcLink != nil {
		if err := f.tcLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TC link: %w", err))
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
func (f *TCFilter) SetMode(mode PolicyMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objs.PolicyMode.Put(uint32(0), uint8(mode))
}

// GetMode gets the current policy mode
func (f *TCFilter) GetMode() (PolicyMode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var mode uint8
	if err := f.objs.PolicyMode.Lookup(uint32(0), &mode); err != nil {
		return ModeDisabled, err
	}
	return PolicyMode(mode), nil
}

// AllowIP adds an IP address or CIDR to the allowlist
func (f *TCFilter) AllowIP(cidr *net.IPNet) error {
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
func (f *TCFilter) DenyIP(cidr *net.IPNet) error {
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
func (f *TCFilter) RemoveAllowedIP(cidr *net.IPNet) error {
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
func (f *TCFilter) RemoveDeniedIP(cidr *net.IPNet) error {
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
func (f *TCFilter) ClearRules() error {
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
func (f *TCFilter) GetStats() (Stats, error) {
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

// InterfaceName returns the interface name this filter is attached to
func (f *TCFilter) InterfaceName() string {
	return f.ifaceName
}
