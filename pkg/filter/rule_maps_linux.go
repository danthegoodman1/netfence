//go:build linux

package filter

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
)

// ruleMapCore is the hook-independent userspace view of the maps shared by
// the cgroup and TC programs. Concrete filters own attachment and pin
// lifecycles; this core owns every rule, mode, inventory, and stats operation.
type ruleMapCore struct {
	mu   sync.Mutex
	maps ruleMapHandles
}

type ruleMapHandles struct {
	allowed4 *ebpf.Map
	allowed6 *ebpf.Map
	denied4  *ebpf.Map
	denied6  *ebpf.Map
	exact4   *ebpf.Map
	exact6   *ebpf.Map
	mode     *ebpf.Map
	stats    *ebpf.Map
}

func (c *ruleMapCore) setRuleMaps(m ruleMapHandles) { c.maps = m }

func (c *ruleMapCore) protectedBackendLocked() (protectedRuleBackend, error) {
	m := c.maps
	if m.allowed4 == nil || m.allowed6 == nil || m.denied4 == nil || m.denied6 == nil || m.mode == nil {
		return nil, fmt.Errorf("filter handles are closed")
	}
	return bpfProtectedRuleBackend{
		allowedIPv4: m.allowed4,
		allowedIPv6: m.allowed6,
		deniedIPv4:  m.denied4,
		deniedIPv6:  m.denied6,
		policyMode:  m.mode,
	}, nil
}

func (c *ruleMapCore) exactBackendLocked() (exactDNSBackend, error) {
	if c.maps.exact4 == nil || c.maps.exact6 == nil {
		return nil, fmt.Errorf("filter handles are closed")
	}
	return bpfExactDNSBackend{ipv4: c.maps.exact4, ipv6: c.maps.exact6}, nil
}

func (c *ruleMapCore) SetMode(mode PolicyMode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maps.mode == nil {
		return fmt.Errorf("filter handles are closed")
	}
	return c.maps.mode.Put(uint32(0), uint8(mode))
}

func (c *ruleMapCore) GetMode() (PolicyMode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maps.mode == nil {
		return ModeDisabled, fmt.Errorf("filter handles are closed")
	}
	var mode uint8
	if err := c.maps.mode.Lookup(uint32(0), &mode); err != nil {
		return ModeDisabled, err
	}
	return PolicyMode(mode), nil
}

func (c *ruleMapCore) putCIDR(cidr *net.IPNet, v4, v6 *ebpf.Map) error {
	if v4 == nil || v6 == nil {
		return fmt.Errorf("filter handles are closed")
	}
	if cidr.IP.To4() != nil {
		return v4.Put(ipv4CIDRToKey(cidr), uint8(1))
	}
	return v6.Put(ipv6CIDRToKey(cidr), uint8(1))
}

func (c *ruleMapCore) deleteCIDR(cidr *net.IPNet, v4, v6 *ebpf.Map) error {
	if v4 == nil || v6 == nil {
		return fmt.Errorf("filter handles are closed")
	}
	var err error
	if cidr.IP.To4() != nil {
		err = v4.Delete(ipv4CIDRToKey(cidr))
	} else {
		err = v6.Delete(ipv6CIDRToKey(cidr))
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (c *ruleMapCore) AllowIP(cidr *net.IPNet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.putCIDR(cidr, c.maps.allowed4, c.maps.allowed6)
}

func (c *ruleMapCore) DenyIP(cidr *net.IPNet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.putCIDR(cidr, c.maps.denied4, c.maps.denied6)
}

func (c *ruleMapCore) RemoveAllowedIP(cidr *net.IPNet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deleteCIDR(cidr, c.maps.allowed4, c.maps.allowed6)
}

func (c *ruleMapCore) RemoveDeniedIP(cidr *net.IPNet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deleteCIDR(cidr, c.maps.denied4, c.maps.denied6)
}

func (c *ruleMapCore) ReplaceProtectedRules(allowed, denied []*net.IPNet, mode PolicyMode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.protectedBackendLocked()
	if err != nil {
		return err
	}
	return replaceProtectedRules(b, allowed, denied, mode)
}

func (c *ruleMapCore) ProtectedRuleOccupancy() (ProtectedRuleOccupancy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.protectedBackendLocked()
	if err != nil {
		return ProtectedRuleOccupancy{}, err
	}
	return protectedRuleOccupancy(b)
}

func (c *ruleMapCore) AddDNSAllowedIPs(ips []net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.exactBackendLocked()
	if err != nil {
		return err
	}
	return addExactDNSIPs(b, ips)
}

func (c *ruleMapCore) RemoveDNSAllowedIPs(ips []net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.exactBackendLocked()
	if err != nil {
		return err
	}
	return removeExactDNSIPs(b, ips)
}

func (c *ruleMapCore) ReplaceDNSAllowedIPs(remove, add []net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.exactBackendLocked()
	if err != nil {
		return err
	}
	return replaceExactDNSIPs(b, remove, add)
}

func (c *ruleMapCore) DNSAllowedIPs() ([]net.IP, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.exactBackendLocked()
	if err != nil {
		return nil, err
	}
	return listExactDNSIPs(b)
}

func (c *ruleMapCore) DNSAllowOccupancy() (DNSAllowOccupancy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := c.exactBackendLocked()
	if err != nil {
		return DNSAllowOccupancy{}, err
	}
	return exactDNSOccupancy(b)
}

// ClearRules removes every protected LPM and DNS exact-tier rule while
// leaving mode and statistics untouched.
func (c *ruleMapCore) ClearRules() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.maps
	if m.allowed4 == nil || m.allowed6 == nil || m.denied4 == nil || m.denied6 == nil || m.exact4 == nil || m.exact6 == nil {
		return fmt.Errorf("filter handles are closed")
	}
	if err := clearMap[IPv4LPMKey](m.allowed4); err != nil {
		return fmt.Errorf("clearing allowed IPv4 rules: %w", err)
	}
	if err := clearMap[IPv6LPMKey](m.allowed6); err != nil {
		return fmt.Errorf("clearing allowed IPv6 rules: %w", err)
	}
	if err := clearMap[IPv4LPMKey](m.denied4); err != nil {
		return fmt.Errorf("clearing denied IPv4 rules: %w", err)
	}
	if err := clearMap[IPv6LPMKey](m.denied6); err != nil {
		return fmt.Errorf("clearing denied IPv6 rules: %w", err)
	}
	if err := clearMap[[4]byte](m.exact4); err != nil {
		return fmt.Errorf("clearing DNS exact IPv4 rules: %w", err)
	}
	if err := clearMap[[16]byte](m.exact6); err != nil {
		return fmt.Errorf("clearing DNS exact IPv6 rules: %w", err)
	}
	return nil
}

func clearMap[K any](m *ebpf.Map) error {
	var keys []K
	var value uint8
	var key K
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (c *ruleMapCore) GetStats() (Stats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maps.stats == nil {
		return Stats{}, fmt.Errorf("filter handles are closed")
	}
	allowed, err := sumPerCPUCounter(c.maps.stats, 0)
	if err != nil {
		return Stats{}, fmt.Errorf("reading allowed count: %w", err)
	}
	blocked, err := sumPerCPUCounter(c.maps.stats, 1)
	if err != nil {
		return Stats{}, fmt.Errorf("reading blocked count: %w", err)
	}
	return Stats{Allowed: allowed, Blocked: blocked}, nil
}

// Rules lists the protected CIDR maps for pinned-state adoption.
func (c *ruleMapCore) Rules() (allowed, denied []*net.IPNet, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maps.allowed4 == nil || c.maps.allowed6 == nil || c.maps.denied4 == nil || c.maps.denied6 == nil {
		return nil, nil, fmt.Errorf("filter handles are closed")
	}
	allowed, err = dumpRuleMaps(c.maps.allowed4, c.maps.allowed6)
	if err != nil {
		return nil, nil, fmt.Errorf("dumping allowed rules: %w", err)
	}
	denied, err = dumpRuleMaps(c.maps.denied4, c.maps.denied6)
	if err != nil {
		return nil, nil, fmt.Errorf("dumping denied rules: %w", err)
	}
	return allowed, denied, nil
}
