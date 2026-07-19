//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" cgroup ../../bpf/filter_cgroup.c -- -I/usr/include/bpf -I/usr/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tc ../../bpf/filter_tc.c -- -I/usr/include/bpf -I/usr/include

package filter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

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

// ruleMapNames are the LPM rule maps whose capacity Options.MaxRuleEntries
// overrides. They must match the map names in bpf/filter_tc.c and
// bpf/filter_cgroup.c.
var ruleMapNames = []string{"allowed_ipv4", "denied_ipv4", "allowed_ipv6", "denied_ipv6"}

// dnsRuleMapNames are deliberately separate from ruleMapNames: exact
// DNS-derived host allows are regenerable and independently capacity-managed.
var dnsRuleMapNames = []string{"dns_allowed_ipv4", "dns_allowed_ipv6"}

// applyOptions applies load-time tuning to a BPF collection spec before load.
// It only resizes maps; program instructions are never modified.
func applyOptions(spec *ebpf.CollectionSpec, opts Options) error {
	if opts.MaxRuleEntries != 0 {
		for _, name := range ruleMapNames {
			m, ok := spec.Maps[name]
			if !ok {
				return fmt.Errorf("BPF spec missing rule map %s", name)
			}
			m.MaxEntries = opts.MaxRuleEntries
		}
	}
	if opts.MaxDNSRuleEntries != 0 {
		for _, name := range dnsRuleMapNames {
			m, ok := spec.Maps[name]
			if !ok {
				return fmt.Errorf("BPF spec missing DNS exact rule map %s", name)
			}
			m.MaxEntries = opts.MaxDNSRuleEntries
		}
	}
	return nil
}

type bpfExactDNSBackend struct {
	ipv4 *ebpf.Map
	ipv6 *ebpf.Map
}

type bpfProtectedRuleBackend struct {
	allowedIPv4 *ebpf.Map
	allowedIPv6 *ebpf.Map
	deniedIPv4  *ebpf.Map
	deniedIPv6  *ebpf.Map
	policyMode  *ebpf.Map
}

func (b bpfProtectedRuleBackend) mapFor(bucket protectedRuleBucket) (*ebpf.Map, error) {
	var m *ebpf.Map
	switch bucket {
	case protectedAllowedIPv4:
		m = b.allowedIPv4
	case protectedAllowedIPv6:
		m = b.allowedIPv6
	case protectedDeniedIPv4:
		m = b.deniedIPv4
	case protectedDeniedIPv6:
		m = b.deniedIPv6
	default:
		return nil, fmt.Errorf("unsupported protected rule bucket %d", bucket)
	}
	if m == nil {
		return nil, fmt.Errorf("%s map handle is closed", bucket)
	}
	return m, nil
}

func (b bpfProtectedRuleBackend) keys(bucket protectedRuleBucket) ([]protectedRuleKey, error) {
	m, err := b.mapFor(bucket)
	if err != nil {
		return nil, err
	}
	var value uint8
	var out []protectedRuleKey
	if bucket == protectedAllowedIPv4 || bucket == protectedDeniedIPv4 {
		var raw IPv4LPMKey
		iter := m.Iterate()
		for iter.Next(&raw, &value) {
			key := protectedRuleKey{bucket: bucket, prefixLen: raw.Prefixlen}
			binary.LittleEndian.PutUint32(key.addr[:4], raw.Addr)
			out = append(out, key)
		}
		if err := iter.Err(); err != nil {
			return nil, err
		}
	} else {
		var raw IPv6LPMKey
		iter := m.Iterate()
		for iter.Next(&raw, &value) {
			key := protectedRuleKey{bucket: bucket, prefixLen: raw.Prefixlen}
			for i := range raw.Addr {
				binary.LittleEndian.PutUint32(key.addr[i*4:(i+1)*4], raw.Addr[i])
			}
			out = append(out, key)
		}
		if err := iter.Err(); err != nil {
			return nil, err
		}
	}
	sortProtectedRuleKeys(out)
	return out, nil
}

func (b bpfProtectedRuleBackend) count(bucket protectedRuleBucket) (uint32, error) {
	m, err := b.mapFor(bucket)
	if err != nil {
		return 0, err
	}
	var value uint8
	var count uint64
	if bucket == protectedAllowedIPv4 || bucket == protectedDeniedIPv4 {
		var key IPv4LPMKey
		iter := m.Iterate()
		for iter.Next(&key, &value) {
			count++
		}
		if err := iter.Err(); err != nil {
			return 0, err
		}
	} else {
		var key IPv6LPMKey
		iter := m.Iterate()
		for iter.Next(&key, &value) {
			count++
		}
		if err := iter.Err(); err != nil {
			return 0, err
		}
	}
	if count > uint64(^uint32(0)) {
		return 0, fmt.Errorf("%s entry count overflows uint32", bucket)
	}
	return uint32(count), nil
}

func (b bpfProtectedRuleBackend) capacity(bucket protectedRuleBucket) (uint32, error) {
	m, err := b.mapFor(bucket)
	if err != nil {
		return 0, err
	}
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	return info.MaxEntries, nil
}

func (b bpfProtectedRuleBackend) put(key protectedRuleKey) error {
	m, err := b.mapFor(key.bucket)
	if err != nil {
		return err
	}
	if key.bucket == protectedAllowedIPv4 || key.bucket == protectedDeniedIPv4 {
		return m.Put(ipv4CIDRToKey(key.cidr()), uint8(1))
	}
	return m.Put(ipv6CIDRToKey(key.cidr()), uint8(1))
}

func (b bpfProtectedRuleBackend) delete(key protectedRuleKey) error {
	m, err := b.mapFor(key.bucket)
	if err != nil {
		return err
	}
	var deleteErr error
	if key.bucket == protectedAllowedIPv4 || key.bucket == protectedDeniedIPv4 {
		deleteErr = m.Delete(ipv4CIDRToKey(key.cidr()))
	} else {
		deleteErr = m.Delete(ipv6CIDRToKey(key.cidr()))
	}
	if deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
		return deleteErr
	}
	return nil
}

func (b bpfProtectedRuleBackend) mode() (PolicyMode, error) {
	if b.policyMode == nil {
		return ModeDisabled, fmt.Errorf("policy mode map handle is closed")
	}
	var mode uint8
	if err := b.policyMode.Lookup(uint32(0), &mode); err != nil {
		return ModeDisabled, err
	}
	return PolicyMode(mode), nil
}

func (b bpfProtectedRuleBackend) setMode(mode PolicyMode) error {
	if b.policyMode == nil {
		return fmt.Errorf("policy mode map handle is closed")
	}
	return b.policyMode.Put(uint32(0), uint8(mode))
}

func (b bpfExactDNSBackend) mapFor(family exactIPFamily) (*ebpf.Map, error) {
	var m *ebpf.Map
	switch family {
	case exactIPv4:
		m = b.ipv4
	case exactIPv6:
		m = b.ipv6
	default:
		return nil, fmt.Errorf("unsupported exact IP family %d", family)
	}
	if m == nil {
		return nil, fmt.Errorf("DNS exact IPv%d map handle is closed", family)
	}
	return m, nil
}

func (b bpfExactDNSBackend) keys(family exactIPFamily) ([]exactIPKey, error) {
	m, err := b.mapFor(family)
	if err != nil {
		return nil, err
	}
	var value uint8
	var out []exactIPKey
	if family == exactIPv4 {
		var raw [4]byte
		iter := m.Iterate()
		for iter.Next(&raw, &value) {
			var key exactIPKey
			key.family = exactIPv4
			copy(key.addr[:4], raw[:])
			out = append(out, key)
		}
		if err := iter.Err(); err != nil {
			return nil, err
		}
	} else {
		var raw [16]byte
		iter := m.Iterate()
		for iter.Next(&raw, &value) {
			var key exactIPKey
			key.family = exactIPv6
			copy(key.addr[:], raw[:])
			out = append(out, key)
		}
		if err := iter.Err(); err != nil {
			return nil, err
		}
	}
	sortExactIPKeys(out)
	return out, nil
}

func (b bpfExactDNSBackend) capacity(family exactIPFamily) (uint32, error) {
	m, err := b.mapFor(family)
	if err != nil {
		return 0, err
	}
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	return info.MaxEntries, nil
}

func exactIPKeyForBPF(key exactIPKey) (any, error) {
	switch key.family {
	case exactIPv4:
		var raw [4]byte
		copy(raw[:], key.addr[:4])
		return raw, nil
	case exactIPv6:
		var raw [16]byte
		copy(raw[:], key.addr[:])
		return raw, nil
	default:
		return nil, fmt.Errorf("unsupported exact IP family %d", key.family)
	}
}

func (b bpfExactDNSBackend) put(key exactIPKey) error {
	m, err := b.mapFor(key.family)
	if err != nil {
		return err
	}
	raw, err := exactIPKeyForBPF(key)
	if err != nil {
		return err
	}
	return m.Put(raw, uint8(1))
}

func (b bpfExactDNSBackend) delete(key exactIPKey) error {
	m, err := b.mapFor(key.family)
	if err != nil {
		return err
	}
	raw, err := exactIPKeyForBPF(key)
	if err != nil {
		return err
	}
	if err := m.Delete(raw); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
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

func sumPerCPUCounter(m *ebpf.Map, key uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(key, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total, nil
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
