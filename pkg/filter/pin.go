//go:build linux

package filter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Pin file names inside a filter's pin directory. Maps use their BPF map
// names; links get a "link_" prefix. These are a persistence format: changing
// them orphans state pinned by earlier daemon versions.
const (
	pinAllowedIPv4 = "allowed_ipv4"
	pinAllowedIPv6 = "allowed_ipv6"
	pinDeniedIPv4  = "denied_ipv4"
	pinDeniedIPv6  = "denied_ipv6"
	pinPolicyMode  = "policy_mode"
	pinStats       = "stats"

	pinLinkConnect4 = "link_connect4"
	pinLinkConnect6 = "link_connect6"
	pinLinkSendmsg4 = "link_sendmsg4"
	pinLinkSendmsg6 = "link_sendmsg6"
	pinLinkTCX      = "link_tcx"
)

// pinner is satisfied by both *ebpf.Map and link.Link.
type pinner interface {
	Pin(string) error
}

// pinAll pins every object under dir, clearing any stale directory from a
// prior life first (pin paths are per-attachment-ID, so an existing dir can
// only be leftover state that nothing else owns). On error the caller is
// responsible for removing dir and closing the objects.
func pinAll(dir string, objects map[string]pinner) error {
	// A stale dir here is leftover from a crashed create or an unclean
	// removal; removing its pin files drops the kernel references, which is
	// exactly the cleanup a stale life needs.
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("clearing stale pin dir %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating pin dir %s: %w", dir, err)
	}
	for name, obj := range objects {
		if err := obj.Pin(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("pinning %s: %w", name, err)
		}
	}
	return nil
}

// keyToIPv4CIDR inverts ipv4CIDRToKey.
func keyToIPv4CIDR(k IPv4LPMKey) *net.IPNet {
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, k.Addr)
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(k.Prefixlen), 32)}
}

// keyToIPv6CIDR inverts ipv6CIDRToKey.
func keyToIPv6CIDR(k IPv6LPMKey) *net.IPNet {
	ip := make(net.IP, net.IPv6len)
	for i, word := range k.Addr {
		binary.LittleEndian.PutUint32(ip[i*4:], word)
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(k.Prefixlen), 128)}
}

// dumpRuleMaps lists every CIDR currently present in an IPv4 + IPv6 rule map
// pair. Used to re-adopt rule state from pinned maps after a daemon restart.
func dumpRuleMaps(m4, m6 *ebpf.Map) ([]*net.IPNet, error) {
	var out []*net.IPNet
	var value uint8

	var k4 IPv4LPMKey
	iter := m4.Iterate()
	for iter.Next(&k4, &value) {
		out = append(out, keyToIPv4CIDR(k4))
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating IPv4 rules: %w", err)
	}

	var k6 IPv6LPMKey
	iter = m6.Iterate()
	for iter.Next(&k6, &value) {
		out = append(out, keyToIPv6CIDR(k6))
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating IPv6 rules: %w", err)
	}
	return out, nil
}

// loadPinnedMaps fills dsts from pinned maps under dir. On error the caller
// is responsible for closing any already-loaded maps.
func loadPinnedMaps(dir string, dsts map[string]**ebpf.Map) error {
	for name, dst := range dsts {
		m, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
		if err != nil {
			return pinnedObjectLoadError("map", name, err)
		}
		*dst = m
	}
	return nil
}

func pinnedObjectLoadError(kind, name string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: missing pinned %s %s: %w", ErrPinnedStateInvalid, kind, name, err)
	}
	return fmt.Errorf("loading pinned %s %s: %w", kind, name, err)
}

// closePinnedLoadOnError finalizes a failed pinned-state load without losing
// a close ambiguity behind the primary error. ErrPinnedStateCloseFailed is a
// veto marker: restore callers must not remove pins when it is present, even
// when the primary failure is structurally discardable.
func closePinnedLoadOnError(retErr *error, closeHandles func() error) {
	if retErr == nil || *retErr == nil {
		return
	}
	if closeErr := closeHandles(); closeErr != nil {
		*retErr = errors.Join(*retErr, fmt.Errorf("%w: %w", ErrPinnedStateCloseFailed, closeErr))
	}
}

// currentCgroupID returns the kernel cgroup id of the cgroup v2 directory at
// path — the id a cgroup bpf_link reports via link info. The canonical
// source is name_to_handle_at (the handle IS the cgroup id on cgroup2); the
// kernfs inode number is an equivalent fallback on modern kernels.
func currentCgroupID(path string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err == nil {
		if b := handle.Bytes(); len(b) >= 8 {
			return binary.LittleEndian.Uint64(b[:8]), nil
		}
	}
	var st unix.Stat_t
	if serr := unix.Stat(path, &st); serr != nil {
		return 0, fmt.Errorf("resolving cgroup id of %s: name_to_handle_at: %v, stat: %w", path, err, serr)
	}
	return st.Ino, nil
}

// validateCgroupLinkTarget guards against target reincarnation: a bpf_link
// binds to the cgroup OBJECT, not its path. If the cgroup was destroyed and
// recreated at the same path while the daemon was down, the pinned link is
// still loadable (and its maps readable) but is attached to the DEAD cgroup —
// adopting it would leave the recreated cgroup completely unfiltered while
// the daemon reports an enforcing attachment. Unverifiable links are refused
// too (fail-closed): the caller falls back to a fresh attachment.
func validateCgroupLinkTarget(l link.Link, name string, wantCgroupID uint64) error {
	info, err := l.Info()
	if err != nil {
		return fmt.Errorf("reading pinned link %s info: %w", name, err)
	}
	cg := info.Cgroup()
	if cg == nil {
		return fmt.Errorf("%w: pinned link %s has no cgroup link info", ErrPinnedStateInvalid, name)
	}
	if cg.CgroupId != wantCgroupID {
		return fmt.Errorf("%w: pinned link %s is attached to cgroup id %d but the target path is now cgroup id %d", ErrPinnedTargetMismatch, name, cg.CgroupId, wantCgroupID)
	}
	return nil
}

// validateTCXLinkTarget is the TC twin of validateCgroupLinkTarget: a TCX
// link binds to an ifindex, and an interface recreated under the same name
// gets a new ifindex, leaving the pinned link defunct.
func validateTCXLinkTarget(l link.Link, name string, wantIfindex int) error {
	info, err := l.Info()
	if err != nil {
		return fmt.Errorf("reading pinned link %s info: %w", name, err)
	}
	tcx := info.TCX()
	if tcx == nil {
		return fmt.Errorf("%w: pinned link %s has no TCX link info", ErrPinnedStateInvalid, name)
	}
	if tcx.Ifindex != uint32(wantIfindex) {
		return fmt.Errorf("%w: pinned link %s is attached to ifindex %d but the interface is now ifindex %d", ErrPinnedTargetMismatch, name, tcx.Ifindex, wantIfindex)
	}
	return nil
}
