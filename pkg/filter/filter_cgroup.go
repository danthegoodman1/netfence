//go:build linux

// Package filter provides eBPF-based network filtering for containers and interfaces.
package filter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// CgroupFilter manages the cgroup-based BPF filter
type CgroupFilter struct {
	mu           sync.Mutex
	objs         *cgroupObjects
	cgroupPath   string
	pinDir       string
	cgroupLink4  link.Link
	cgroupLink6  link.Link
	sendmsgLink4 link.Link
	sendmsgLink6 link.Link
	removePinDir func(string) error
	// closeHandlesForTest is nil in production. It lets unit tests exercise
	// Detach's close-once/unpin-retry state machine without privileged BPF FDs.
	closeHandlesForTest   func() error
	handlesCloseAttempted bool
	handlesCloseErr       error
}

// NewCgroupFilter creates a new cgroup-based filter attached to the specified
// cgroup path. The carve-outs are baked into the program as a load-time
// constant (see Carveouts / DefaultCarveouts).
func NewCgroupFilter(cgroupPath string, mode PolicyMode, carveouts Carveouts) (*CgroupFilter, error) {
	return NewCgroupFilterWithOptions(cgroupPath, mode, carveouts, Options{})
}

// NewCgroupFilterWithOptions is NewCgroupFilter with load-time tuning (see
// Options).
func NewCgroupFilterWithOptions(cgroupPath string, mode PolicyMode, carveouts Carveouts, opts Options) (*CgroupFilter, error) {
	// Verify cgroup path exists
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cgroup path does not exist: %s", cgroupPath)
	}

	// Load the eBPF spec and bake the carve-out flags in before load: the
	// JIT folds the constant, so the per-packet cost is zero, and the value
	// is per-attachment because each filter loads its own program instance.
	spec, err := loadCgroup()
	if err != nil {
		return nil, fmt.Errorf("loading cgroup BPF spec: %w", err)
	}
	if err := applyOptions(spec, opts); err != nil {
		return nil, fmt.Errorf("applying cgroup filter options: %w", err)
	}
	carveoutVar, ok := spec.Variables["carveout_flags"]
	if !ok {
		return nil, fmt.Errorf("cgroup BPF spec missing carveout_flags variable")
	}
	if err := carveoutVar.Set(carveouts.flags()); err != nil {
		return nil, fmt.Errorf("setting carve-out flags: %w", err)
	}

	objs := &cgroupObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
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

	// Attach IPv4 unconnected-UDP sendmsg filter to the cgroup. Unconnected
	// sendto/sendmsg with a destination address bypasses the connect hooks,
	// so it must be filtered separately with the same policy.
	sendmsg4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictSendmsg4,
		Attach:  ebpf.AttachCGroupUDP4Sendmsg,
	})
	if err != nil {
		link6.Close()
		link4.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching IPv4 sendmsg filter to cgroup: %w", err)
	}

	// Attach IPv6 unconnected-UDP sendmsg filter to the cgroup
	sendmsg6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictSendmsg6,
		Attach:  ebpf.AttachCGroupUDP6Sendmsg,
	})
	if err != nil {
		sendmsg4.Close()
		link6.Close()
		link4.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching IPv6 sendmsg filter to cgroup: %w", err)
	}

	f := &CgroupFilter{
		objs:         objs,
		cgroupPath:   cgroupPath,
		pinDir:       opts.PinDir,
		cgroupLink4:  link4,
		cgroupLink6:  link6,
		sendmsgLink4: sendmsg4,
		sendmsgLink6: sendmsg6,
		removePinDir: os.RemoveAll,
	}

	// Pin links + maps last, once everything is attached: a crash before this
	// point leaves nothing pinned (state dies with the process, as before),
	// while a successful pin means the full set is adoptable after a restart.
	if opts.PinDir != "" {
		if err := pinAll(opts.PinDir, f.pinnables()); err != nil {
			_ = os.RemoveAll(opts.PinDir)
			_ = f.Close()
			return nil, fmt.Errorf("pinning cgroup filter state: %w", err)
		}
	}

	return f, nil
}

// LoadPinnedCgroupFilter re-adopts a cgroup filter previously pinned under
// pinDir (a filter created with Options.PinDir): it loads the pinned rule/
// mode/stat maps and cgroup links into a working CgroupFilter WITHOUT
// re-attaching anything — the pinned links kept the programs attached (and
// enforcing) the whole time, and the pinned maps kept the rules. The program
// handles themselves are not needed post-attach and are not reloaded.
//
// On error the partially-loaded handles are closed and the pins are left in
// place for the caller to inspect or remove.
func LoadPinnedCgroupFilter(cgroupPath, pinDir string) (_ *CgroupFilter, retErr error) {
	f := &CgroupFilter{
		objs:         &cgroupObjects{},
		cgroupPath:   cgroupPath,
		pinDir:       pinDir,
		removePinDir: os.RemoveAll,
	}
	defer closePinnedLoadOnError(&retErr, f.closeHandles)

	if err := loadPinnedMaps(pinDir, map[string]**ebpf.Map{
		pinAllowedIPv4: &f.objs.AllowedIpv4,
		pinAllowedIPv6: &f.objs.AllowedIpv6,
		pinDeniedIPv4:  &f.objs.DeniedIpv4,
		pinDeniedIPv6:  &f.objs.DeniedIpv6,
		pinPolicyMode:  &f.objs.PolicyMode,
		pinStats:       &f.objs.Stats,
	}); err != nil {
		return nil, err
	}

	// The links must be validated against the cgroup CURRENTLY at the path:
	// a bpf_link binds to the cgroup object, so a destroy+recreate at the
	// same path (routine container restart) leaves these pins loadable but
	// defunct — adopting them would report enforcement while the recreated
	// cgroup runs unfiltered (see validateCgroupLinkTarget).
	cgroupID, err := currentCgroupID(cgroupPath)
	if err != nil {
		return nil, err
	}
	for name, dst := range map[string]*link.Link{
		pinLinkConnect4: &f.cgroupLink4,
		pinLinkConnect6: &f.cgroupLink6,
		pinLinkSendmsg4: &f.sendmsgLink4,
		pinLinkSendmsg6: &f.sendmsgLink6,
	} {
		l, err := link.LoadPinnedLink(filepath.Join(pinDir, name), nil)
		if err != nil {
			return nil, pinnedObjectLoadError("link", name, err)
		}
		*dst = l
		if err := validateCgroupLinkTarget(l, name, cgroupID); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// pinnables returns every object that must be pinned for the filter to
// survive the process, keyed by pin file name.
func (f *CgroupFilter) pinnables() map[string]pinner {
	return map[string]pinner{
		pinAllowedIPv4:  f.objs.AllowedIpv4,
		pinAllowedIPv6:  f.objs.AllowedIpv6,
		pinDeniedIPv4:   f.objs.DeniedIpv4,
		pinDeniedIPv6:   f.objs.DeniedIpv6,
		pinPolicyMode:   f.objs.PolicyMode,
		pinStats:        f.objs.Stats,
		pinLinkConnect4: f.cgroupLink4,
		pinLinkConnect6: f.cgroupLink6,
		pinLinkSendmsg4: f.sendmsgLink4,
		pinLinkSendmsg6: f.sendmsgLink6,
	}
}

// Close releases the userspace BPF file descriptors. If the filter is pinned
// the bpffs pins keep the links attached and the maps populated — the kernel
// keeps enforcing (keep-enforcing daemon-stop path). If unpinned, this drops
// the last references and the kernel detaches.
func (f *CgroupFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeHandles()
}

// Detach permanently removes the filter: it unpins all links and maps
// (removing the pin directory) and closes every handle, dropping the last
// kernel references so enforcement stops. For an unpinned filter this is
// equivalent to Close.
func (f *CgroupFilter) Detach() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var errs []error
	// Removing the bpffs entries IS the unpin: once the pin files are gone,
	// our fds hold the only references and closeHandles drops them.
	if f.pinDir != "" {
		remove := f.removePinDir
		if remove == nil {
			remove = os.RemoveAll
		}
		if err := remove(f.pinDir); err != nil {
			errs = append(errs, fmt.Errorf("removing pin dir %s: %w", f.pinDir, err))
		}
	}
	if err := f.closeHandles(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors during detach: %v", errs)
	}
	return nil
}

// closeHandles closes all fds. Callers hold f.mu (or have exclusive access
// during construction).
func (f *CgroupFilter) closeHandles() (retErr error) {
	if f.handlesCloseAttempted {
		return f.handlesCloseErr
	}
	f.handlesCloseAttempted = true
	defer func() { f.handlesCloseErr = retErr }()
	if f.closeHandlesForTest != nil {
		closeFn := f.closeHandlesForTest
		f.closeHandlesForTest = nil
		return closeFn()
	}
	var errs []error

	if f.cgroupLink4 != nil {
		l := f.cgroupLink4
		f.cgroupLink4 = nil
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing IPv4 cgroup link: %w", err))
		}
	}

	if f.cgroupLink6 != nil {
		l := f.cgroupLink6
		f.cgroupLink6 = nil
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing IPv6 cgroup link: %w", err))
		}
	}

	if f.sendmsgLink4 != nil {
		l := f.sendmsgLink4
		f.sendmsgLink4 = nil
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing IPv4 sendmsg cgroup link: %w", err))
		}
	}

	if f.sendmsgLink6 != nil {
		l := f.sendmsgLink6
		f.sendmsgLink6 = nil
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing IPv6 sendmsg cgroup link: %w", err))
		}
	}

	if f.objs != nil {
		objs := f.objs
		f.objs = nil
		if err := objs.Close(); err != nil {
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
	if f.objs == nil || f.objs.PolicyMode == nil {
		return fmt.Errorf("filter handles are closed")
	}
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
	if f.objs == nil || f.objs.Stats == nil {
		return stats, fmt.Errorf("filter handles are closed")
	}
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

// Rules lists every CIDR currently present in the allow and deny maps. Used
// to re-adopt rule bookkeeping from pinned maps after a daemon restart.
func (f *CgroupFilter) Rules() (allowed, denied []*net.IPNet, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	allowed, err = dumpRuleMaps(f.objs.AllowedIpv4, f.objs.AllowedIpv6)
	if err != nil {
		return nil, nil, fmt.Errorf("dumping allowed rules: %w", err)
	}
	denied, err = dumpRuleMaps(f.objs.DeniedIpv4, f.objs.DeniedIpv6)
	if err != nil {
		return nil, nil, fmt.Errorf("dumping denied rules: %w", err)
	}
	return allowed, denied, nil
}
