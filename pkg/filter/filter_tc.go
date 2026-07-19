//go:build linux

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

// TCDirection selects which TCX hook the TC filter attaches to.
type TCDirection int

const (
	// DirectionEgress filters packets transmitted out through the interface.
	// Correct for an uplink (e.g. eth0) or an interface inside the workload's
	// own network namespace, where the packet destination is the true external
	// destination. This is the default.
	DirectionEgress TCDirection = iota
	// DirectionIngress filters packets received by the host from the
	// interface. Correct for host-side veth peers and VM tap devices, where
	// the workload's outbound traffic arrives at the host as ingress and the
	// packet destination is the true external destination. Attaching EGRESS
	// there would instead see host-to-workload return traffic and filter by
	// the workload's own address.
	DirectionIngress
)

// String returns a human-readable name for the direction
func (d TCDirection) String() string {
	switch d {
	case DirectionIngress:
		return "ingress"
	default:
		return "egress"
	}
}

// TCFilter manages the TC-based BPF filter
type TCFilter struct {
	mu           sync.Mutex
	objs         *tcObjects
	ifaceName    string
	direction    TCDirection
	pinDir       string
	tcLink       link.Link
	removePinDir func(string) error
	// closeHandlesForTest is nil in production. See CgroupFilter.
	closeHandlesForTest   func() error
	handlesCloseAttempted bool
	handlesCloseErr       error
}

// NewTCFilter creates a new TC-based filter attached to the specified
// interface in the given direction (see TCDirection for how to choose). The
// carve-outs are baked into the program as a load-time constant (see
// Carveouts / DefaultCarveouts).
func NewTCFilter(ifaceName string, mode PolicyMode, direction TCDirection, carveouts Carveouts) (*TCFilter, error) {
	return NewTCFilterWithOptions(ifaceName, mode, direction, carveouts, Options{})
}

// NewTCFilterWithOptions is NewTCFilter with load-time tuning (see Options).
func NewTCFilterWithOptions(ifaceName string, mode PolicyMode, direction TCDirection, carveouts Carveouts, opts Options) (*TCFilter, error) {
	// Load the eBPF spec and bake the carve-out flags in before load: the
	// JIT folds the constant, so the per-packet cost is zero, and the value
	// is per-attachment because each filter loads its own program instance.
	spec, err := loadTc()
	if err != nil {
		return nil, fmt.Errorf("loading TC BPF spec: %w", err)
	}
	if err := applyOptions(spec, opts); err != nil {
		return nil, fmt.Errorf("applying TC filter options: %w", err)
	}
	carveoutVar, ok := spec.Variables["carveout_flags"]
	if !ok {
		return nil, fmt.Errorf("TC BPF spec missing carveout_flags variable")
	}
	if err := carveoutVar.Set(carveouts.flags()); err != nil {
		return nil, fmt.Errorf("setting carve-out flags: %w", err)
	}

	objs := &tcObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
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

	attach := ebpf.AttachTCXEgress
	if direction == DirectionIngress {
		attach = ebpf.AttachTCXIngress
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.FilterEgress,
		Attach:    attach,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching TC filter to interface %s (%s): %w", ifaceName, direction, err)
	}

	f := &TCFilter{
		objs:         objs,
		ifaceName:    ifaceName,
		direction:    direction,
		pinDir:       opts.PinDir,
		tcLink:       tcLink,
		removePinDir: os.RemoveAll,
	}

	// Pin link + maps last, once everything is attached: a crash before this
	// point leaves nothing pinned (state dies with the process, as before),
	// while a successful pin means the full set is adoptable after a restart.
	if opts.PinDir != "" {
		if err := pinAll(opts.PinDir, f.pinnables()); err != nil {
			_ = os.RemoveAll(opts.PinDir)
			_ = f.Close()
			return nil, fmt.Errorf("pinning TC filter state: %w", err)
		}
	}

	return f, nil
}

// LoadPinnedTCFilter re-adopts a TC filter previously pinned under pinDir (a
// filter created with Options.PinDir): it loads the pinned rule/mode/stat
// maps and TCX link into a working TCFilter WITHOUT re-attaching anything —
// the pinned link kept the program attached (and enforcing) the whole time,
// and the pinned maps kept the rules. The program handle itself is not
// needed post-attach and is not reloaded.
//
// On error the partially-loaded handles are closed and the pins are left in
// place for the caller to inspect or remove.
func LoadPinnedTCFilter(ifaceName string, direction TCDirection, pinDir string) (_ *TCFilter, retErr error) {
	f := &TCFilter{
		objs:         &tcObjects{},
		ifaceName:    ifaceName,
		direction:    direction,
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

	l, err := link.LoadPinnedLink(filepath.Join(pinDir, pinLinkTCX), nil)
	if err != nil {
		return nil, pinnedObjectLoadError("link", pinLinkTCX, err)
	}
	f.tcLink = l

	// The link must be validated against the interface CURRENTLY under the
	// name: a TCX link binds to an ifindex, so a destroy+recreate under the
	// same name leaves this pin loadable but defunct — adopting it would
	// report enforcement while the recreated interface runs unfiltered (see
	// validateTCXLinkTarget).
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}
	if err := validateTCXLinkTarget(l, pinLinkTCX, iface.Index); err != nil {
		return nil, err
	}

	return f, nil
}

// pinnables returns every object that must be pinned for the filter to
// survive the process, keyed by pin file name.
func (f *TCFilter) pinnables() map[string]pinner {
	return map[string]pinner{
		pinAllowedIPv4: f.objs.AllowedIpv4,
		pinAllowedIPv6: f.objs.AllowedIpv6,
		pinDeniedIPv4:  f.objs.DeniedIpv4,
		pinDeniedIPv6:  f.objs.DeniedIpv6,
		pinPolicyMode:  f.objs.PolicyMode,
		pinStats:       f.objs.Stats,
		pinLinkTCX:     f.tcLink,
	}
}

// Close releases the userspace BPF file descriptors. If the filter is pinned
// the bpffs pins keep the link attached and the maps populated — the kernel
// keeps enforcing (keep-enforcing daemon-stop path). If unpinned, this drops
// the last references and the kernel detaches.
func (f *TCFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeHandles()
}

// Detach permanently removes the filter: it unpins the link and maps
// (removing the pin directory) and closes every handle, dropping the last
// kernel references so enforcement stops. For an unpinned filter this is
// equivalent to Close.
func (f *TCFilter) Detach() error {
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
func (f *TCFilter) closeHandles() (retErr error) {
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

	if f.tcLink != nil {
		l := f.tcLink
		f.tcLink = nil
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TC link: %w", err))
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
func (f *TCFilter) SetMode(mode PolicyMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objs == nil || f.objs.PolicyMode == nil {
		return fmt.Errorf("filter handles are closed")
	}
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

// InterfaceName returns the interface name this filter is attached to
func (f *TCFilter) InterfaceName() string {
	return f.ifaceName
}

// Direction returns the direction this filter is attached in
func (f *TCFilter) Direction() TCDirection {
	return f.direction
}

// Rules lists every CIDR currently present in the allow and deny maps. Used
// to re-adopt rule bookkeeping from pinned maps after a daemon restart.
func (f *TCFilter) Rules() (allowed, denied []*net.IPNet, err error) {
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
