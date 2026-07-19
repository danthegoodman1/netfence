//go:build linux

// Package filter provides eBPF-based network filtering for containers and interfaces.
package filter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// CgroupFilter manages the cgroup-based BPF filter
type CgroupFilter struct {
	ruleMapCore
	objs         *cgroupObjects
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

func (f *CgroupFilter) syncRuleMaps() {
	if f.objs == nil {
		f.setRuleMaps(ruleMapHandles{})
		return
	}
	f.setRuleMaps(ruleMapHandles{
		allowed4: f.objs.AllowedIpv4,
		allowed6: f.objs.AllowedIpv6,
		denied4:  f.objs.DeniedIpv4,
		denied6:  f.objs.DeniedIpv6,
		exact4:   f.objs.DnsAllowedIpv4,
		exact6:   f.objs.DnsAllowedIpv6,
		mode:     f.objs.PolicyMode,
		stats:    f.objs.Stats,
	})
}

// NewCgroupFilter creates a new cgroup-based filter attached to the specified
// cgroup path. The carve-outs are baked into the program as a load-time
// constant (see Carveouts / DefaultCarveouts).
func NewCgroupFilter(cgroupPath string, mode PolicyMode, carveouts Carveouts) (*CgroupFilter, error) {
	return NewCgroupFilterWithOptions(cgroupPath, mode, carveouts, Options{})
}

// NewCgroupFilterWithOptions is NewCgroupFilter with load-time tuning (see
// Options). On an ordinary construction failure it returns (nil, err). If
// cleanup itself is ambiguous, it instead returns a non-nil partial filter
// with the error: the caller owns that partial attachment and must retain its
// target ownership/quarantine until cleanup is explicitly resolved.
func NewCgroupFilterWithOptions(cgroupPath string, mode PolicyMode, carveouts Carveouts, opts Options) (_ *CgroupFilter, retErr error) {
	// Verify cgroup path exists
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cgroup path does not exist: %s", cgroupPath)
	}
	pinClaimed := false
	if opts.PinDir != "" {
		if err := claimPinDir(opts.PinDir); err != nil {
			return nil, err
		}
		pinClaimed = true
		defer func() {
			if retErr == nil || !pinClaimed {
				return
			}
			if err := os.RemoveAll(opts.PinDir); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("cleaning claimed cgroup pin dir %s: %w", opts.PinDir, err))
			}
		}()
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
	fail := func(primary error, partial *CgroupFilter) (*CgroupFilter, error) {
		if pinClaimed {
			if unpinErr := os.RemoveAll(opts.PinDir); unpinErr != nil {
				// Pins may have reached bpffs despite the primary error. Keep
				// handles and directory ownership together for caller Detach.
				pinClaimed = false
				return partial, errors.Join(primary, fmt.Errorf("unpinning partially constructed cgroup filter: %w", unpinErr))
			}
			pinClaimed = false
		}
		if closeErr := partial.Close(); closeErr != nil {
			// Unpin is proven, but a still-live handle may remain attached.
			// Return it so caller Detach/tombstone retains exact ownership.
			return partial, errors.Join(primary, fmt.Errorf("closing partially constructed cgroup filter: %w", closeErr))
		}
		return nil, primary
	}

	// Set the policy mode
	if err := objs.PolicyMode.Put(uint32(0), uint8(mode)); err != nil {
		return fail(fmt.Errorf("setting policy mode: %w", err), &CgroupFilter{objs: objs, pinDir: opts.PinDir, removePinDir: os.RemoveAll})
	}

	// Attach IPv4 filter to the cgroup
	link4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictConnect4,
		Attach:  ebpf.AttachCGroupInet4Connect,
	})
	if err != nil {
		return fail(fmt.Errorf("attaching IPv4 filter to cgroup: %w", err), &CgroupFilter{objs: objs, pinDir: opts.PinDir, removePinDir: os.RemoveAll})
	}

	// Attach IPv6 filter to the cgroup
	link6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictConnect6,
		Attach:  ebpf.AttachCGroupInet6Connect,
	})
	if err != nil {
		return fail(fmt.Errorf("attaching IPv6 filter to cgroup: %w", err), &CgroupFilter{objs: objs, pinDir: opts.PinDir, cgroupLink4: link4, removePinDir: os.RemoveAll})
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
		return fail(fmt.Errorf("attaching IPv4 sendmsg filter to cgroup: %w", err), &CgroupFilter{objs: objs, pinDir: opts.PinDir, cgroupLink4: link4, cgroupLink6: link6, removePinDir: os.RemoveAll})
	}

	// Attach IPv6 unconnected-UDP sendmsg filter to the cgroup
	sendmsg6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.RestrictSendmsg6,
		Attach:  ebpf.AttachCGroupUDP6Sendmsg,
	})
	if err != nil {
		return fail(fmt.Errorf("attaching IPv6 sendmsg filter to cgroup: %w", err), &CgroupFilter{objs: objs, pinDir: opts.PinDir, cgroupLink4: link4, cgroupLink6: link6, sendmsgLink4: sendmsg4, removePinDir: os.RemoveAll})
	}

	f := &CgroupFilter{
		objs:         objs,
		pinDir:       opts.PinDir,
		cgroupLink4:  link4,
		cgroupLink6:  link6,
		sendmsgLink4: sendmsg4,
		sendmsgLink6: sendmsg6,
		removePinDir: os.RemoveAll,
	}
	f.syncRuleMaps()
	if err := writePinSchemaVersion(f.objs.PinSchemaVersion, currentPinSchemaVersion); err != nil {
		return fail(fmt.Errorf("initializing cgroup pin schema: %w", err), f)
	}

	// Pin links + maps last, once everything is attached: a crash before this
	// point leaves nothing pinned (state dies with the process, as before),
	// while a successful pin means the full set is adoptable after a restart.
	if opts.PinDir != "" {
		if err := pinAll(opts.PinDir, f.pinnables()); err != nil {
			return fail(fmt.Errorf("pinning cgroup filter state: %w", err), f)
		}
		pinClaimed = false
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
func LoadPinnedCgroupFilter(cgroupPath, pinDir string) (*CgroupFilter, error) {
	return loadPinnedCgroupFilter(cgroupPath, pinDir, nil, Options{}, pinMigrationOps{})
}

// LoadPinnedCgroupFilterWithOptions is the explicit legacy-schema upgrade
// entry point. originalCarveouts MUST match the posture used to load the old
// pinned program; guessing could loosen enforcement. Existing map capacities
// are always adopted from the pins, while opts.MaxDNSRuleEntries sizes only a
// missing exact map created during migration.
func LoadPinnedCgroupFilterWithOptions(cgroupPath, pinDir string, originalCarveouts Carveouts, opts Options) (*CgroupFilter, error) {
	return loadPinnedCgroupFilter(cgroupPath, pinDir, &originalCarveouts, opts, pinMigrationOps{})
}

func loadPinnedCgroupFilter(cgroupPath, pinDir string, originalCarveouts *Carveouts, opts Options, migrationOps pinMigrationOps) (_ *CgroupFilter, retErr error) {
	f := &CgroupFilter{
		objs:         &cgroupObjects{},
		pinDir:       pinDir,
		removePinDir: os.RemoveAll,
	}
	defer closePinnedLoadOnError(&retErr, f.closeHandles)

	// Inspect the version marker before loading any version-specific path. A
	// newer schema may have renamed those paths; treating that as a missing
	// legacy object would wrongly authorize removal of live future pins.
	marker, markerPresent, err := loadOptionalPinnedMap(pinDir, pinSchemaVersion)
	if err != nil {
		return nil, err
	}
	f.objs.PinSchemaVersion = marker
	committed, err := classifyPinnedSchema(marker, markerPresent)
	if err != nil {
		return nil, err
	}
	legacyRequired := []string{
		pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6, pinPolicyMode, pinStats,
		pinLinkConnect4, pinLinkConnect6, pinLinkSendmsg4, pinLinkSendmsg6,
	}
	if committed {
		if err := validatePinnedDirectorySet(pinDir,
			append(append([]string{}, legacyRequired...), pinDNSAllowedIPv4, pinDNSAllowedIPv6, pinSchemaVersion), nil); err != nil {
			return nil, err
		}
	} else if err := validatePinnedDirectorySet(pinDir, legacyRequired,
		[]string{pinDNSAllowedIPv4, pinDNSAllowedIPv6, pinSchemaVersion}); err != nil {
		return nil, err
	}

	requiredMaps := map[string]**ebpf.Map{
		pinAllowedIPv4: &f.objs.AllowedIpv4,
		pinAllowedIPv6: &f.objs.AllowedIpv6,
		pinDeniedIPv4:  &f.objs.DeniedIpv4,
		pinDeniedIPv6:  &f.objs.DeniedIpv6,
		pinPolicyMode:  &f.objs.PolicyMode,
		pinStats:       &f.objs.Stats,
	}
	if committed {
		requiredMaps[pinDNSAllowedIPv4] = &f.objs.DnsAllowedIpv4
		requiredMaps[pinDNSAllowedIPv6] = &f.objs.DnsAllowedIpv6
		err = loadCommittedPinnedMaps(pinDir, requiredMaps)
	} else {
		err = loadUncommittedRequiredPinnedMaps(pinDir, requiredMaps)
	}
	if err != nil {
		return nil, err
	}

	exact4Present, exact6Present := committed, committed
	if !committed {
		f.objs.DnsAllowedIpv4, exact4Present, err = loadOptionalPinnedMap(pinDir, pinDNSAllowedIPv4)
		if err != nil {
			return nil, err
		}
		f.objs.DnsAllowedIpv6, exact6Present, err = loadOptionalPinnedMap(pinDir, pinDNSAllowedIPv6)
		if err != nil {
			return nil, err
		}
	}
	if committed {
		spec, err := loadCgroup()
		if err != nil {
			return nil, fmt.Errorf("loading current cgroup spec to validate committed pins: %w", err)
		}
		if err := validatePinnedMapsAgainstSpec(spec, map[string]*ebpf.Map{
			pinAllowedIPv4:    f.objs.AllowedIpv4,
			pinAllowedIPv6:    f.objs.AllowedIpv6,
			pinDeniedIPv4:     f.objs.DeniedIpv4,
			pinDeniedIPv6:     f.objs.DeniedIpv6,
			pinDNSAllowedIPv4: f.objs.DnsAllowedIpv4,
			pinDNSAllowedIPv6: f.objs.DnsAllowedIpv6,
			pinPolicyMode:     f.objs.PolicyMode,
			pinStats:          f.objs.Stats,
			pinSchemaVersion:  f.objs.PinSchemaVersion,
		}); err != nil {
			return nil, err
		}
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
	if cgroupID == 0 {
		return nil, fmt.Errorf("%w: current cgroup target exposes no identity", ErrPinnedSchemaIncompatible)
	}
	var pinnedCgroupID uint64
	for _, item := range []struct {
		name string
		dst  *link.Link
	}{
		{pinLinkConnect4, &f.cgroupLink4},
		{pinLinkConnect6, &f.cgroupLink6},
		{pinLinkSendmsg4, &f.sendmsgLink4},
		{pinLinkSendmsg6, &f.sendmsgLink6},
	} {
		name, dst := item.name, item.dst
		l, err := link.LoadPinnedLink(filepath.Join(pinDir, name), nil)
		if err != nil {
			if committed {
				return nil, pinnedCommittedObjectLoadError("link", name, err)
			}
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%w: uncommitted/legacy pin set is missing required link %s; preserving possible partial enforcement", ErrPinnedSchemaIncompatible, name)
			}
			return nil, pinnedObjectLoadError("link", name, err)
		}
		*dst = l
		linkCgroupID, err := cgroupLinkTargetID(l, name)
		if err != nil {
			return nil, err
		}
		if pinnedCgroupID == 0 {
			pinnedCgroupID = linkCgroupID
		} else if linkCgroupID != pinnedCgroupID {
			return nil, fmt.Errorf("%w: pinned cgroup links identify mixed targets (%d and %d)", ErrPinnedSchemaIncompatible, pinnedCgroupID, linkCgroupID)
		}
		familyMaps := map[string]*ebpf.Map{
			pinPolicyMode: f.objs.PolicyMode,
			pinStats:      f.objs.Stats,
		}
		switch name {
		case pinLinkConnect4, pinLinkSendmsg4:
			familyMaps[pinAllowedIPv4] = f.objs.AllowedIpv4
			familyMaps[pinDeniedIPv4] = f.objs.DeniedIpv4
			if committed {
				familyMaps[pinDNSAllowedIPv4] = f.objs.DnsAllowedIpv4
			}
		case pinLinkConnect6, pinLinkSendmsg6:
			familyMaps[pinAllowedIPv6] = f.objs.AllowedIpv6
			familyMaps[pinDeniedIPv6] = f.objs.DeniedIpv6
			if committed {
				familyMaps[pinDNSAllowedIPv6] = f.objs.DnsAllowedIpv6
			}
		}
		if err := verifyPinnedLinkUsesMaps(l, familyMaps); err != nil {
			return nil, fmt.Errorf("verifying cgroup link %s map identity before adoption/migration: %w", name, err)
		}
	}
	// Target mismatch is intentionally last: only a complete link set with
	// coherent old target IDs, attach types, and map identities is safe to
	// classify as a discardable reincarnation.
	if pinnedCgroupID != cgroupID {
		return nil, fmt.Errorf("%w: pinned cgroup links are attached to cgroup id %d but the target path is now cgroup id %d", ErrPinnedTargetMismatch, pinnedCgroupID, cgroupID)
	}

	if committed {
		f.syncRuleMaps()
		return f, nil
	}
	if originalCarveouts == nil {
		return nil, fmt.Errorf("%w: cgroup pin set %s has no committed current schema marker", ErrPinnedSchemaUpgradeRequired, pinDir)
	}
	if err := f.migratePinnedSchema(*originalCarveouts, opts, markerPresent, exact4Present, exact6Present, migrationOps); err != nil {
		return nil, err
	}

	return f, nil
}

func (f *CgroupFilter) migratePinnedSchema(carveouts Carveouts, opts Options, markerPresent, exact4Present, exact6Present bool, migrationOps pinMigrationOps) (retErr error) {
	ops := migrationOps.withDefaults()
	spec, err := loadCgroup()
	if err != nil {
		return fmt.Errorf("loading current cgroup BPF spec for pinned migration: %w", err)
	}
	if err := applyOptions(spec, opts); err != nil {
		return fmt.Errorf("applying cgroup migration options: %w", err)
	}
	carveoutVar, ok := spec.Variables["carveout_flags"]
	if !ok {
		return fmt.Errorf("current cgroup BPF spec missing carveout_flags variable")
	}
	if err := carveoutVar.Set(carveouts.flags()); err != nil {
		return fmt.Errorf("setting migration carve-out flags: %w", err)
	}
	replacements := map[string]*ebpf.Map{
		pinAllowedIPv4: f.objs.AllowedIpv4,
		pinAllowedIPv6: f.objs.AllowedIpv6,
		pinDeniedIPv4:  f.objs.DeniedIpv4,
		pinDeniedIPv6:  f.objs.DeniedIpv6,
		pinPolicyMode:  f.objs.PolicyMode,
		pinStats:       f.objs.Stats,
	}
	if exact4Present {
		replacements[pinDNSAllowedIPv4] = f.objs.DnsAllowedIpv4
	}
	if exact6Present {
		replacements[pinDNSAllowedIPv6] = f.objs.DnsAllowedIpv6
	}
	if markerPresent {
		replacements[pinSchemaVersion] = f.objs.PinSchemaVersion
	}
	if err := replacementMapOptions(spec, replacements); err != nil {
		return err
	}

	upgraded := &cgroupObjects{}
	if err := spec.LoadAndAssign(upgraded, &ebpf.CollectionOptions{MapReplacements: replacements}); err != nil {
		return fmt.Errorf("loading current cgroup programs over pinned maps: %w", err)
	}
	defer func() {
		if upgraded != nil {
			if err := upgraded.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("closing cgroup migration objects: %w", err))
			}
		}
	}()

	// Zero is durable in-progress. Pin missing exact maps first and marker last;
	// until link updates begin the legacy programs continue enforcing unchanged.
	if err := ops.writeSchema(upgraded.PinSchemaVersion, 0); err != nil {
		return err
	}
	if err := pinMigrationMapIfMissing(ops, f.pinDir, pinDNSAllowedIPv4, exact4Present, upgraded.DnsAllowedIpv4); err != nil {
		return err
	}
	if err := pinMigrationMapIfMissing(ops, f.pinDir, pinDNSAllowedIPv6, exact6Present, upgraded.DnsAllowedIpv6); err != nil {
		return err
	}
	if err := pinMigrationMapIfMissing(ops, f.pinDir, pinSchemaVersion, markerPresent, upgraded.PinSchemaVersion); err != nil {
		return err
	}

	updates := []struct {
		name   string
		link   link.Link
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{pinLinkConnect4, f.cgroupLink4, upgraded.RestrictConnect4, ebpf.AttachCGroupInet4Connect},
		{pinLinkConnect6, f.cgroupLink6, upgraded.RestrictConnect6, ebpf.AttachCGroupInet6Connect},
		{pinLinkSendmsg4, f.sendmsgLink4, upgraded.RestrictSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{pinLinkSendmsg6, f.sendmsgLink6, upgraded.RestrictSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, update := range updates {
		if err := ops.updateLink(update.link, update.prog); err != nil {
			return fmt.Errorf("updating pinned cgroup link %s (schema marker remains in-progress): %w", update.name, err)
		}
	}
	for _, update := range updates {
		if err := verifyUpdatedLinkProgram(update.link, update.prog, update.attach); err != nil {
			return fmt.Errorf("verifying pinned cgroup link %s before schema commit: %w", update.name, err)
		}
	}
	if err := ops.writeSchema(upgraded.PinSchemaVersion, currentPinSchemaVersion); err != nil {
		return fmt.Errorf("committing migrated cgroup pin schema: %w", err)
	}

	// Links now own the programs. Close their userspace fds, retain the cloned
	// replacement/new map handles as the adopted filter object.
	if err := upgraded.cgroupPrograms.Close(); err != nil {
		return fmt.Errorf("closing migrated cgroup program handles: %w", err)
	}
	upgraded.cgroupPrograms = cgroupPrograms{}
	old := f.objs
	f.objs = upgraded
	f.syncRuleMaps()
	upgraded = nil
	if err := old.Close(); err != nil {
		return fmt.Errorf("closing pre-migration cgroup map handles: %w", err)
	}
	return nil
}

// pinnables returns every object that must be pinned for the filter to
// survive the process, keyed by pin file name.
func (f *CgroupFilter) pinnables() map[string]pinner {
	return map[string]pinner{
		pinAllowedIPv4:    f.objs.AllowedIpv4,
		pinAllowedIPv6:    f.objs.AllowedIpv6,
		pinDeniedIPv4:     f.objs.DeniedIpv4,
		pinDeniedIPv6:     f.objs.DeniedIpv6,
		pinDNSAllowedIPv4: f.objs.DnsAllowedIpv4,
		pinDNSAllowedIPv6: f.objs.DnsAllowedIpv6,
		pinPolicyMode:     f.objs.PolicyMode,
		pinStats:          f.objs.Stats,
		pinSchemaVersion:  f.objs.PinSchemaVersion,
		pinLinkConnect4:   f.cgroupLink4,
		pinLinkConnect6:   f.cgroupLink6,
		pinLinkSendmsg4:   f.sendmsgLink4,
		pinLinkSendmsg6:   f.sendmsgLink6,
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
		f.syncRuleMaps()
		if err := objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}
	return nil
}
