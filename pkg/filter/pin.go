//go:build linux

package filter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Pin file names inside a filter's pin directory. Maps use their BPF map
// names; links get a "link_" prefix. These are a persistence format: changing
// them orphans state pinned by earlier daemon versions.
const (
	pinAllowedIPv4    = "allowed_ipv4"
	pinAllowedIPv6    = "allowed_ipv6"
	pinDeniedIPv4     = "denied_ipv4"
	pinDeniedIPv6     = "denied_ipv6"
	pinDNSAllowedIPv4 = "dns_allowed_ipv4"
	pinDNSAllowedIPv6 = "dns_allowed_ipv6"
	pinPolicyMode     = "policy_mode"
	pinStats          = "stats"
	pinSchemaVersion  = "pin_schema_version"

	pinLinkConnect4 = "link_connect4"
	pinLinkConnect6 = "link_connect6"
	pinLinkSendmsg4 = "link_sendmsg4"
	pinLinkSendmsg6 = "link_sendmsg6"
	pinLinkTCX      = "link_tcx"
)

const currentPinSchemaVersion uint32 = 1

// InspectPinnedSchema classifies a pin directory without loading links or
// mutating anything. It is used before orphan cleanup so a crash-partial
// marker-absent/zero pin set is never blindly removed. Future/unknown or
// inconsistent committed schemas return a non-discardable error.
func InspectPinnedSchema(pinDir string) (_ PinnedSchemaState, retErr error) {
	marker, present, err := loadOptionalPinnedMap(pinDir, pinSchemaVersion)
	if err != nil {
		return PinnedSchemaUncommitted, err
	}
	if marker != nil {
		defer func() {
			if err := marker.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("closing inspected pin schema map: %w", err))
			}
		}()
	}
	committed, err := classifyPinnedSchema(marker, present)
	if err != nil {
		return PinnedSchemaUncommitted, err
	}
	if !committed {
		return PinnedSchemaUncommitted, nil
	}
	return inspectCompleteCommittedPinSet(pinDir, marker)
}

func inspectCompleteCommittedPinSet(pinDir string, marker *ebpf.Map) (_ PinnedSchemaState, retErr error) {
	maps := map[string]*ebpf.Map{pinSchemaVersion: marker}
	defer func() {
		for name, m := range maps {
			if name == pinSchemaVersion { // outer InspectPinnedSchema owns marker
				continue
			}
			if err := m.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("closing inspected map %s: %w", name, err))
			}
		}
	}()
	for _, name := range []string{
		pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6,
		pinDNSAllowedIPv4, pinDNSAllowedIPv6, pinPolicyMode, pinStats,
	} {
		loaded, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			return PinnedSchemaUncommitted, pinnedCommittedObjectLoadError("map", name, err)
		}
		maps[name] = loaded
	}

	links := make(map[string]link.Link)
	defer func() {
		for name, l := range links {
			if err := l.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("closing inspected link %s: %w", name, err))
			}
		}
	}()
	for _, name := range []string{pinLinkTCX, pinLinkConnect4, pinLinkConnect6, pinLinkSendmsg4, pinLinkSendmsg6} {
		l, present, err := loadOptionalPinnedLink(pinDir, name)
		if err != nil {
			return PinnedSchemaUncommitted, err
		}
		if present {
			links[name] = l
		}
	}
	_, hasTC := links[pinLinkTCX]
	cgroupCount := 0
	for _, name := range []string{pinLinkConnect4, pinLinkConnect6, pinLinkSendmsg4, pinLinkSendmsg6} {
		if links[name] != nil {
			cgroupCount++
		}
	}
	if (hasTC && cgroupCount != 0) || (!hasTC && cgroupCount != 4) {
		return PinnedSchemaUncommitted, fmt.Errorf("%w: committed pin set has mixed/incomplete links (tc=%t cgroup=%d/4)", ErrPinnedSchemaIncompatible, hasTC, cgroupCount)
	}
	expectedNames := map[string]struct{}{
		pinAllowedIPv4: {}, pinAllowedIPv6: {}, pinDeniedIPv4: {}, pinDeniedIPv6: {},
		pinDNSAllowedIPv4: {}, pinDNSAllowedIPv6: {}, pinPolicyMode: {}, pinStats: {}, pinSchemaVersion: {},
	}
	if hasTC {
		expectedNames[pinLinkTCX] = struct{}{}
	} else {
		for _, name := range []string{pinLinkConnect4, pinLinkConnect6, pinLinkSendmsg4, pinLinkSendmsg6} {
			expectedNames[name] = struct{}{}
		}
	}
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return PinnedSchemaUncommitted, fmt.Errorf("listing committed pin set: %w", err)
	}
	actualNames := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		actualNames[entry.Name()] = struct{}{}
	}
	if len(actualNames) != len(expectedNames) {
		return PinnedSchemaUncommitted, fmt.Errorf("%w: committed pin set has %d directory entries, want exact recognized set of %d", ErrPinnedSchemaIncompatible, len(actualNames), len(expectedNames))
	}
	for name := range expectedNames {
		if _, ok := actualNames[name]; !ok {
			return PinnedSchemaUncommitted, fmt.Errorf("%w: committed pin set is missing recognized entry %s", ErrPinnedSchemaIncompatible, name)
		}
	}

	var spec *ebpf.CollectionSpec
	err = nil
	if hasTC {
		spec, err = loadTc()
	} else {
		spec, err = loadCgroup()
	}
	if err != nil {
		return PinnedSchemaUncommitted, fmt.Errorf("loading current BPF spec for pin inspection: %w", err)
	}
	if err := validatePinnedMapsAgainstSpec(spec, maps); err != nil {
		return PinnedSchemaUncommitted, err
	}

	if hasTC {
		l := links[pinLinkTCX]
		info, err := l.Info()
		if err != nil {
			return PinnedSchemaUncommitted, fmt.Errorf("reading inspected TCX link info: %w", err)
		}
		tcx := info.TCX()
		if tcx == nil || tcx.Ifindex == 0 || (uint32(tcx.AttachType) != uint32(ebpf.AttachTCXIngress) && uint32(tcx.AttachType) != uint32(ebpf.AttachTCXEgress)) {
			return PinnedSchemaUncommitted, fmt.Errorf("%w: committed TCX link has invalid type/attach metadata", ErrPinnedSchemaIncompatible)
		}
		if err := verifyPinnedLinkUsesMaps(l, map[string]*ebpf.Map{
			pinAllowedIPv4: maps[pinAllowedIPv4], pinAllowedIPv6: maps[pinAllowedIPv6],
			pinDeniedIPv4: maps[pinDeniedIPv4], pinDeniedIPv6: maps[pinDeniedIPv6],
			pinDNSAllowedIPv4: maps[pinDNSAllowedIPv4], pinDNSAllowedIPv6: maps[pinDNSAllowedIPv6],
			pinPolicyMode: maps[pinPolicyMode], pinStats: maps[pinStats],
		}); err != nil {
			return PinnedSchemaUncommitted, err
		}
	} else {
		var coherentCgroupID uint64
		for _, item := range []struct {
			name   string
			attach ebpf.AttachType
			ipv6   bool
		}{
			{pinLinkConnect4, ebpf.AttachCGroupInet4Connect, false},
			{pinLinkConnect6, ebpf.AttachCGroupInet6Connect, true},
			{pinLinkSendmsg4, ebpf.AttachCGroupUDP4Sendmsg, false},
			{pinLinkSendmsg6, ebpf.AttachCGroupUDP6Sendmsg, true},
		} {
			l := links[item.name]
			info, err := l.Info()
			if err != nil {
				return PinnedSchemaUncommitted, fmt.Errorf("reading inspected cgroup link %s info: %w", item.name, err)
			}
			cg := info.Cgroup()
			if cg == nil || cg.CgroupId == 0 || uint32(cg.AttachType) != uint32(item.attach) {
				return PinnedSchemaUncommitted, fmt.Errorf("%w: committed cgroup link %s has wrong attach metadata", ErrPinnedSchemaIncompatible, item.name)
			}
			if coherentCgroupID == 0 {
				coherentCgroupID = cg.CgroupId
			} else if cg.CgroupId != coherentCgroupID {
				return PinnedSchemaUncommitted, fmt.Errorf("%w: committed cgroup links identify mixed targets (%d and %d)", ErrPinnedSchemaIncompatible, coherentCgroupID, cg.CgroupId)
			}
			expected := map[string]*ebpf.Map{pinPolicyMode: maps[pinPolicyMode], pinStats: maps[pinStats]}
			if item.ipv6 {
				expected[pinAllowedIPv6], expected[pinDeniedIPv6], expected[pinDNSAllowedIPv6] = maps[pinAllowedIPv6], maps[pinDeniedIPv6], maps[pinDNSAllowedIPv6]
			} else {
				expected[pinAllowedIPv4], expected[pinDeniedIPv4], expected[pinDNSAllowedIPv4] = maps[pinAllowedIPv4], maps[pinDeniedIPv4], maps[pinDNSAllowedIPv4]
			}
			if err := verifyPinnedLinkUsesMaps(l, expected); err != nil {
				return PinnedSchemaUncommitted, fmt.Errorf("verifying inspected cgroup link %s maps: %w", item.name, err)
			}
		}
	}
	return PinnedSchemaCurrent, nil
}

// pinner is satisfied by both *ebpf.Map and link.Link.
type pinner interface {
	Pin(string) error
}

type pinMigrationOps struct {
	pinObject   func(pinner, string) error
	updateLink  func(link.Link, *ebpf.Program) error
	writeSchema func(*ebpf.Map, uint32) error
}

func (o pinMigrationOps) withDefaults() pinMigrationOps {
	if o.pinObject == nil {
		o.pinObject = func(obj pinner, path string) error { return obj.Pin(path) }
	}
	if o.updateLink == nil {
		o.updateLink = func(l link.Link, p *ebpf.Program) error { return l.Update(p) }
	}
	if o.writeSchema == nil {
		o.writeSchema = writePinSchemaVersion
	}
	return o
}

// claimPinDir atomically claims a previously absent attachment pin directory.
// Existing state is never replaced: a collision fails before any BPF program
// is loaded or attached.
func claimPinDir(dir string) error {
	// Claim before loading or attaching any new program. Even a transient
	// stacked BLOCK_ALL attachment would disturb traffic owned by a viable
	// colliding pin set, so EEXIST must fail before kernel mutation.
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return fmt.Errorf("creating pin parent for %s: %w", dir, err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("claiming new pin dir %s without replacing existing state: %w", dir, err)
	}
	return nil
}

// pinAll pins into a directory already exclusively claimed by claimPinDir.
func pinAll(dir string, objects map[string]pinner) error {
	// The schema marker is the commit record. Pin every required map/link in a
	// stable order first, then pin the marker last. A crash at any earlier
	// point leaves marker absent and is restart-classified as an incomplete
	// migration; marker=current can never coexist with a create-time partial
	// pin set produced by this code.
	names := make([]string, 0, len(objects))
	for name := range objects {
		if name != pinSchemaVersion {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		obj := objects[name]
		if err := obj.Pin(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("pinning %s: %w", name, err)
		}
	}
	marker, ok := objects[pinSchemaVersion]
	if !ok || marker == nil {
		return fmt.Errorf("pin set missing commit-last schema marker")
	}
	if err := marker.Pin(filepath.Join(dir, pinSchemaVersion)); err != nil {
		return fmt.Errorf("pinning commit-last %s: %w", pinSchemaVersion, err)
	}
	return nil
}

func writePinSchemaVersion(m *ebpf.Map, version uint32) error {
	if m == nil {
		return fmt.Errorf("pin schema map handle is nil")
	}
	if err := m.Put(uint32(0), version); err != nil {
		return fmt.Errorf("writing pin schema version %d: %w", version, err)
	}
	return nil
}

func readPinSchemaVersion(m *ebpf.Map) (uint32, error) {
	if m == nil {
		return 0, fmt.Errorf("pin schema map handle is nil")
	}
	var version uint32
	if err := m.Lookup(uint32(0), &version); err != nil {
		return 0, fmt.Errorf("reading pin schema version: %w", err)
	}
	return version, nil
}

func loadOptionalPinnedMap(dir, name string) (*ebpf.Map, bool, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
	if err == nil {
		return m, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, pinnedObjectLoadError("map", name, err)
}

func loadOptionalPinnedLink(dir, name string) (link.Link, bool, error) {
	l, err := link.LoadPinnedLink(filepath.Join(dir, name), nil)
	if err == nil {
		return l, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, pinnedObjectLoadError("link", name, err)
}

// classifyPinnedSchema reads the marker before any version-specific object.
// Missing/zero is a restart-convergent legacy/partial migration. A current
// marker makes every required-object failure non-discardable at its call
// site. Future/unknown versions abort immediately, before this binary tries
// names that the newer schema may have renamed or removed.
func classifyPinnedSchema(marker *ebpf.Map, markerPresent bool) (committed bool, err error) {
	if !markerPresent {
		return false, nil
	}
	version, err := readPinSchemaVersion(marker)
	if err != nil {
		return false, err
	}
	switch version {
	case 0:
		return false, nil
	case currentPinSchemaVersion:
		return true, nil
	default:
		return false, fmt.Errorf("%w: found version %d, current binary supports %d", ErrPinnedSchemaIncompatible, version, currentPinSchemaVersion)
	}
}

func pinnedCommittedObjectLoadError(kind, name string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: committed schema %d is missing pinned %s %s: %w", ErrPinnedSchemaIncompatible, currentPinSchemaVersion, kind, name, err)
	}
	return fmt.Errorf("loading committed-schema pinned %s %s: %w", kind, name, err)
}

func loadCommittedPinnedMaps(dir string, dsts map[string]**ebpf.Map) error {
	for name, dst := range dsts {
		m, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
		if err != nil {
			return pinnedCommittedObjectLoadError("map", name, err)
		}
		*dst = m
	}
	return nil
}

func loadUncommittedRequiredPinnedMaps(dir string, dsts map[string]**ebpf.Map) error {
	for name, dst := range dsts {
		m, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: uncommitted/legacy pin set is missing required map %s; preserving possible partial enforcement", ErrPinnedSchemaIncompatible, name)
			}
			return pinnedObjectLoadError("map", name, err)
		}
		*dst = m
	}
	return nil
}

func validatePinnedDirectorySet(dir string, required, optional []string) error {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("listing pinned filter directory %s: %w", dir, err)
	}
	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%w: pin directory %s contains unknown or opposite-kind entry %s", ErrPinnedSchemaIncompatible, dir, name)
		}
		present[name] = struct{}{}
	}
	for _, name := range required {
		if _, ok := present[name]; !ok {
			return fmt.Errorf("%w: pin directory %s is missing required entry %s", ErrPinnedSchemaIncompatible, dir, name)
		}
	}
	return nil
}

func replacementMapOptions(spec *ebpf.CollectionSpec, replacements map[string]*ebpf.Map) error {
	for name, m := range replacements {
		mapSpec, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("BPF spec missing replacement map %s", name)
		}
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("reading pinned replacement map %s info: %w", name, err)
		}
		// Only rule-map capacities are configurable. They keep their
		// creation-time capacity across restarts/config changes. Fixed-shape
		// policy/stats/schema maps retain the compiled spec capacity so a
		// malformed pin cannot make itself look compatible by rewriting it.
		switch name {
		case pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6,
			pinDNSAllowedIPv4, pinDNSAllowedIPv6:
			mapSpec.MaxEntries = info.MaxEntries
		}
	}
	return nil
}

func validatePinnedMapsAgainstSpec(spec *ebpf.CollectionSpec, maps map[string]*ebpf.Map) error {
	if err := replacementMapOptions(spec, maps); err != nil {
		return err
	}
	for name, m := range maps {
		mapSpec, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("%w: current BPF spec has no required map %s", ErrPinnedSchemaIncompatible, name)
		}
		if err := mapSpec.Compatible(m); err != nil {
			return fmt.Errorf("%w: pinned map %s does not match current schema: %w", ErrPinnedSchemaIncompatible, name, err)
		}
	}
	return nil
}

func verifyPinnedLinkUsesMaps(l link.Link, maps map[string]*ebpf.Map) error {
	linkInfo, err := l.Info()
	if err != nil {
		return fmt.Errorf("reading pinned link info: %w", err)
	}
	program, err := ebpf.NewProgramFromID(linkInfo.Program)
	if err != nil {
		return fmt.Errorf("opening pinned link program id %d: %w", linkInfo.Program, err)
	}
	defer program.Close()
	programInfo, err := program.Info()
	if err != nil {
		return fmt.Errorf("reading pinned link program info: %w", err)
	}
	mapIDs, ok := programInfo.MapIDs()
	if !ok {
		return fmt.Errorf("pinned link program does not expose referenced map IDs")
	}
	referenced := make(map[ebpf.MapID]struct{}, len(mapIDs))
	for _, id := range mapIDs {
		referenced[id] = struct{}{}
	}
	for name, m := range maps {
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("reading pinned map %s info: %w", name, err)
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("pinned map %s does not expose a kernel map ID", name)
		}
		if _, ok := referenced[id]; !ok {
			return fmt.Errorf("%w: pinned link program id %d does not reference loaded map %s id %d", ErrPinnedSchemaIncompatible, linkInfo.Program, name, id)
		}
	}
	return nil
}

func pinMigrationMapIfMissing(ops pinMigrationOps, dir, name string, present bool, m *ebpf.Map) error {
	if present {
		return nil
	}
	if m == nil {
		return fmt.Errorf("migration-created map %s is nil", name)
	}
	if err := ops.pinObject(m, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("pinning migration map %s: %w", name, err)
	}
	return nil
}

func verifyUpdatedLinkProgram(l link.Link, program *ebpf.Program, expectedAttach ebpf.AttachType) error {
	linkInfo, err := l.Info()
	if err != nil {
		return fmt.Errorf("reading updated link info: %w", err)
	}
	programInfo, err := program.Info()
	if err != nil {
		return fmt.Errorf("reading desired program info: %w", err)
	}
	programID, ok := programInfo.ID()
	if !ok {
		return fmt.Errorf("desired program has no kernel program ID")
	}
	if linkInfo.Program != programID {
		return fmt.Errorf("link points to program id %d, want newly loaded id %d", linkInfo.Program, programID)
	}
	if cg := linkInfo.Cgroup(); cg != nil {
		if uint32(cg.AttachType) != uint32(expectedAttach) {
			return fmt.Errorf("cgroup link attach type is %d, want %d", cg.AttachType, expectedAttach)
		}
		return nil
	}
	if tcx := linkInfo.TCX(); tcx != nil {
		if uint32(tcx.AttachType) != uint32(expectedAttach) {
			return fmt.Errorf("TCX link attach type is %d, want %d", tcx.AttachType, expectedAttach)
		}
		return nil
	}
	return fmt.Errorf("updated link exposes neither cgroup nor TCX type information")
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
// the daemon reports an enforcing attachment. Unverifiable or wrong-kind
// links are non-discardable unknown live state; only a positively proven
// target-ID mismatch authorizes replacement.
func validateCgroupLinkTarget(l link.Link, name string, wantCgroupID uint64) error {
	if wantCgroupID == 0 {
		return fmt.Errorf("%w: current cgroup target exposes no identity", ErrPinnedSchemaIncompatible)
	}
	gotCgroupID, err := cgroupLinkTargetID(l, name)
	if err != nil {
		return err
	}
	if gotCgroupID != wantCgroupID {
		return fmt.Errorf("%w: pinned link %s is attached to cgroup id %d but the target path is now cgroup id %d", ErrPinnedTargetMismatch, name, gotCgroupID, wantCgroupID)
	}
	return nil
}

func cgroupLinkTargetID(l link.Link, name string) (uint64, error) {
	info, err := l.Info()
	if err != nil {
		return 0, fmt.Errorf("reading pinned link %s info: %w", name, err)
	}
	cg := info.Cgroup()
	if cg == nil {
		return 0, fmt.Errorf("%w: pinned link %s has no cgroup link info", ErrPinnedSchemaIncompatible, name)
	}
	if cg.CgroupId == 0 {
		return 0, fmt.Errorf("%w: pinned link %s exposes no cgroup target identity", ErrPinnedSchemaIncompatible, name)
	}
	expectedAttach := map[string]ebpf.AttachType{
		pinLinkConnect4: ebpf.AttachCGroupInet4Connect,
		pinLinkConnect6: ebpf.AttachCGroupInet6Connect,
		pinLinkSendmsg4: ebpf.AttachCGroupUDP4Sendmsg,
		pinLinkSendmsg6: ebpf.AttachCGroupUDP6Sendmsg,
	}[name]
	if expectedAttach == 0 {
		return 0, fmt.Errorf("%w: unrecognized cgroup link pin name %s", ErrPinnedSchemaIncompatible, name)
	}
	if uint32(cg.AttachType) != uint32(expectedAttach) {
		return 0, fmt.Errorf("%w: pinned link %s has cgroup attach type %d, want %d", ErrPinnedSchemaIncompatible, name, cg.AttachType, expectedAttach)
	}
	return cg.CgroupId, nil
}

// validateTCXLinkTarget is the TC twin of validateCgroupLinkTarget: a TCX
// link binds to an ifindex, and an interface recreated under the same name
// gets a new ifindex, leaving the pinned link defunct.
func validateTCXLinkTarget(l link.Link, name string, wantIfindex int, wantAttach ebpf.AttachType) error {
	if wantIfindex <= 0 {
		return fmt.Errorf("%w: current TCX target exposes no identity", ErrPinnedSchemaIncompatible)
	}
	gotIfindex, err := tcxLinkTargetIfindex(l, name, wantAttach)
	if err != nil {
		return err
	}
	if gotIfindex != uint32(wantIfindex) {
		return fmt.Errorf("%w: pinned link %s is attached to ifindex %d but the interface is now ifindex %d", ErrPinnedTargetMismatch, name, gotIfindex, wantIfindex)
	}
	return nil
}

func tcxLinkTargetIfindex(l link.Link, name string, wantAttach ebpf.AttachType) (uint32, error) {
	info, err := l.Info()
	if err != nil {
		return 0, fmt.Errorf("reading pinned link %s info: %w", name, err)
	}
	tcx := info.TCX()
	if tcx == nil {
		return 0, fmt.Errorf("%w: pinned link %s has no TCX link info", ErrPinnedSchemaIncompatible, name)
	}
	if tcx.Ifindex == 0 {
		return 0, fmt.Errorf("%w: pinned link %s exposes no TCX target identity", ErrPinnedSchemaIncompatible, name)
	}
	if uint32(tcx.AttachType) != uint32(wantAttach) {
		return 0, fmt.Errorf("%w: pinned link %s has TCX attach type %d, want %d", ErrPinnedSchemaIncompatible, name, tcx.AttachType, wantAttach)
	}
	return tcx.Ifindex, nil
}
