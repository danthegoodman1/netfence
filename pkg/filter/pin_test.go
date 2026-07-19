//go:build linux

package filter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// pinTestRoot returns a unique bpffs directory for a test, skipping when the
// environment cannot host pins (no root or no bpffs mount).
func pinTestRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || uint32(st.Type) != uint32(unix.BPF_FS_MAGIC) {
		t.Skip("bpffs not mounted at /sys/fs/bpf")
	}
	root := filepath.Join("/sys/fs/bpf", fmt.Sprintf("netfence-pintest-%d-%s", os.Getpid(), t.Name()))
	require := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	require(os.RemoveAll(root))
	require(os.MkdirAll(root, 0o700))
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func mustParse(t *testing.T, s string) *net.IPNet {
	t.Helper()
	cidr, err := ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return cidr
}

func TestPinnedObjectLoadErrorOnlyClassifiesMissingObjectsAsStructural(t *testing.T) {
	missing := pinnedObjectLoadError("map", pinPolicyMode, os.ErrNotExist)
	if !errors.Is(missing, ErrPinnedStateInvalid) || !errors.Is(missing, os.ErrNotExist) {
		t.Fatalf("missing pin must retain both classifications: %v", missing)
	}
	for _, ambiguous := range []error{unix.EIO, unix.EACCES, unix.ENOMEM} {
		err := pinnedObjectLoadError("map", pinPolicyMode, ambiguous)
		if errors.Is(err, ErrPinnedStateInvalid) {
			t.Fatalf("ambiguous load error %v was incorrectly made discardable: %v", ambiguous, err)
		}
		if !errors.Is(err, ambiguous) {
			t.Fatalf("ambiguous load cause %v was lost: %v", ambiguous, err)
		}
	}
}

func TestPinnedLoadCloseFailureVetoesDiscardablePrimaryError(t *testing.T) {
	loadErr := fmt.Errorf("%w: required map missing", ErrPinnedStateInvalid)
	closePinnedLoadOnError(&loadErr, func() error { return unix.EIO })
	if !errors.Is(loadErr, ErrPinnedStateInvalid) {
		t.Fatalf("primary structural classification was lost: %v", loadErr)
	}
	if !errors.Is(loadErr, ErrPinnedStateCloseFailed) || !errors.Is(loadErr, unix.EIO) {
		t.Fatalf("partial-close ambiguity was not propagated: %v", loadErr)
	}
}

type recordingPinner struct {
	name   string
	calls  *[]string
	failAt string
}

func (p recordingPinner) Pin(string) error {
	*p.calls = append(*p.calls, p.name)
	if p.name == p.failAt {
		return unix.EIO
	}
	return nil
}

func TestPinAllPinsSchemaMarkerStrictlyLast(t *testing.T) {
	newObjects := func(calls *[]string, failAt string) map[string]pinner {
		return map[string]pinner{
			"z_map":          recordingPinner{name: "z_map", calls: calls, failAt: failAt},
			"a_link":         recordingPinner{name: "a_link", calls: calls, failAt: failAt},
			pinSchemaVersion: recordingPinner{name: pinSchemaVersion, calls: calls, failAt: failAt},
			"m_map":          recordingPinner{name: "m_map", calls: calls, failAt: failAt},
		}
	}
	var calls []string
	requireOrder := []string{"a_link", "m_map", "z_map", pinSchemaVersion}
	if err := pinAll("unused", newObjects(&calls, "")); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(calls) != fmt.Sprint(requireOrder) {
		t.Fatalf("pin order=%v, want %v", calls, requireOrder)
	}

	calls = nil
	err := pinAll("unused", newObjects(&calls, "m_map"))
	if !errors.Is(err, unix.EIO) {
		t.Fatalf("want injected pin failure, got %v", err)
	}
	if fmt.Sprint(calls) != fmt.Sprint([]string{"a_link", "m_map"}) {
		t.Fatalf("pinning continued to marker after earlier failure: %v", calls)
	}
}

func TestTargetValidationTreatsZeroCurrentIdentityAsNonDiscardable(t *testing.T) {
	if err := validateCgroupLinkTarget(nil, pinLinkConnect4, 0); !errors.Is(err, ErrPinnedSchemaIncompatible) || errors.Is(err, ErrPinnedTargetMismatch) {
		t.Fatalf("zero current cgroup identity must be non-discardable, got %v", err)
	}
	if err := validateTCXLinkTarget(nil, pinLinkTCX, 0, ebpf.AttachTCXEgress); !errors.Is(err, ErrPinnedSchemaIncompatible) || errors.Is(err, ErrPinnedTargetMismatch) {
		t.Fatalf("zero current TCX identity must be non-discardable, got %v", err)
	}
}

func cidrStrings(cidrs []*net.IPNet) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, c.String())
	}
	return out
}

func assertSameCIDRSet(t *testing.T, want []string, got []*net.IPNet, msg string) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, s := range cidrStrings(got) {
		gotSet[s] = true
	}
	if len(gotSet) != len(want) {
		t.Fatalf("%s: want %v, got %v", msg, want, cidrStrings(got))
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Fatalf("%s: want %v, got %v", msg, want, cidrStrings(got))
		}
	}
}

func assertSameIPSet(t *testing.T, want []string, got []net.IP, msg string) {
	t.Helper()
	gotSet := make(map[string]bool, len(got))
	for _, ip := range got {
		gotSet[ip.String()] = true
	}
	if len(gotSet) != len(want) {
		t.Fatalf("%s: want %v, got %v", msg, want, got)
	}
	for _, ip := range want {
		if !gotSet[ip] {
			t.Fatalf("%s: want %v, got %v", msg, want, got)
		}
	}
}

func loadLegacyCollection(t *testing.T, fixture string) *ebpf.Collection {
	return loadLegacyCollectionWithCarveouts(t, fixture, nil)
}

func loadLegacyCollectionWithCarveouts(t *testing.T, fixture string, carveouts *Carveouts) *ebpf.Collection {
	t.Helper()
	spec := loadLegacyCollectionSpec(t, fixture, carveouts)
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("loading legacy fixture collection: %v", err)
	}
	return collection
}

func loadLegacyCollectionSpec(t *testing.T, fixture string, carveouts *Carveouts) *ebpf.CollectionSpec {
	t.Helper()
	obj := filepath.Join(t.TempDir(), fixture+".o")
	cmd := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-Wall", "-Werror",
		"-c", filepath.Join("testdata", fixture+".c"), "-o", obj,
		"-I/usr/include/bpf", "-I/usr/include")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compiling genuine legacy fixture: %v: %s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatalf("loading legacy fixture spec: %v", err)
	}
	for _, absent := range []string{pinDNSAllowedIPv4, pinDNSAllowedIPv6, pinSchemaVersion} {
		if _, ok := spec.Maps[absent]; ok {
			t.Fatalf("frozen pre-exact fixture unexpectedly contains %s", absent)
		}
	}
	if carveouts != nil {
		carveoutVar, ok := spec.Variables["carveout_flags"]
		if !ok {
			t.Fatal("frozen legacy fixture missing carveout_flags variable")
		}
		if err := carveoutVar.Set(carveouts.flags()); err != nil {
			t.Fatalf("setting frozen legacy carve-outs: %v", err)
		}
	}
	return spec
}

func pinLegacyMaps(t *testing.T, pinDir string, collection *ebpf.Collection) {
	t.Helper()
	if err := claimPinDir(pinDir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6, pinPolicyMode, pinStats} {
		m := collection.Maps[name]
		if m == nil {
			t.Fatalf("legacy fixture missing map %s", name)
		}
		if err := m.Pin(filepath.Join(pinDir, name)); err != nil {
			t.Fatalf("pinning legacy map %s: %v", name, err)
		}
	}
}

func createLegacyCgroupPinSet(t *testing.T, cgroupPath, pinDir string, mode PolicyMode, allowed *net.IPNet) {
	t.Helper()
	carveouts := DefaultCarveouts()
	createLegacyCgroupPinSetWithCarveouts(t, cgroupPath, pinDir, mode, allowed, carveouts)
}

func createLegacyCgroupPinSetWithCarveouts(t *testing.T, cgroupPath, pinDir string, mode PolicyMode, allowed *net.IPNet, carveouts Carveouts) {
	t.Helper()
	collection := loadLegacyCollectionWithCarveouts(t, "legacy_cgroup", &carveouts)
	defer collection.Close()
	if err := collection.Maps[pinPolicyMode].Put(uint32(0), uint8(mode)); err != nil {
		t.Fatal(err)
	}
	if allowed != nil {
		if err := collection.Maps[pinAllowedIPv4].Put(ipv4CIDRToKey(allowed), uint8(1)); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]link.Link{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, item := range []struct {
		name   string
		prog   string
		attach ebpf.AttachType
	}{
		{pinLinkConnect4, "restrict_connect4", ebpf.AttachCGroupInet4Connect},
		{pinLinkConnect6, "restrict_connect6", ebpf.AttachCGroupInet6Connect},
		{pinLinkSendmsg4, "restrict_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg},
		{pinLinkSendmsg6, "restrict_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Program: collection.Programs[item.prog], Attach: item.attach})
		if err != nil {
			t.Fatalf("attaching legacy %s: %v", item.name, err)
		}
		links[item.name] = l
	}
	pinLegacyMaps(t, pinDir, collection)
	for name, l := range links {
		if err := l.Pin(filepath.Join(pinDir, name)); err != nil {
			t.Fatalf("pinning legacy link %s: %v", name, err)
		}
	}
}

func createLegacyTCPinSet(t *testing.T, iface, pinDir string, mode PolicyMode, allowed *net.IPNet) {
	t.Helper()
	createLegacyTCPinSetDirection(t, iface, pinDir, mode, allowed, DirectionEgress)
}

func createLegacyTCPinSetDirection(t *testing.T, iface, pinDir string, mode PolicyMode, allowed *net.IPNet, direction TCDirection) {
	t.Helper()
	collection := loadLegacyCollection(t, "legacy_tc")
	defer collection.Close()
	if err := collection.Maps[pinPolicyMode].Put(uint32(0), uint8(mode)); err != nil {
		t.Fatal(err)
	}
	if allowed != nil {
		if err := collection.Maps[pinAllowedIPv4].Put(ipv4CIDRToKey(allowed), uint8(1)); err != nil {
			t.Fatal(err)
		}
	}
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	attach := ebpf.AttachTCXEgress
	if direction == DirectionIngress {
		attach = ebpf.AttachTCXIngress
	}
	l, err := link.AttachTCX(link.TCXOptions{Interface: netIface.Index, Program: collection.Programs["filter_egress"], Attach: attach})
	if err != nil {
		t.Fatalf("attaching legacy TCX program: %v", err)
	}
	defer l.Close()
	pinLegacyMaps(t, pinDir, collection)
	if err := l.Pin(filepath.Join(pinDir, pinLinkTCX)); err != nil {
		t.Fatalf("pinning legacy TCX link: %v", err)
	}
}

func readPinnedSchemaForTest(t *testing.T, pinDir string) (uint32, bool) {
	t.Helper()
	m, present, err := loadOptionalPinnedMap(pinDir, pinSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		return 0, false
	}
	defer m.Close()
	version, err := readPinSchemaVersion(m)
	if err != nil {
		t.Fatal(err)
	}
	return version, true
}

func pinnedLinkProgramID(t *testing.T, path string) ebpf.ProgramID {
	t.Helper()
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		t.Fatalf("loading pinned link %s: %v", path, err)
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		t.Fatalf("reading pinned link info %s: %v", path, err)
	}
	return info.Program
}

func pinDirectoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("listing pin directory %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestPinnedCgroupDialHelperProcess(t *testing.T) {
	if os.Getenv("NETFENCE_PIN_DIAL_HELPER") != "1" {
		return
	}
	conn, err := net.DialTimeout("tcp4", os.Getenv("NETFENCE_PIN_DIAL_ADDR"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func dialFromPinnedTestCgroup(cgroupPath, addr string) bool {
	cmd := exec.Command("sh", "-c", `echo $$ > "$NETFENCE_PIN_CGROUP/cgroup.procs" && exec "$NETFENCE_PIN_TEST_BINARY" -test.run '^TestPinnedCgroupDialHelperProcess$' -test.count=1`)
	cmd.Env = append(os.Environ(),
		"NETFENCE_PIN_DIAL_HELPER=1",
		"NETFENCE_PIN_DIAL_ADDR="+addr,
		"NETFENCE_PIN_CGROUP="+cgroupPath,
		"NETFENCE_PIN_TEST_BINARY="+os.Args[0],
	)
	return cmd.Run() == nil
}

func listenPinTestTCP(t *testing.T, ip net.IP) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln
}

func pinTestIPCommand(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
}

func setupPinTestTCNetns(t *testing.T) (iface, namespace, allowedIP, blockedIP string) {
	t.Helper()
	iface, peer, namespace := "nfpmh0", "nfpmp0", "nfpmns0"
	cleanup := func() {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
		_ = exec.Command("ip", "link", "del", iface).Run()
	}
	cleanup()
	t.Cleanup(cleanup)
	pinTestIPCommand(t, "netns", "add", namespace)
	pinTestIPCommand(t, "link", "add", iface, "type", "veth", "peer", "name", peer)
	pinTestIPCommand(t, "link", "set", peer, "netns", namespace)
	for _, addr := range []string{"10.249.0.1", "10.249.0.3", "10.249.0.5"} {
		pinTestIPCommand(t, "addr", "add", addr+"/24", "dev", iface)
	}
	pinTestIPCommand(t, "link", "set", iface, "up")
	pinTestIPCommand(t, "-n", namespace, "addr", "add", "10.249.0.2/24", "dev", peer)
	pinTestIPCommand(t, "-n", namespace, "link", "set", peer, "up")
	pinTestIPCommand(t, "-n", namespace, "link", "set", "lo", "up")
	return iface, namespace, "10.249.0.3", "10.249.0.5"
}

func dialFromPinTestNetns(namespace, host, port string) bool {
	return exec.Command("ip", "netns", "exec", namespace, "nc", "-z", "-w", "2", host, port).Run() == nil
}

// queryCgroupProgCount counts programs attached to the cgroup for one attach
// type — the ground truth for "exactly one attachment, never duplicated".
func queryCgroupProgCount(t *testing.T, cgroupPath string, attach ebpf.AttachType) int {
	t.Helper()
	dir, err := os.Open(cgroupPath)
	if err != nil {
		t.Fatalf("opening cgroup: %v", err)
	}
	defer dir.Close()
	res, err := link.QueryPrograms(link.QueryOptions{Target: int(dir.Fd()), Attach: attach})
	if err != nil {
		t.Fatalf("querying cgroup programs: %v", err)
	}
	return len(res.Programs)
}

// waitForZeroPrograms polls until no program is attached for the attach type
// (kernel link teardown is deferred past the last fd close).
func waitForZeroPrograms(t *testing.T, cgroupPath string, attach ebpf.AttachType, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := queryCgroupProgCount(t, cgroupPath, attach)
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Detach must remove the %s attachment: still %d programs", name, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCgroupFilterPinRestoreRoundTrip proves the 3A filter contract on a real
// kernel: create+pin -> rules -> Close (fds gone, pins keep the attachment
// and rules alive) -> LoadPinnedCgroupFilter re-adopts WITHOUT re-attaching
// (mode + rules intact, still exactly one program per hook) -> Detach removes
// the pins and the kernel attachment.
func TestCgroupFilterPinRestoreRoundTrip(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-1")

	cgroupPath := "/sys/fs/cgroup/netfence-pin-roundtrip"
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("creating test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	allowA := mustParse(t, "198.51.100.1/32")
	allowB := mustParse(t, "2001:db8::/64")
	denyC := mustParse(t, "203.0.113.0/24")

	f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{PinDir: pinDir, MaxDNSRuleEntries: 2})
	if err != nil {
		t.Fatalf("creating pinned cgroup filter: %v", err)
	}
	if err := f.AllowIP(allowA); err != nil {
		t.Fatal(err)
	}
	if err := f.AllowIP(allowB); err != nil {
		t.Fatal(err)
	}
	if err := f.DenyIP(denyC); err != nil {
		t.Fatal(err)
	}
	if err := f.AddDNSAllowedIPs([]net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}); err != nil {
		t.Fatal(err)
	}

	cgroupHooks := map[string]ebpf.AttachType{
		"connect4": ebpf.AttachCGroupInet4Connect,
		"connect6": ebpf.AttachCGroupInet6Connect,
		"sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
		"sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
	}
	for name, hook := range cgroupHooks {
		if n := queryCgroupProgCount(t, cgroupPath, hook); n != 1 {
			t.Fatalf("expected 1 %s program after create, got %d", name, n)
		}
	}

	// Close = daemon stop (keep-enforcing): fds released, pins keep the
	// links attached.
	if err := f.Close(); err != nil {
		t.Fatalf("closing filter: %v", err)
	}
	for name, hook := range cgroupHooks {
		if n := queryCgroupProgCount(t, cgroupPath, hook); n != 1 {
			t.Fatalf("kernel must keep enforcing after Close: expected 1 %s program, got %d", name, n)
		}
	}
	for _, pin := range []string{
		pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6,
		pinDNSAllowedIPv4, pinDNSAllowedIPv6, pinPolicyMode, pinStats, pinSchemaVersion,
		pinLinkConnect4, pinLinkConnect6, pinLinkSendmsg4, pinLinkSendmsg6,
	} {
		if _, err := os.Stat(filepath.Join(pinDir, pin)); err != nil {
			t.Fatalf("pin %s missing after Close: %v", pin, err)
		}
	}

	// Simulated restart: re-adopt from pins in a brand-new filter value.
	restored, err := LoadPinnedCgroupFilter(cgroupPath, pinDir)
	if err != nil {
		t.Fatalf("re-adopting pinned filter: %v", err)
	}
	mode, err := restored.GetMode()
	if err != nil {
		t.Fatal(err)
	}
	if mode != ModeAllowlist {
		t.Fatalf("expected allowlist mode after restore, got %s", mode)
	}
	allowed, denied, err := restored.Rules()
	if err != nil {
		t.Fatal(err)
	}
	assertSameCIDRSet(t, []string{allowA.String(), allowB.String()}, allowed, "allowed rules after restore")
	assertSameCIDRSet(t, []string{denyC.String()}, denied, "denied rules after restore")
	dnsAllowed, err := restored.DNSAllowedIPs()
	if err != nil {
		t.Fatal(err)
	}
	assertSameIPSet(t, []string{"192.0.2.10", "2001:db8::10"}, dnsAllowed, "DNS exact rules after restore")
	occupancy, err := restored.DNSAllowOccupancy()
	if err != nil {
		t.Fatal(err)
	}
	if occupancy.IPv4Entries != 1 || occupancy.IPv6Entries != 1 || occupancy.IPv4Capacity != 2 || occupancy.IPv6Capacity != 2 {
		t.Fatalf("unexpected restored DNS occupancy: %+v", occupancy)
	}

	// Re-adopt must NOT have attached anything new, on ANY of the hooks.
	for name, hook := range cgroupHooks {
		if n := queryCgroupProgCount(t, cgroupPath, hook); n != 1 {
			t.Fatalf("restore must not duplicate the attachment: expected 1 %s program, got %d", name, n)
		}
	}

	// The restored filter is fully operable: mutate a rule through it.
	if err := restored.RemoveAllowedIP(allowB); err != nil {
		t.Fatalf("mutating restored filter: %v", err)
	}

	// Detach destroys everything: pins gone, kernel detached. The kernel
	// frees the unpinned links a beat after the last fd closes, so poll.
	if err := restored.Detach(); err != nil {
		t.Fatalf("detaching restored filter: %v", err)
	}
	if _, err := os.Stat(pinDir); !os.IsNotExist(err) {
		t.Fatalf("pin dir must be removed by Detach, stat err=%v", err)
	}
	for name, hook := range cgroupHooks {
		waitForZeroPrograms(t, cgroupPath, hook, name)
	}
}

// queryTCXProgCount counts programs attached to the interface's TCX egress
// hook — the ground truth for "exactly one attachment, never duplicated".
func queryTCXProgCount(t *testing.T, ifindex int) int {
	return queryTCXProgCountAt(t, ifindex, ebpf.AttachTCXEgress)
}

func queryTCXProgCountAt(t *testing.T, ifindex int, attach ebpf.AttachType) int {
	t.Helper()
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		t.Fatalf("querying TCX programs: %v", err)
	}
	return len(res.Programs)
}

// TestTCFilterPinRestoreRoundTrip is the TC twin of the cgroup round-trip.
func TestTCFilterPinRestoreRoundTrip(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-1")

	const iface = "nf-pin0"
	if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("creating dummy interface: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}

	allowA := mustParse(t, "198.51.100.1/32")
	denyB := mustParse(t, "203.0.113.0/24")

	f, err := NewTCFilterWithOptions(iface, ModeDenylist, DirectionEgress, DefaultCarveouts(), Options{PinDir: pinDir, MaxDNSRuleEntries: 1})
	if err != nil {
		t.Fatalf("creating pinned TC filter: %v", err)
	}
	if err := f.AllowIP(allowA); err != nil {
		t.Fatal(err)
	}
	if err := f.DenyIP(denyB); err != nil {
		t.Fatal(err)
	}
	if err := f.AddDNSAllowedIPs([]net.IP{net.ParseIP("192.0.2.11")}); err != nil {
		t.Fatal(err)
	}
	if n := queryTCXProgCount(t, netIface.Index); n != 1 {
		t.Fatalf("expected 1 TCX egress program after create, got %d", n)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing filter: %v", err)
	}

	// The pinned TCX link must still exist — and still be attached — after
	// Close.
	if _, err := os.Stat(filepath.Join(pinDir, pinLinkTCX)); err != nil {
		t.Fatalf("TCX link pin missing after Close: %v", err)
	}
	if n := queryTCXProgCount(t, netIface.Index); n != 1 {
		t.Fatalf("kernel must keep enforcing after Close: expected 1 TCX egress program, got %d", n)
	}

	restored, err := LoadPinnedTCFilter(iface, DirectionEgress, pinDir)
	if err != nil {
		t.Fatalf("re-adopting pinned TC filter: %v", err)
	}
	mode, err := restored.GetMode()
	if err != nil {
		t.Fatal(err)
	}
	if mode != ModeDenylist {
		t.Fatalf("expected denylist mode after restore, got %s", mode)
	}
	allowed, denied, err := restored.Rules()
	if err != nil {
		t.Fatal(err)
	}
	assertSameCIDRSet(t, []string{allowA.String()}, allowed, "allowed rules after restore")
	assertSameCIDRSet(t, []string{denyB.String()}, denied, "denied rules after restore")
	dnsAllowed, err := restored.DNSAllowedIPs()
	if err != nil {
		t.Fatal(err)
	}
	assertSameIPSet(t, []string{"192.0.2.11"}, dnsAllowed, "TC DNS exact rules after restore")

	// Re-adopt must NOT have attached a second TCX program.
	if n := queryTCXProgCount(t, netIface.Index); n != 1 {
		t.Fatalf("restore must not duplicate the attachment: expected 1 TCX egress program, got %d", n)
	}

	if err := restored.Detach(); err != nil {
		t.Fatalf("detaching restored TC filter: %v", err)
	}
	if _, err := os.Stat(pinDir); !os.IsNotExist(err) {
		t.Fatalf("pin dir must be removed by Detach, stat err=%v", err)
	}
	// Kernel link teardown is deferred past the last fd close, so poll.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n := queryTCXProgCount(t, netIface.Index); n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Detach must remove the TCX attachment: still %d programs", queryTCXProgCount(t, netIface.Index))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCgroupPinnedLinkReincarnationRejected: a bpf_link binds to the cgroup
// OBJECT, not the path. If the cgroup is destroyed and recreated at the same
// path while the daemon is down, the pinned link is defunct (attached to the
// dead cgroup) even though it still loads and its maps still read. Adopting
// it would leave the RECREATED cgroup completely unfiltered while claiming
// enforcement — LoadPinnedCgroupFilter must refuse.
func TestCgroupPinnedLinkReincarnationRejected(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-1")

	cgroupPath := "/sys/fs/cgroup/netfence-pin-reincarnation"
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("creating test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{PinDir: pinDir})
	if err != nil {
		t.Fatalf("creating pinned cgroup filter: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	// Destroy and recreate the cgroup at the SAME path (a routine container
	// restart does exactly this).
	if err := os.Remove(cgroupPath); err != nil {
		t.Fatalf("removing cgroup: %v", err)
	}
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("recreating cgroup: %v", err)
	}

	restored, err := LoadPinnedCgroupFilter(cgroupPath, pinDir)
	if err == nil {
		_ = restored.Detach()
		n := queryCgroupProgCount(t, cgroupPath, ebpf.AttachCGroupInet4Connect)
		t.Fatalf("LoadPinnedCgroupFilter adopted a defunct link for a recreated cgroup (err=nil, connect4 programs on RECREATED cgroup=%d) — the recreated cgroup is unfiltered while the daemon believes it is enforcing", n)
	}
	if !errors.Is(err, ErrPinnedTargetMismatch) {
		t.Fatalf("expected typed pinned-target mismatch, got %v", err)
	}
	t.Logf("correctly refused defunct link: %v", err)
}

// TestTCPinnedLinkReincarnationWithLostIdentityIsPreserved is the TC twin.
// Once the old interface disappears this kernel reports ifindex zero, which
// is not enough evidence to authorize destructive replacement; preserve the
// unknown live pin set as schema-incompatible.
func TestTCPinnedLinkReincarnationWithLostIdentityIsPreserved(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-1")

	const iface = "nf-pinre0"
	if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("creating dummy interface: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })

	f, err := NewTCFilterWithOptions(iface, ModeAllowlist, DirectionEgress, DefaultCarveouts(), Options{PinDir: pinDir})
	if err != nil {
		t.Fatalf("creating pinned TC filter: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	// Destroy and recreate the interface under the SAME name.
	if out, err := exec.Command("ip", "link", "del", iface).CombinedOutput(); err != nil {
		t.Fatalf("deleting interface: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("recreating interface: %v: %s", err, out)
	}

	restored, err := LoadPinnedTCFilter(iface, DirectionEgress, pinDir)
	if err == nil {
		_ = restored.Detach()
		t.Fatal("LoadPinnedTCFilter adopted a defunct TCX link for a recreated interface — the recreated interface is unfiltered while the daemon believes it is enforcing")
	}
	if !errors.Is(err, ErrPinnedSchemaIncompatible) {
		t.Fatalf("expected non-discardable unavailable-target identity, got %v", err)
	}
	t.Logf("correctly preserved link with unavailable old target identity: %v", err)
}

// TestPinCollisionOnCreateIsNonDestructiveAndPrecedesAttach proves an
// existing pin path is never cleared or transiently stacked with a new
// program. Only validated daemon cleanup may remove old persistent state.
func TestPinCollisionOnCreateIsNonDestructiveAndPrecedesAttach(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-1")

	cgroupPath := "/sys/fs/cgroup/netfence-pin-collision"
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("creating test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	// Stand-in for viable state owned by another lifecycle. bpffs doesn't
	// support ordinary files, but an existing directory is sufficient to prove
	// the colliding tree survives untouched.
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(pinDir, "must-survive")
	if err := os.Mkdir(sentinel, 0o700); err != nil {
		t.Fatal(err)
	}

	f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{PinDir: pinDir})
	if err == nil || f != nil {
		if f != nil {
			_ = f.Detach()
		}
		t.Fatalf("colliding create must fail before attach, got filter=%v err=%v", f, err)
	}
	if info, err := os.Stat(sentinel); err != nil || !info.IsDir() {
		t.Fatalf("colliding directory was modified: info=%v err=%v", info, err)
	}
	for name, attach := range map[string]ebpf.AttachType{
		"connect4": ebpf.AttachCGroupInet4Connect,
		"connect6": ebpf.AttachCGroupInet6Connect,
		"sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
		"sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
	} {
		if n := queryCgroupProgCount(t, cgroupPath, attach); n != 0 {
			t.Fatalf("collision must be detected before %s attach, got %d programs", name, n)
		}
	}
}

func TestInspectPinnedSchemaCurrentMissingMapIsNonDiscardable(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-current-missing")
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-inspect-%d", os.Getpid())
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{PinDir: pinDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(pinDir, pinDNSAllowedIPv4)); err != nil {
		t.Fatal(err)
	}

	state, err := InspectPinnedSchema(pinDir)
	if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
		t.Fatalf("current marker plus missing map must be preserved as incompatible, state=%v err=%v", state, err)
	}
	if n := queryCgroupProgCount(t, cgroupPath, ebpf.AttachCGroupInet4Connect); n != 1 {
		t.Fatalf("inspection failure changed enforcement attachment count: %d", n)
	}
}

func TestLegacyCgroupMismatchedPinnedMapIsPreservedWithoutUpdate(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-legacy-mismatch")
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-mismatch-%d", os.Getpid())
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	createLegacyCgroupPinSet(t, cgroupPath, pinDir, ModeAllowlist, mustParse(t, "198.51.100.7/32"))
	beforeNames := pinDirectoryNames(t, pinDir)
	beforeProgram := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkConnect4))

	other := loadLegacyCollection(t, "legacy_cgroup")
	defer other.Close()
	if err := os.Remove(filepath.Join(pinDir, pinAllowedIPv4)); err != nil {
		t.Fatal(err)
	}
	if err := other.Maps[pinAllowedIPv4].Pin(filepath.Join(pinDir, pinAllowedIPv4)); err != nil {
		t.Fatal(err)
	}

	updates := 0
	carveouts := DefaultCarveouts()
	f, err := loadPinnedCgroupFilter(cgroupPath, pinDir, &carveouts, Options{}, pinMigrationOps{
		updateLink: func(link.Link, *ebpf.Program) error {
			updates++
			return nil
		},
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("mismatched legacy maps must not be adopted: filter=%v err=%v", f, err)
	}
	if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
		t.Fatalf("expected non-discardable map identity error, got %v", err)
	}
	if updates != 0 {
		t.Fatalf("migration updated %d links before proving legacy map identity", updates)
	}
	if got := pinDirectoryNames(t, pinDir); fmt.Sprint(got) != fmt.Sprint(beforeNames) {
		t.Fatalf("mismatched legacy pin set was modified: before=%v after=%v", beforeNames, got)
	}
	if got := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkConnect4)); got != beforeProgram {
		t.Fatalf("legacy link program changed despite map mismatch: before=%d after=%d", beforeProgram, got)
	}
	if n := queryCgroupProgCount(t, cgroupPath, ebpf.AttachCGroupInet4Connect); n != 1 {
		t.Fatalf("legacy enforcement attachment was not preserved: %d", n)
	}
}

func TestLegacyTCMismatchedPinnedMapIsPreservedWithoutUpdate(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-legacy-tc-mismatch")
	const iface = "nf-pmm0"
	if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("creating dummy interface: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
	createLegacyTCPinSet(t, iface, pinDir, ModeAllowlist, mustParse(t, "198.51.100.8/32"))
	beforeNames := pinDirectoryNames(t, pinDir)
	beforeProgram := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkTCX))

	other := loadLegacyCollection(t, "legacy_tc")
	defer other.Close()
	if err := os.Remove(filepath.Join(pinDir, pinAllowedIPv4)); err != nil {
		t.Fatal(err)
	}
	if err := other.Maps[pinAllowedIPv4].Pin(filepath.Join(pinDir, pinAllowedIPv4)); err != nil {
		t.Fatal(err)
	}

	updates := 0
	carveouts := DefaultCarveouts()
	f, err := loadPinnedTCFilter(iface, DirectionEgress, pinDir, &carveouts, Options{}, pinMigrationOps{
		updateLink: func(link.Link, *ebpf.Program) error {
			updates++
			return nil
		},
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("mismatched legacy TC maps must not be adopted: filter=%v err=%v", f, err)
	}
	if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
		t.Fatalf("expected non-discardable TC map identity error, got %v", err)
	}
	if updates != 0 {
		t.Fatalf("TC migration updated %d links before proving legacy map identity", updates)
	}
	if got := pinDirectoryNames(t, pinDir); fmt.Sprint(got) != fmt.Sprint(beforeNames) {
		t.Fatalf("mismatched legacy TC pin set was modified: before=%v after=%v", beforeNames, got)
	}
	if got := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkTCX)); got != beforeProgram {
		t.Fatalf("legacy TCX program changed despite map mismatch: before=%d after=%d", beforeProgram, got)
	}
}

func TestLegacyTCMapIncompatibilityOutranksTargetMismatch(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "legacy-tc-priority")
	const ifaceA, ifaceB = "nf-ptpa", "nf-ptpb"
	for _, iface := range []string{ifaceA, ifaceB} {
		if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
			t.Fatalf("creating dummy interface %s: %v: %s", iface, err, out)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", ifaceA).Run()
		_ = exec.Command("ip", "link", "del", ifaceB).Run()
	})
	createLegacyTCPinSet(t, ifaceA, pinDir, ModeAllowlist, mustParse(t, "198.51.100.74/32"))
	other := loadLegacyCollection(t, "legacy_tc")
	defer other.Close()
	if err := os.Remove(filepath.Join(pinDir, pinAllowedIPv4)); err != nil {
		t.Fatal(err)
	}
	if err := other.Maps[pinAllowedIPv4].Pin(filepath.Join(pinDir, pinAllowedIPv4)); err != nil {
		t.Fatal(err)
	}
	before := pinDirectoryNames(t, pinDir)
	updates := 0
	carveouts := DefaultCarveouts()
	f, err := loadPinnedTCFilter(ifaceB, DirectionEgress, pinDir, &carveouts, Options{}, pinMigrationOps{
		updateLink: func(link.Link, *ebpf.Program) error { updates++; return nil },
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("mismatched-map/target TC directory returned filter: %v", f)
	}
	if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) || errors.Is(err, ErrPinnedTargetMismatch) {
		t.Fatalf("TC map incompatibility must outrank discardable target mismatch, got %v", err)
	}
	if updates != 0 {
		t.Fatalf("TC incompatible map/target triggered %d updates", updates)
	}
	if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("TC priority rejection modified pins: before=%v after=%v", before, after)
	}
}

func TestLegacyExtraPinnedObjectIsPreservedWithoutMigration(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "legacy-extra")
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-extra-%d", os.Getpid())
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(pinDir)
		_ = os.Remove(cgroupPath)
	})
	createLegacyCgroupPinSet(t, cgroupPath, pinDir, ModeAllowlist, mustParse(t, "198.51.100.75/32"))
	extra := loadLegacyCollection(t, "legacy_cgroup")
	defer extra.Close()
	if err := extra.Maps[pinPolicyMode].Pin(filepath.Join(pinDir, "unexpected_live_object")); err != nil {
		t.Fatal(err)
	}
	before := pinDirectoryNames(t, pinDir)
	updates := 0
	carveouts := DefaultCarveouts()
	f, err := loadPinnedCgroupFilter(cgroupPath, pinDir, &carveouts, Options{}, pinMigrationOps{
		updateLink: func(link.Link, *ebpf.Program) error { updates++; return nil },
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("legacy directory with extra object returned filter: %v", f)
	}
	if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
		t.Fatalf("extra pinned object must be non-discardable, got %v", err)
	}
	if updates != 0 {
		t.Fatalf("extra pinned object triggered %d migration updates", updates)
	}
	if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("extra-object rejection modified pins: before=%v after=%v", before, after)
	}
	if n := queryCgroupProgCount(t, cgroupPath, ebpf.AttachCGroupInet4Connect); n != 1 {
		t.Fatalf("extra-object rejection changed live enforcement: %d programs", n)
	}
}

func TestLegacyCgroupMixedLinkTargetsAreNonDiscardable(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "legacy-mixed-targets")
	cgroupA := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-mix-a-%d", os.Getpid())
	cgroupB := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-mix-b-%d", os.Getpid())
	for _, path := range []string{cgroupA, cgroupB} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(pinDir)
		_ = os.Remove(cgroupA)
		_ = os.Remove(cgroupB)
	})
	createLegacyCgroupPinSet(t, cgroupA, pinDir, ModeAllowlist, mustParse(t, "198.51.100.76/32"))

	replacements := make(map[string]*ebpf.Map)
	for _, name := range []string{pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6, pinPolicyMode, pinStats} {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		replacements[name] = m
	}
	spec := loadLegacyCollectionSpec(t, "legacy_cgroup", nil)
	mixedCollection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		t.Fatal(err)
	}
	defer mixedCollection.Close()
	mixedLink, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupB, Program: mixedCollection.Programs["restrict_connect6"], Attach: ebpf.AttachCGroupInet6Connect,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mixedLink.Close()
	if err := os.Remove(filepath.Join(pinDir, pinLinkConnect6)); err != nil {
		t.Fatal(err)
	}
	if err := mixedLink.Pin(filepath.Join(pinDir, pinLinkConnect6)); err != nil {
		t.Fatal(err)
	}
	before := pinDirectoryNames(t, pinDir)
	updates := 0
	carveouts := DefaultCarveouts()
	f, err := loadPinnedCgroupFilter(cgroupA, pinDir, &carveouts, Options{}, pinMigrationOps{
		updateLink: func(link.Link, *ebpf.Program) error { updates++; return nil },
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("mixed-target cgroup directory returned filter: %v", f)
	}
	if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) || errors.Is(err, ErrPinnedTargetMismatch) {
		t.Fatalf("mixed old cgroup targets must outrank discardable mismatch, got %v", err)
	}
	if updates != 0 {
		t.Fatalf("mixed old cgroup targets triggered %d updates", updates)
	}
	if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("mixed-target rejection modified pins: before=%v after=%v", before, after)
	}
	if n := queryCgroupProgCount(t, cgroupA, ebpf.AttachCGroupInet4Connect); n != 1 {
		t.Fatalf("mixed-target rejection lost cgroup A enforcement: %d", n)
	}
	if n := queryCgroupProgCount(t, cgroupB, ebpf.AttachCGroupInet6Connect); n != 1 {
		t.Fatalf("mixed-target rejection lost cgroup B enforcement: %d", n)
	}
}

func TestLegacyMissingRequiredObjectsArePreservedWithoutMigration(t *testing.T) {
	cgroupObjects := []struct {
		name   string
		attach ebpf.AttachType
	}{
		{pinAllowedIPv4, 0}, {pinAllowedIPv6, 0}, {pinDeniedIPv4, 0},
		{pinDeniedIPv6, 0}, {pinPolicyMode, 0}, {pinStats, 0},
		{pinLinkConnect4, ebpf.AttachCGroupInet4Connect},
		{pinLinkConnect6, ebpf.AttachCGroupInet6Connect},
		{pinLinkSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{pinLinkSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	for i, missing := range cgroupObjects {
		t.Run("cgroup_"+missing.name, func(t *testing.T) {
			root := pinTestRoot(t)
			pinDir := filepath.Join(root, "legacy-missing")
			cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-missing-%d-%d", os.Getpid(), i)
			if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(pinDir)
				_ = os.Remove(cgroupPath)
			})
			createLegacyCgroupPinSet(t, cgroupPath, pinDir, ModeAllowlist, mustParse(t, "198.51.100.80/32"))
			var held link.Link
			if missing.attach != 0 {
				var err error
				held, err = link.LoadPinnedLink(filepath.Join(pinDir, missing.name), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			}
			if err := os.Remove(filepath.Join(pinDir, missing.name)); err != nil {
				t.Fatal(err)
			}
			before := pinDirectoryNames(t, pinDir)
			updates := 0
			carveouts := DefaultCarveouts()
			f, err := loadPinnedCgroupFilter(cgroupPath, pinDir, &carveouts, Options{}, pinMigrationOps{
				updateLink: func(link.Link, *ebpf.Program) error { updates++; return nil },
			})
			if f != nil {
				_ = f.Close()
				t.Fatalf("missing legacy object returned filter: %v", f)
			}
			if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
				t.Fatalf("missing legacy %s must be non-discardable, got %v", missing.name, err)
			}
			if updates != 0 {
				t.Fatalf("missing legacy %s triggered %d updates", missing.name, updates)
			}
			if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatalf("missing legacy %s load modified remaining pins: before=%v after=%v", missing.name, before, after)
			}
			attach := missing.attach
			if attach == 0 {
				attach = ebpf.AttachCGroupInet4Connect
			}
			if n := queryCgroupProgCount(t, cgroupPath, attach); n != 1 {
				t.Fatalf("missing legacy %s did not retain live enforcement: %d programs", missing.name, n)
			}
		})
	}

	for i, missing := range []string{
		pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6,
		pinPolicyMode, pinStats, pinLinkTCX,
	} {
		t.Run("tc_"+missing, func(t *testing.T) {
			root := pinTestRoot(t)
			pinDir := filepath.Join(root, "legacy-missing")
			iface := fmt.Sprintf("nf-pmo%02d", i)
			if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
				t.Fatalf("creating dummy interface: %v: %s", err, out)
			}
			t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
			createLegacyTCPinSet(t, iface, pinDir, ModeAllowlist, mustParse(t, "198.51.100.81/32"))
			var held link.Link
			if missing == pinLinkTCX {
				var err error
				held, err = link.LoadPinnedLink(filepath.Join(pinDir, missing), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			}
			if err := os.Remove(filepath.Join(pinDir, missing)); err != nil {
				t.Fatal(err)
			}
			before := pinDirectoryNames(t, pinDir)
			updates := 0
			carveouts := DefaultCarveouts()
			f, err := loadPinnedTCFilter(iface, DirectionEgress, pinDir, &carveouts, Options{}, pinMigrationOps{
				updateLink: func(link.Link, *ebpf.Program) error { updates++; return nil },
			})
			if f != nil {
				_ = f.Close()
				t.Fatalf("missing legacy TC object returned filter: %v", f)
			}
			if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
				t.Fatalf("missing legacy TC %s must be non-discardable, got %v", missing, err)
			}
			if updates != 0 {
				t.Fatalf("missing legacy TC %s triggered %d updates", missing, updates)
			}
			if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatalf("missing legacy TC %s load modified remaining pins: before=%v after=%v", missing, before, after)
			}
			netIface, err := net.InterfaceByName(iface)
			if err != nil {
				t.Fatal(err)
			}
			if n := queryTCXProgCount(t, netIface.Index); n != 1 {
				t.Fatalf("missing legacy TC %s did not retain live enforcement: %d programs", missing, n)
			}
		})
	}
}

func TestLegacyCgroupMigrationAmbiguousUpdateConvergesWithoutEnforcementGap(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-legacy-migrate")
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-migrate-%d", os.Getpid())
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(pinDir)
		_ = os.Remove(cgroupPath)
	})

	// Own the reachable non-carveout route outright so package-parallel Linux
	// gates cannot race interface enumeration or borrow another test's address.
	const allowedIface, allowedAddress = "nfpcgm0", "198.18.255.250"
	_ = exec.Command("ip", "link", "del", allowedIface).Run()
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", allowedIface).Run() })
	pinTestIPCommand(t, "link", "add", allowedIface, "type", "dummy")
	pinTestIPCommand(t, "addr", "add", allowedAddress+"/32", "dev", allowedIface)
	pinTestIPCommand(t, "link", "set", allowedIface, "up")
	allowedIP := net.ParseIP(allowedAddress)
	legacyAllow := mustParse(t, allowedIP.String()+"/32")
	carveouts := DefaultCarveouts()
	carveouts.LocalhostV4 = false // deliberate historical non-default posture
	createLegacyCgroupPinSetWithCarveouts(t, cgroupPath, pinDir, ModeAllowlist, legacyAllow, carveouts)
	allowedListener := listenPinTestTCP(t, allowedIP)
	blockedListener := listenPinTestTCP(t, net.IPv4(127, 0, 0, 1))
	probe, err := net.DialTimeout("tcp4", blockedListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("localhost probe topology is unavailable outside the cgroup: %v", err)
	}
	_ = probe.Close()
	if !dialFromPinnedTestCgroup(cgroupPath, allowedListener.Addr().String()) {
		t.Fatal("genuine legacy program did not admit its reachable authoritative LPM destination")
	}
	if dialFromPinnedTestCgroup(cgroupPath, blockedListener.Addr().String()) {
		t.Fatal("genuine legacy program did not enforce the non-default disabled localhost-v4 carve-out")
	}

	updateCalls := 0
	f, err := loadPinnedCgroupFilter(cgroupPath, pinDir, &carveouts, Options{MaxDNSRuleEntries: 2}, pinMigrationOps{
		updateLink: func(l link.Link, p *ebpf.Program) error {
			updateCalls++
			if err := l.Update(p); err != nil {
				return err
			}
			if updateCalls == 2 {
				return unix.EIO // the kernel update happened; its result was ambiguous
			}
			return nil
		},
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("ambiguous migration must not return an adopted filter: %v", f)
	}
	if err == nil || !errors.Is(err, unix.EIO) {
		t.Fatalf("expected injected ambiguous update error, got %v", err)
	}
	if updateCalls != 2 {
		t.Fatalf("expected failure after two real link updates, got %d", updateCalls)
	}
	if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != 0 {
		t.Fatalf("partial migration must retain durable in-progress marker, present=%t version=%d", present, version)
	}
	for _, name := range []string{pinDNSAllowedIPv4, pinDNSAllowedIPv6, pinSchemaVersion} {
		if _, err := os.Stat(filepath.Join(pinDir, name)); err != nil {
			t.Fatalf("partial migration lost restart-convergence pin %s: %v", name, err)
		}
	}
	for name, attach := range map[string]ebpf.AttachType{
		"connect4": ebpf.AttachCGroupInet4Connect,
		"connect6": ebpf.AttachCGroupInet6Connect,
		"sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
		"sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
	} {
		if n := queryCgroupProgCount(t, cgroupPath, attach); n != 1 {
			t.Fatalf("partial migration changed %s attachment cardinality: %d", name, n)
		}
	}
	if !dialFromPinnedTestCgroup(cgroupPath, allowedListener.Addr().String()) {
		t.Fatal("authoritative LPM allow was overblocked after ambiguous partial migration")
	}
	if dialFromPinnedTestCgroup(cgroupPath, blockedListener.Addr().String()) {
		t.Fatal("non-default localhost-v4 posture loosened after ambiguous partial migration")
	}

	restored, err := LoadPinnedCgroupFilterWithOptions(cgroupPath, pinDir, carveouts, Options{MaxDNSRuleEntries: 2})
	if err != nil {
		t.Fatalf("retry did not converge genuine partial migration: %v", err)
	}
	if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != currentPinSchemaVersion {
		t.Fatalf("retry did not commit current schema, present=%t version=%d", present, version)
	}
	allowed, _, err := restored.Rules()
	if err != nil {
		t.Fatal(err)
	}
	assertSameCIDRSet(t, []string{legacyAllow.String()}, allowed, "legacy cgroup rules after migration retry")
	if err := restored.AddDNSAllowedIPs([]net.IP{net.ParseIP("192.0.2.30")}); err != nil {
		t.Fatalf("migrated exact map is not operable: %v", err)
	}
	occupancy, err := restored.DNSAllowOccupancy()
	if err != nil {
		t.Fatal(err)
	}
	if occupancy.IPv4Entries != 1 || occupancy.IPv4Capacity != 2 || occupancy.IPv6Capacity != 2 {
		t.Fatalf("unexpected migrated exact-map occupancy: %+v", occupancy)
	}
	if !dialFromPinnedTestCgroup(cgroupPath, allowedListener.Addr().String()) {
		t.Fatal("authoritative LPM allow was overblocked after migration convergence")
	}
	if dialFromPinnedTestCgroup(cgroupPath, blockedListener.Addr().String()) {
		t.Fatal("non-default localhost-v4 posture loosened after migration convergence")
	}
	if err := restored.Detach(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyTCMigrationAmbiguousUpdateConverges(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-legacy-tc-migrate")
	iface, namespace, allowedIP, blockedIP := setupPinTestTCNetns(t)
	allowedListener := listenPinTestTCP(t, net.ParseIP(allowedIP))
	blockedListener := listenPinTestTCP(t, net.ParseIP(blockedIP))
	_, allowedPort, err := net.SplitHostPort(allowedListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, blockedPort, err := net.SplitHostPort(blockedListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	legacyAllow := mustParse(t, allowedIP+"/32")
	createLegacyTCPinSetDirection(t, iface, pinDir, ModeAllowlist, legacyAllow, DirectionIngress)
	if netIface, err := net.InterfaceByName(iface); err != nil {
		t.Fatal(err)
	} else if n := queryTCXProgCountAt(t, netIface.Index, ebpf.AttachTCXIngress); n != 1 {
		t.Fatalf("expected one genuine legacy TCX program, got %d", n)
	}
	if !dialFromPinTestNetns(namespace, allowedIP, allowedPort) {
		t.Fatal("genuine legacy TC program overblocked its reachable authoritative allow")
	}
	if dialFromPinTestNetns(namespace, blockedIP, blockedPort) {
		t.Fatal("genuine legacy TC program admitted unrelated allowlist traffic")
	}

	carveouts := DefaultCarveouts()
	updateCalls := 0
	f, err := loadPinnedTCFilter(iface, DirectionIngress, pinDir, &carveouts, Options{MaxDNSRuleEntries: 2}, pinMigrationOps{
		updateLink: func(l link.Link, p *ebpf.Program) error {
			updateCalls++
			if err := l.Update(p); err != nil {
				return err
			}
			return unix.EIO // update applied, result ambiguous
		},
	})
	if f != nil {
		_ = f.Close()
		t.Fatalf("ambiguous TC migration must not return an adopted filter: %v", f)
	}
	if err == nil || !errors.Is(err, unix.EIO) || updateCalls != 1 {
		t.Fatalf("expected one ambiguous applied TC update, calls=%d err=%v", updateCalls, err)
	}
	if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != 0 {
		t.Fatalf("partial TC migration must retain in-progress marker, present=%t version=%d", present, version)
	}
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	if n := queryTCXProgCountAt(t, netIface.Index, ebpf.AttachTCXIngress); n != 1 {
		t.Fatalf("ambiguous TC migration changed attachment cardinality: %d", n)
	}
	if !dialFromPinTestNetns(namespace, allowedIP, allowedPort) {
		t.Fatal("ambiguous applied TC migration overblocked its authoritative allow")
	}
	if dialFromPinTestNetns(namespace, blockedIP, blockedPort) {
		t.Fatal("ambiguous applied TC migration opened unrelated traffic")
	}

	restored, err := LoadPinnedTCFilterWithOptions(iface, DirectionIngress, pinDir, carveouts, Options{MaxDNSRuleEntries: 2})
	if err != nil {
		t.Fatalf("retry did not converge genuine TC migration: %v", err)
	}
	if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != currentPinSchemaVersion {
		t.Fatalf("retry did not commit current TC schema, present=%t version=%d", present, version)
	}
	allowed, _, err := restored.Rules()
	if err != nil {
		t.Fatal(err)
	}
	assertSameCIDRSet(t, []string{legacyAllow.String()}, allowed, "legacy TC rules after migration retry")
	if !dialFromPinTestNetns(namespace, allowedIP, allowedPort) {
		t.Fatal("converged TC migration overblocked its authoritative allow")
	}
	if dialFromPinTestNetns(namespace, blockedIP, blockedPort) {
		t.Fatal("converged TC migration opened unrelated traffic")
	}
	if err := restored.AddDNSAllowedIPs([]net.IP{net.ParseIP("192.0.2.31")}); err != nil {
		t.Fatal(err)
	}
	if err := restored.Detach(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMigrationMapPinCrashPointsConvergeBeforeLinkUpdates(t *testing.T) {
	tests := []struct {
		name           string
		failName       string
		applyThenError bool
		wantExact4     bool
		wantExact6     bool
		wantMarker     bool
	}{
		{name: "before_ipv4_exact_pin", failName: pinDNSAllowedIPv4},
		{name: "ipv4_exact_pin_applied_then_eio", failName: pinDNSAllowedIPv4, applyThenError: true, wantExact4: true},
		{name: "before_ipv6_exact_pin", failName: pinDNSAllowedIPv6, wantExact4: true},
		{name: "ipv6_exact_pin_applied_then_eio", failName: pinDNSAllowedIPv6, applyThenError: true, wantExact4: true, wantExact6: true},
		{name: "before_marker_pin", failName: pinSchemaVersion, wantExact4: true, wantExact6: true},
		{name: "marker_pin_applied_then_eio", failName: pinSchemaVersion, applyThenError: true, wantExact4: true, wantExact6: true, wantMarker: true},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := pinTestRoot(t)
			pinDir := filepath.Join(root, "att-legacy-pin-crash")
			cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-crash-%d-%d", os.Getpid(), i)
			if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(pinDir)
				_ = os.Remove(cgroupPath)
			})
			createLegacyCgroupPinSet(t, cgroupPath, pinDir, ModeAllowlist, mustParse(t, "198.51.100.50/32"))

			updates := 0
			carveouts := DefaultCarveouts()
			f, err := loadPinnedCgroupFilter(cgroupPath, pinDir, &carveouts, Options{MaxDNSRuleEntries: 2}, pinMigrationOps{
				pinObject: func(obj pinner, path string) error {
					if filepath.Base(path) != tt.failName {
						return obj.Pin(path)
					}
					if tt.applyThenError {
						if err := obj.Pin(path); err != nil {
							return err
						}
					}
					return unix.EIO
				},
				updateLink: func(link.Link, *ebpf.Program) error {
					updates++
					return nil
				},
			})
			if f != nil {
				_ = f.Close()
				t.Fatalf("pin failure returned an adopted filter: %v", f)
			}
			if err == nil || !errors.Is(err, unix.EIO) {
				t.Fatalf("expected injected pin EIO, got %v", err)
			}
			if updates != 0 {
				t.Fatalf("pin crash point updated %d links", updates)
			}
			for name, want := range map[string]bool{
				pinDNSAllowedIPv4: tt.wantExact4,
				pinDNSAllowedIPv6: tt.wantExact6,
				pinSchemaVersion:  tt.wantMarker,
			} {
				_, statErr := os.Stat(filepath.Join(pinDir, name))
				if got := statErr == nil; got != want {
					t.Fatalf("pin %s presence=%t, want %t (stat err=%v)", name, got, want, statErr)
				}
			}
			if tt.wantMarker {
				if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != 0 {
					t.Fatalf("applied-then-error marker must remain in progress, present=%t version=%d", present, version)
				}
			}
			if state, inspectErr := InspectPinnedSchema(pinDir); inspectErr != nil || state != PinnedSchemaUncommitted {
				t.Fatalf("pin crash point must classify as preserved/uncommitted, state=%v err=%v", state, inspectErr)
			}
			if n := queryCgroupProgCount(t, cgroupPath, ebpf.AttachCGroupInet4Connect); n != 1 {
				t.Fatalf("pre-update pin failure changed enforcement attachment count: %d", n)
			}

			restored, err := LoadPinnedCgroupFilterWithOptions(cgroupPath, pinDir, carveouts, Options{MaxDNSRuleEntries: 2})
			if err != nil {
				t.Fatalf("retry did not converge pin crash point: %v", err)
			}
			if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != currentPinSchemaVersion {
				t.Fatalf("retry did not commit schema, present=%t version=%d", present, version)
			}
			if err := restored.Detach(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyCgroupMigrationCommitWriteAmbiguityConverges(t *testing.T) {
	for i, applied := range []bool{false, true} {
		name := "before_commit_write"
		if applied {
			name = "commit_write_applied_then_eio"
		}
		t.Run(name, func(t *testing.T) {
			root := pinTestRoot(t)
			pinDir := filepath.Join(root, "att-legacy-commit")
			cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-commit-%d-%d", os.Getpid(), i)
			if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.RemoveAll(pinDir)
				_ = os.Remove(cgroupPath)
			})
			legacyAllow := mustParse(t, "198.51.100.61/32")
			createLegacyCgroupPinSet(t, cgroupPath, pinDir, ModeAllowlist, legacyAllow)
			carveouts := DefaultCarveouts()
			writes := 0
			f, err := loadPinnedCgroupFilter(cgroupPath, pinDir, &carveouts, Options{MaxDNSRuleEntries: 2}, pinMigrationOps{
				writeSchema: func(m *ebpf.Map, version uint32) error {
					writes++
					if version != currentPinSchemaVersion {
						return writePinSchemaVersion(m, version)
					}
					if applied {
						if err := writePinSchemaVersion(m, version); err != nil {
							return err
						}
					}
					return unix.EIO
				},
			})
			if f != nil {
				_ = f.Close()
				t.Fatalf("ambiguous commit returned adopted filter: %v", f)
			}
			if err == nil || !errors.Is(err, unix.EIO) || writes != 2 {
				t.Fatalf("expected two schema writes ending in EIO, writes=%d err=%v", writes, err)
			}
			wantVersion := uint32(0)
			if applied {
				wantVersion = currentPinSchemaVersion
			}
			if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != wantVersion {
				t.Fatalf("commit ambiguity marker present=%t version=%d, want %d", present, version, wantVersion)
			}
			for name, attach := range map[string]ebpf.AttachType{
				"connect4": ebpf.AttachCGroupInet4Connect,
				"connect6": ebpf.AttachCGroupInet6Connect,
				"sendmsg4": ebpf.AttachCGroupUDP4Sendmsg,
				"sendmsg6": ebpf.AttachCGroupUDP6Sendmsg,
			} {
				if n := queryCgroupProgCount(t, cgroupPath, attach); n != 1 {
					t.Fatalf("commit ambiguity changed %s attachment count: %d", name, n)
				}
			}
			restored, err := LoadPinnedCgroupFilterWithOptions(cgroupPath, pinDir, carveouts, Options{MaxDNSRuleEntries: 2})
			if err != nil {
				t.Fatalf("retry did not converge commit ambiguity: %v", err)
			}
			allowed, _, err := restored.Rules()
			if err != nil {
				t.Fatal(err)
			}
			assertSameCIDRSet(t, []string{legacyAllow.String()}, allowed, "rules after commit ambiguity retry")
			if version, present := readPinnedSchemaForTest(t, pinDir); !present || version != currentPinSchemaVersion {
				t.Fatalf("retry did not leave current marker, present=%t version=%d", present, version)
			}
			if err := restored.Detach(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFutureSchemaMarkerAbortsBeforeVersionSpecificLoads(t *testing.T) {
	root := pinTestRoot(t)
	for _, surface := range []string{"cgroup", "tc"} {
		t.Run(surface, func(t *testing.T) {
			pinDir := filepath.Join(root, "future-"+surface)
			if err := claimPinDir(pinDir); err != nil {
				t.Fatal(err)
			}
			marker, err := ebpf.NewMap(&ebpf.MapSpec{Name: pinSchemaVersion, Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer marker.Close()
			future := currentPinSchemaVersion + 1
			if err := writePinSchemaVersion(marker, future); err != nil {
				t.Fatal(err)
			}
			if err := marker.Pin(filepath.Join(pinDir, pinSchemaVersion)); err != nil {
				t.Fatal(err)
			}
			before := pinDirectoryNames(t, pinDir)
			carveouts := DefaultCarveouts()
			updates := 0
			ops := pinMigrationOps{updateLink: func(link.Link, *ebpf.Program) error { updates++; return nil }}
			if surface == "cgroup" {
				got, loadErr := loadPinnedCgroupFilter("/sys/fs/cgroup", pinDir, &carveouts, Options{}, ops)
				err = loadErr
				if got != nil {
					_ = got.Close()
					t.Fatalf("future schema returned cgroup filter: %v", got)
				}
			} else {
				got, loadErr := loadPinnedTCFilter("does-not-need-to-exist", DirectionEgress, pinDir, &carveouts, Options{}, ops)
				err = loadErr
				if got != nil {
					_ = got.Close()
					t.Fatalf("future schema returned TC filter: %v", got)
				}
			}
			if err == nil || !errors.Is(err, ErrPinnedSchemaIncompatible) {
				t.Fatalf("future schema must be non-discardable, got %v", err)
			}
			if updates != 0 {
				t.Fatalf("future schema attempted %d link updates", updates)
			}
			if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatalf("future schema inspection modified pins: before=%v after=%v", before, after)
			}
		})
	}
}

func TestPublicLegacyLoadRequiresExplicitOriginalCarveouts(t *testing.T) {
	t.Run("cgroup", func(t *testing.T) {
		root := pinTestRoot(t)
		pinDir := filepath.Join(root, "legacy-public-cgroup")
		cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-pin-public-%d", os.Getpid())
		if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.RemoveAll(pinDir)
			_ = os.Remove(cgroupPath)
		})
		createLegacyCgroupPinSet(t, cgroupPath, pinDir, ModeAllowlist, mustParse(t, "198.51.100.70/32"))
		beforeNames := pinDirectoryNames(t, pinDir)
		beforePrograms := map[string]ebpf.ProgramID{}
		for _, name := range []string{pinLinkConnect4, pinLinkConnect6, pinLinkSendmsg4, pinLinkSendmsg6} {
			beforePrograms[name] = pinnedLinkProgramID(t, filepath.Join(pinDir, name))
		}
		f, err := LoadPinnedCgroupFilter(cgroupPath, pinDir)
		if f != nil {
			_ = f.Close()
			t.Fatalf("implicit legacy load returned filter: %v", f)
		}
		if !errors.Is(err, ErrPinnedSchemaUpgradeRequired) {
			t.Fatalf("implicit legacy load must require original carve-outs, got %v", err)
		}
		if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(beforeNames) {
			t.Fatalf("implicit legacy load modified pins: before=%v after=%v", beforeNames, after)
		}
		for name, before := range beforePrograms {
			if after := pinnedLinkProgramID(t, filepath.Join(pinDir, name)); after != before {
				t.Fatalf("implicit legacy load updated %s: before=%d after=%d", name, before, after)
			}
		}
	})

	t.Run("tc", func(t *testing.T) {
		root := pinTestRoot(t)
		pinDir := filepath.Join(root, "legacy-public-tc")
		const iface = "nf-plr0"
		if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
			t.Fatalf("creating dummy interface: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
		createLegacyTCPinSet(t, iface, pinDir, ModeAllowlist, mustParse(t, "198.51.100.71/32"))
		beforeNames := pinDirectoryNames(t, pinDir)
		beforeProgram := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkTCX))
		f, err := LoadPinnedTCFilter(iface, DirectionEgress, pinDir)
		if f != nil {
			_ = f.Close()
			t.Fatalf("implicit legacy TC load returned filter: %v", f)
		}
		if !errors.Is(err, ErrPinnedSchemaUpgradeRequired) {
			t.Fatalf("implicit legacy TC load must require original carve-outs, got %v", err)
		}
		if after := pinDirectoryNames(t, pinDir); fmt.Sprint(after) != fmt.Sprint(beforeNames) {
			t.Fatalf("implicit legacy TC load modified pins: before=%v after=%v", beforeNames, after)
		}
		if after := pinnedLinkProgramID(t, filepath.Join(pinDir, pinLinkTCX)); after != beforeProgram {
			t.Fatalf("implicit legacy TC load updated link: before=%d after=%d", beforeProgram, after)
		}
	})
}

func assertRealTinyExactMapCapacity(t *testing.T, f Filter) {
	t.Helper()
	initialV6 := net.ParseIP("2001:db8::41")
	if err := f.AddDNSAllowedIPs([]net.IP{initialV6}); err != nil {
		t.Fatal(err)
	}
	err := f.AddDNSAllowedIPs([]net.IP{net.ParseIP("192.0.2.41"), net.ParseIP("2001:db8::42")})
	if !errors.Is(err, ErrDNSAllowCapacity) {
		t.Fatalf("real tiny HASH maps must return capacity error, got %v", err)
	}
	got, err := f.DNSAllowedIPs()
	if err != nil {
		t.Fatal(err)
	}
	assertSameIPSet(t, []string{initialV6.String()}, got, "real tiny exact-map contents after rejected cross-family batch")
	occupancy, err := f.DNSAllowOccupancy()
	if err != nil {
		t.Fatal(err)
	}
	if occupancy.IPv4Entries != 0 || occupancy.IPv4Capacity != 1 || occupancy.IPv6Entries != 1 || occupancy.IPv6Capacity != 1 {
		t.Fatalf("unexpected real tiny exact-map occupancy: %+v", occupancy)
	}
	if err := f.AddDNSAllowedIPs([]net.IP{net.ParseIP("192.0.2.41")}); err != nil {
		t.Fatalf("rejected cross-family batch consumed IPv4 capacity: %v", err)
	}
}

func TestRealTinyExactMapCapacityCgroupAndTC(t *testing.T) {
	t.Run("cgroup", func(t *testing.T) {
		cgroupPath := fmt.Sprintf("/sys/fs/cgroup/netfence-tiny-exact-%d", os.Getpid())
		if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroupPath) })
		f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{MaxDNSRuleEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer f.Detach()
		assertRealTinyExactMapCapacity(t, f)
	})

	t.Run("tc", func(t *testing.T) {
		const iface = "nf-pte0"
		if out, err := exec.Command("ip", "link", "add", iface, "type", "dummy").CombinedOutput(); err != nil {
			t.Fatalf("creating dummy interface: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", iface).Run() })
		f, err := NewTCFilterWithOptions(iface, ModeAllowlist, DirectionEgress, DefaultCarveouts(), Options{MaxDNSRuleEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer f.Detach()
		assertRealTinyExactMapCapacity(t, f)
	})
}
