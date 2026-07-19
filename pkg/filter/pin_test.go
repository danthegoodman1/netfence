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

	f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{PinDir: pinDir})
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
		pinAllowedIPv4, pinAllowedIPv6, pinDeniedIPv4, pinDeniedIPv6, pinPolicyMode, pinStats,
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
	t.Helper()
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: ebpf.AttachTCXEgress})
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

	f, err := NewTCFilterWithOptions(iface, ModeDenylist, DirectionEgress, DefaultCarveouts(), Options{PinDir: pinDir})
	if err != nil {
		t.Fatalf("creating pinned TC filter: %v", err)
	}
	if err := f.AllowIP(allowA); err != nil {
		t.Fatal(err)
	}
	if err := f.DenyIP(denyB); err != nil {
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

// TestTCPinnedLinkReincarnationRejected is the TC twin: a TCX link binds to
// the ifindex; recreating the interface under the same name yields a new
// ifindex, and the pinned link must be refused.
func TestTCPinnedLinkReincarnationRejected(t *testing.T) {
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
	if !errors.Is(err, ErrPinnedTargetMismatch) {
		t.Fatalf("expected typed pinned-target mismatch, got %v", err)
	}
	t.Logf("correctly refused defunct link: %v", err)
}

// TestPinCollisionOnCreateCleansStaleDir: a leftover pin dir from a prior
// life must not break (or silently poison) a fresh create.
func TestPinCollisionOnCreateCleansStaleDir(t *testing.T) {
	root := pinTestRoot(t)
	pinDir := filepath.Join(root, "att-1")

	cgroupPath := "/sys/fs/cgroup/netfence-pin-collision"
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("creating test cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroupPath) })

	// Stale dir with a bogus non-BPF file where a map pin should go.
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		t.Fatal(err)
	}

	f, err := NewCgroupFilterWithOptions(cgroupPath, ModeAllowlist, DefaultCarveouts(), Options{PinDir: pinDir})
	if err != nil {
		t.Fatalf("create over a stale pin dir must succeed (clean-and-recreate): %v", err)
	}
	defer func() {
		if err := f.Detach(); err != nil {
			t.Errorf("detach: %v", err)
		}
	}()

	// The fresh pins must load.
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, pinPolicyMode), nil)
	if err != nil {
		t.Fatalf("fresh pin unusable after collision clean: %v", err)
	}
	_ = m.Close()
}
