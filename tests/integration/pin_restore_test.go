//go:build linux

// Phase 3A integration tests: bpffs-pinned BPF state must hold enforcement
// while the daemon is down (crash or stop), restores must re-adopt (not
// re-attach) with rules intact, and Detach / detach_on_stop must destroy the
// pinned state. These tests spawn the REAL netfenced binary so process death
// is process death — an in-process Server cannot prove kernel-held
// enforcement.
package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/emptypb"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

const (
	kill9AllowedIP = "8.8.8.8"
	kill9BlockedIP = "1.1.1.1"
	kill9NewIP     = "9.9.9.9"
)

// --- daemon binary harness ---------------------------------------------------

var (
	buildDaemonOnce sync.Once
	daemonBinPath   string
	daemonBinErr    error
)

// buildDaemonBinary compiles cmd/netfenced once per test process.
func buildDaemonBinary(t *testing.T) string {
	t.Helper()
	buildDaemonOnce.Do(func() {
		root, err := findModuleRoot()
		if err != nil {
			daemonBinErr = err
			return
		}
		bin := filepath.Join(os.TempDir(), fmt.Sprintf("netfenced-3a-test-%d", os.Getpid()))
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/netfenced")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			daemonBinErr = fmt.Errorf("building netfenced: %v: %s", err, out)
			return
		}
		daemonBinPath = bin
	})
	require.NoError(t, daemonBinErr)
	return daemonBinPath
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above test working directory")
		}
		dir = parent
	}
}

// daemonConfig is what gets rendered into the spawned daemon's config file.
type daemonConfig struct {
	socket       string
	dataDir      string
	cpURL        string
	pinRoot      string // "" = pinning disabled (the pre-3A behavior)
	detachOnStop bool
	portMin      int
	portMax      int
}

func writeDaemonConfig(t *testing.T, dir string, cfg daemonConfig) string {
	t.Helper()
	content := fmt.Sprintf(`socket: %s
data_dir: %s
log_level: debug
dns:
  listen_addr: 127.0.0.1
  port_min: %d
  port_max: %d
  upstream: 8.8.8.8:53
control_plane:
  url: %s
  # The test control plane is a plaintext local listener; plaintext is an
  # explicit opt-in since 4A (fail-closed default).
  insecure: true
  subscribe_ack_timeout: 10s
filter:
  bpf_pin_dir: %q
  detach_on_stop: %v
`, cfg.socket, cfg.dataDir, cfg.portMin, cfg.portMax, cfg.cpURL, cfg.pinRoot, cfg.detachOnStop)
	path := filepath.Join(dir, "netfence.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// daemonProc is one spawned life of the netfenced binary.
type daemonProc struct {
	cmd     *exec.Cmd
	socket  string
	logPath string
	conn    *grpc.ClientConn
	client  apiv1.DaemonServiceClient
}

// startDaemon spawns the binary and waits until its gRPC socket answers.
func startDaemon(t *testing.T, bin, cfgPath, socket, logPath string) *daemonProc {
	t.Helper()

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	defer logFile.Close()

	cmd := exec.Command(bin, "start", "--config", cfgPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())

	d := &daemonProc{cmd: cmd, socket: socket, logPath: logPath}
	t.Cleanup(func() {
		if d.conn != nil {
			_ = d.conn.Close()
		}
		// Best-effort reap if the test did not already stop this life.
		if d.cmd.ProcessState == nil {
			_ = d.cmd.Process.Kill()
			_, _ = d.cmd.Process.Wait()
		}
		if t.Failed() {
			if logs, err := os.ReadFile(logPath); err == nil {
				t.Logf("daemon log (%s):\n%s", logPath, logs)
			}
		}
	})

	conn, err := grpc.NewClient(
		"unix://"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socket, 5*time.Second)
		}),
	)
	require.NoError(t, err)
	d.conn = conn
	d.client = apiv1.NewDaemonServiceClient(conn)

	require.True(t, waitForCondition(30*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := d.client.GetStatus(ctx, &emptypb.Empty{})
		return err == nil
	}), "daemon did not become ready (see %s)", logPath)

	return d
}

// kill9 SIGKILLs the daemon and waits until the process is fully gone.
func (d *daemonProc) kill9(t *testing.T) {
	t.Helper()
	require.NoError(t, d.cmd.Process.Kill())
	_ = d.cmd.Wait() // "signal: killed" is expected
	_ = d.conn.Close()
}

// term SIGTERMs the daemon (graceful Stop path) and waits for exit.
func (d *daemonProc) term(t *testing.T) {
	t.Helper()
	require.NoError(t, d.cmd.Process.Signal(syscall.SIGTERM))
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("daemon did not exit after SIGTERM")
	}
	_ = d.conn.Close()
}

// --- shared helpers ----------------------------------------------------------

// requireBpffs skips unless bpffs is available (the Docker gate scripts mount
// it; see scripts/test-linux.sh).
func requireBpffs(t *testing.T) {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || uint32(st.Type) != uint32(unix.BPF_FS_MAGIC) {
		t.Skip("bpffs not mounted at /sys/fs/bpf")
	}
}

// connect4ProgCount counts programs attached to the cgroup's connect4 hook —
// the ground truth for "exactly one attachment, never duplicated".
func connect4ProgCount(t *testing.T, cgroupPath string) int {
	t.Helper()
	dir, err := os.Open(cgroupPath)
	require.NoError(t, err)
	defer dir.Close()
	res, err := link.QueryPrograms(link.QueryOptions{Target: int(dir.Fd()), Attach: ebpf.AttachCGroupInet4Connect})
	require.NoError(t, err)
	return len(res.Programs)
}

// startCP runs the in-process test control plane on TCP (so it spans the
// daemon process boundary). Returns the CP, its address, and a stopper.
func startCP(t *testing.T) (*testControlPlane, string, func()) {
	t.Helper()
	cp := newTestControlPlane()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Permit the daemon's keepalive ping cadence (the documented CP-side
	// contract): the default gRPC enforcement policy (5min) would GOAWAY
	// the daemon with "too_many_pings".
	gs := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             time.Second,
		PermitWithoutStream: true,
	}))
	apiv1.RegisterControlPlaneServer(gs, cp)
	go gs.Serve(lis)
	var once sync.Once
	stop := func() { once.Do(gs.Stop) }
	t.Cleanup(stop)
	return cp, lis.Addr().String(), stop
}

type kill9Env struct {
	bin      string
	cfgPath  string
	socket   string
	logPath  string
	pinRoot  string
	cgroup   string
	cp       *testControlPlane
	stopCP   func()
	workDir  string
	attachID string
	daemon   *daemonProc
}

// setupKill9Env spawns a daemon (pinning on/off per pinRoot), attaches the
// test cgroup in allowlist mode with kill9AllowedIP (+extraAllow) allowed,
// and verifies enforcement is live.
func setupKill9Env(t *testing.T, name string, pinningEnabled, detachOnStop bool, portMin int, extraAllow ...string) *kill9Env {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	requireBpffs(t)

	bin := buildDaemonBinary(t)
	cp, cpURL, stopCP := startCP(t)

	workDir := t.TempDir()
	pinRoot := ""
	if pinningEnabled {
		pinRoot = fmt.Sprintf("/sys/fs/bpf/netfence-%s-%d", name, os.Getpid())
		t.Cleanup(func() { _ = os.RemoveAll(pinRoot) })
	}
	socket := filepath.Join(workDir, "netfence.sock")
	logPath := filepath.Join(workDir, "daemon.log")
	cfgPath := writeDaemonConfig(t, workDir, daemonConfig{
		socket:       socket,
		dataDir:      workDir,
		cpURL:        cpURL,
		pinRoot:      pinRoot,
		detachOnStop: detachOnStop,
		portMin:      portMin,
		portMax:      portMin + 10,
	})

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-"+name)
	t.Cleanup(cgroupCleanup)

	allowCidrs := []*apiv1.CIDREntry{{Cidr: kill9AllowedIP + "/32"}}
	for _, ip := range extraAllow {
		allowCidrs = append(allowCidrs, &apiv1.CIDREntry{Cidr: ip + "/32"})
	}
	cp.SetConfig(cgroupPath, &apiv1.SubscribedAck{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: allowCidrs,
	})

	d := startDaemon(t, bin, cfgPath, socket, logPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := d.client.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err, "attach via spawned daemon")

	// Enforcement live: allowed connects, blocked does not (unless this
	// test's initial config deliberately allows the "blocked" IP too).
	require.True(t, waitForCondition(10*time.Second, func() bool {
		return runInCgroup(cgroupPath, kill9AllowedIP+" 53")
	}), "allowed IP must connect once allowlist config lands")
	blockedIsAllowed := false
	for _, ip := range extraAllow {
		if ip == kill9BlockedIP {
			blockedIsAllowed = true
		}
	}
	if !blockedIsAllowed {
		require.False(t, runInCgroup(cgroupPath, kill9BlockedIP+" 53"),
			"blocked IP must not connect in allowlist mode")
	}

	if pinningEnabled {
		require.DirExists(t, filepath.Join(pinRoot, resp.Id), "attachment must be pinned to bpffs")
	}

	return &kill9Env{
		bin: bin, cfgPath: cfgPath, socket: socket, logPath: logPath,
		pinRoot: pinRoot, cgroup: cgroupPath, cp: cp, stopCP: stopCP,
		workDir: workDir, attachID: resp.Id, daemon: d,
	}
}

func (e *kill9Env) pinDir() string {
	if e.pinRoot == "" {
		return ""
	}
	return filepath.Join(e.pinRoot, e.attachID)
}

// --- the headline test -------------------------------------------------------

// TestCgroupKill9KeepsEnforcing is the Phase 3 capstone assertion: SIGKILL
// the daemon mid-flight and the kernel — via the pinned links and maps —
// keeps enforcing the exact policy (blocked stays blocked, allowed stays
// allowed) while the process is dead; a restarted daemon re-adopts the
// pinned state with rules intact, without duplicating the attachment, and
// with no transient allow window at any point (continuous blocked-IP probe).
// The control plane is fully stopped before the restart, so the restored
// rules can only have come from the pinned maps.
func TestCgroupKill9KeepsEnforcing(t *testing.T) {
	env := setupKill9Env(t, "kill9", true, false, 23000)

	// Continuous probe: the blocked IP must NEVER connect — before the kill,
	// while the daemon is dead, across the restart, and after re-adoption.
	probeCtx, probeCancel := context.WithCancel(context.Background())
	defer probeCancel()
	var probeViolations atomic.Int64
	var probeAttempts atomic.Int64
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		for probeCtx.Err() == nil {
			probeAttempts.Add(1)
			if runInCgroup(env.cgroup, kill9BlockedIP+" 53") {
				probeViolations.Add(1)
			}
		}
	}()

	// SIGKILL: no shutdown path runs at all.
	env.daemon.kill9(t)

	// THE invariant: enforcement holds while the daemon process is dead.
	assert.True(t, runInCgroup(env.cgroup, kill9AllowedIP+" 53"),
		"allowed IP must STILL connect while the daemon is dead (kernel-held enforcement)")
	assert.False(t, runInCgroup(env.cgroup, kill9BlockedIP+" 53"),
		"blocked IP must STILL be blocked while the daemon is dead (kernel-held enforcement)")
	require.DirExists(t, env.pinDir(), "pins must survive SIGKILL")

	// Stop the control plane entirely: after the restart, rules can only
	// come from the pinned maps.
	env.stopCP()

	// Restart the daemon: restore must re-adopt, not re-attach.
	d2 := startDaemon(t, env.bin, env.cfgPath, env.socket, env.logPath)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := d2.client.List(ctx, &apiv1.ListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Attachments, 1, "restored daemon must have exactly the one attachment")
	assert.Equal(t, env.attachID, list.Attachments[0].Id, "attachment identity must survive the restart")
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, list.Attachments[0].Mode)

	// Rules intact with NO control plane available.
	assert.True(t, runInCgroup(env.cgroup, kill9AllowedIP+" 53"),
		"allowed IP must connect after restart with the control plane down (rules re-adopted from pins)")
	assert.False(t, runInCgroup(env.cgroup, kill9BlockedIP+" 53"),
		"blocked IP must stay blocked after restart")

	// Exactly one attachment on the cgroup: re-adopt never re-attached.
	assert.Equal(t, 1, connect4ProgCount(t, env.cgroup),
		"restore must re-adopt the pinned links, not attach a second program set")

	// The probe saw zero windows across kill -> dead -> restart -> restored.
	probeCancel()
	<-probeDone
	assert.Zero(t, probeViolations.Load(),
		"blocked IP connected %d/%d times during the kill/restart window — transient fail-open",
		probeViolations.Load(), probeAttempts.Load())
	assert.Greater(t, probeAttempts.Load(), int64(5), "probe must have actually run across the window")

	// Detach destroys pinned state and stops enforcement.
	_, err = d2.client.Detach(ctx, &apiv1.DetachRequest{Id: env.attachID})
	require.NoError(t, err)
	assert.NoDirExists(t, env.pinDir(), "Detach must remove the pin dir")
	// The kernel frees the unpinned links a beat after the last fd closes,
	// so poll rather than assert instantaneously.
	assert.True(t, waitForCondition(5*time.Second, func() bool {
		return connect4ProgCount(t, env.cgroup) == 0
	}), "Detach must remove the kernel attachment")
	assert.True(t, waitForCondition(5*time.Second, func() bool {
		return runInCgroup(env.cgroup, kill9BlockedIP+" 53")
	}), "traffic must be unfiltered after Detach")

	d2.term(t)
}

// TestCgroupKill9NegativeVerifyPre3A re-runs the kill-9 flow with pinning
// DISABLED (bpf_pin_dir: "") — the pre-3A behavior — and inverts the
// headline assertions to prove the kill-9 test actually bites: with fd-bound
// links, SIGKILL detaches everything (blocked IP connects while the daemon
// is dead) and the restarted daemon recreates an EMPTY allowlist (allowed IP
// blocked until a control-plane resync).
//
// Guarded behind NETFENCE_3A_NEGATIVE_VERIFY=1: it exists to document and
// capture the pre-3A failure mode, not to run in the gate. To see the
// headline test FAIL against pre-3A behavior instead, flip the inverted
// assertions back.
func TestCgroupKill9NegativeVerifyPre3A(t *testing.T) {
	if os.Getenv("NETFENCE_3A_NEGATIVE_VERIFY") != "1" {
		t.Skip("negative-verification variant; set NETFENCE_3A_NEGATIVE_VERIFY=1 to run")
	}
	env := setupKill9Env(t, "kill9neg", false, false, 23100)

	env.daemon.kill9(t)

	// Pre-3A failure mode 1: enforcement dies with the process.
	assert.True(t, runInCgroup(env.cgroup, kill9BlockedIP+" 53"),
		"pre-3A: blocked IP CONNECTS while the daemon is dead (fail-open window)")

	env.stopCP()
	d2 := startDaemon(t, env.bin, env.cfgPath, env.socket, env.logPath)
	defer d2.term(t)

	// Pre-3A failure mode 2: restore recreates an EMPTY allowlist — the
	// previously allowed IP is now blocked until a CP resync.
	assert.False(t, runInCgroup(env.cgroup, kill9AllowedIP+" 53"),
		"pre-3A: allowed IP is BLOCKED after restart (rules lost, empty allowlist)")
}

// TestCgroupStopKeepsEnforcingByDefault: graceful stop (SIGTERM) with the
// default detach_on_stop: false keeps the pins — the kernel keeps enforcing
// while the daemon is down. This records the "Default fail mode on daemon
// stop" decision as behavior.
func TestCgroupStopKeepsEnforcingByDefault(t *testing.T) {
	env := setupKill9Env(t, "stopkeep", true, false, 23200)

	env.daemon.term(t)

	assert.DirExists(t, env.pinDir(), "default stop must keep the pins")
	assert.True(t, runInCgroup(env.cgroup, kill9AllowedIP+" 53"),
		"allowed IP must still connect after graceful stop (keep-enforcing default)")
	assert.False(t, runInCgroup(env.cgroup, kill9BlockedIP+" 53"),
		"blocked IP must still be blocked after graceful stop (keep-enforcing default)")
	assert.Equal(t, 1, connect4ProgCount(t, env.cgroup), "attachment must survive the stop")
}

// TestCgroupDetachOnStopStopsEnforcing: detach_on_stop: true makes a
// graceful stop remove the pins and detach — traffic is unfiltered while
// the daemon is down (the explicit fail-open opt-in).
func TestCgroupDetachOnStopStopsEnforcing(t *testing.T) {
	env := setupKill9Env(t, "detachstop", true, true, 23300)

	env.daemon.term(t)

	assert.NoDirExists(t, env.pinDir(), "detach_on_stop must remove the pin dir")
	// The kernel may free the links a beat after the last fd closes, so
	// poll rather than assert instantaneously.
	assert.True(t, waitForCondition(5*time.Second, func() bool {
		return connect4ProgCount(t, env.cgroup) == 0
	}), "detach_on_stop must detach the filter")
	assert.True(t, waitForCondition(5*time.Second, func() bool {
		return runInCgroup(env.cgroup, kill9BlockedIP+" 53")
	}), "traffic must be unfiltered after detach_on_stop stop")
}

// TestCgroupKill9RecreatedTargetNotAdopted: a kernel bpf_link binds to the
// cgroup OBJECT, not its path. If the cgroup is destroyed and recreated at
// the same path while the daemon is down (a routine container restart), the
// pinned links are defunct: adopting them would leave the RECREATED cgroup
// completely unfiltered while the daemon reports an enforcing attachment.
// Restore must detect the reincarnation, discard the pins, and fall back to
// a FRESH attachment on the new cgroup in the persisted mode — fail-closed
// (empty allowlist), never fail-open.
func TestCgroupKill9RecreatedTargetNotAdopted(t *testing.T) {
	env := setupKill9Env(t, "reincarnate", true, false, 23500)

	env.daemon.kill9(t)

	// Destroy and recreate the cgroup at the SAME path while the daemon is
	// dead.
	require.NoError(t, os.Remove(env.cgroup), "removing cgroup (must be empty)")
	require.NoError(t, os.MkdirAll(env.cgroup, 0o755))

	env.stopCP()
	d2 := startDaemon(t, env.bin, env.cfgPath, env.socket, env.logPath)
	defer d2.term(t)

	// A fresh program set must be attached to the RECREATED cgroup (the
	// defunct pinned links target the dead cgroup and enforce nothing here).
	assert.Equal(t, 1, connect4ProgCount(t, env.cgroup),
		"recreated target must get a fresh attachment, not a defunct adopted link")
	// Fail-closed, not fail-open: the persisted allowlist mode is enforced
	// with an empty rule set (the rules belonged to the dead cgroup's life;
	// the control plane resyncs them), so BOTH destinations are blocked.
	assert.False(t, runInCgroup(env.cgroup, kill9BlockedIP+" 53"),
		"recreated target must NOT be fail-open: blocked IP must not connect")
	assert.False(t, runInCgroup(env.cgroup, kill9AllowedIP+" 53"),
		"recreated target enforces the persisted allowlist mode empty (fail-closed) until CP resync")
}

// TestCgroupPinnedRestoreSubscribedAckReconciles: after a kill-9 restart the
// daemon follows its Sync snapshot with a fresh Subscribed declaration for the
// restored attachment. The CP's automatic authoritative SubscribedAck must
// reconcile the re-adopted map by delta: {survivor, stale} becomes
// {survivor, new}, with no traffic gap for the survivor.
func TestCgroupPinnedRestoreSubscribedAckReconciles(t *testing.T) {
	// Initial allowlist: kill9AllowedIP + kill9BlockedIP (the latter plays
	// the "stale rule" here and must connect at first).
	env := setupKill9Env(t, "reseed", true, false, 23400, kill9BlockedIP)
	require.True(t, waitForCondition(5*time.Second, func() bool {
		return runInCgroup(env.cgroup, kill9BlockedIP+" 53")
	}), "stale-to-be IP must connect before the restart")
	require.False(t, runInCgroup(env.cgroup, kill9NewIP+" 53"),
		"new IP must start blocked so post-restore connectivity proves the ack admitted it")

	initialSubscribeCount := env.cp.SubscribedCount(env.attachID)
	require.GreaterOrEqual(t, initialSubscribeCount, 1, "initial Attach must have declared Subscribed")

	// Probe the survivor continuously across SIGKILL, pinned enforcement,
	// re-adoption, and the authoritative delta. Any remove/re-add
	// implementation would create a visible failure here.
	probeCtx, probeCancel := context.WithCancel(context.Background())
	var probeViolations atomic.Int64
	var probeAttempts atomic.Int64
	probeDone := make(chan struct{})
	var probeStopOnce sync.Once
	stopProbe := func() {
		probeStopOnce.Do(func() {
			probeCancel()
			<-probeDone
		})
	}
	go func() {
		defer close(probeDone)
		for probeCtx.Err() == nil {
			probeAttempts.Add(1)
			if !runInCgroup(env.cgroup, kill9AllowedIP+" 53") {
				probeViolations.Add(1)
			}
		}
	}()
	defer stopProbe()

	env.daemon.kill9(t)

	// Change desired state while the daemon is down. The restarted daemon
	// must solicit this full state itself; the test sends no BulkUpdate.
	env.cp.SetConfig(env.cgroup, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: kill9AllowedIP + "/32"},
			{Cidr: kill9NewIP + "/32"},
		},
	})

	// Restart with the CP still up. Sync must be followed by restored
	// Subscribed, and the CP helper replies with the fresh configuration.
	d2 := startDaemon(t, env.bin, env.cfgPath, env.socket, env.logPath)
	defer d2.term(t)

	require.True(t, waitForCondition(15*time.Second, func() bool {
		return env.cp.SubscribedCount(env.attachID) > initialSubscribeCount
	}), "restored attachment must emit a fresh Subscribed after Sync")
	require.True(t, waitForCondition(10*time.Second, func() bool {
		return !runInCgroup(env.cgroup, kill9BlockedIP+" 53") &&
			runInCgroup(env.cgroup, kill9NewIP+" 53")
	}), "automatic restored SubscribedAck must remove stale and admit new rules")

	stopProbe()
	assert.Greater(t, probeAttempts.Load(), int64(5), "survivor probe must span the restart and reconcile")
	assert.Zero(t, probeViolations.Load(), "survivor traffic must never see a remove/re-add window")
	assert.True(t, runInCgroup(env.cgroup, kill9AllowedIP+" 53"),
		"surviving rule must remain connectable after automatic restore reconciliation")
}
