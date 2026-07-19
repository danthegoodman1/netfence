//go:build linux

package integration

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// TestHelperUDPFlood is not a real test: it is the sender side of
// TestBulkUpdateNoTransientWindowTraffic, re-executed as a child process so
// it can be placed in the filtered cgroup. It opens one UNCONNECTED UDP
// socket and hammers WriteTo(target) — every datagram traverses the
// cgroup/sendmsg4 hook, so any transient removal of the allow rule turns
// into an EPERM the parent can count. Protocol: wait for a "go" line on
// stdin, send until stdin closes, then print "sent=N errors=M first=...".
func TestHelperUDPFlood(t *testing.T) {
	target := os.Getenv("NETFENCE_UDP_FLOOD_TARGET")
	if target == "" {
		t.Skip("helper process for TestBulkUpdateNoTransientWindowTraffic")
	}
	canary := os.Getenv("NETFENCE_UDP_FLOOD_CANARY")

	dst, err := net.ResolveUDPAddr("udp4", target)
	require.NoError(t, err)

	// Wait for the parent to place us in the cgroup. The socket MUST be
	// created only after that: cgroup BPF hooks match on the cgroup the
	// socket was created in, so a pre-join socket would bypass the filter
	// entirely and make the whole test vacuous.
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	conn, err := net.ListenPacket("udp4", ":0") // unconnected on purpose
	require.NoError(t, err)
	defer conn.Close()

	// Vacuousness guard: a send to the canary address (never allowlisted)
	// must be BLOCKED, proving this socket is actually filtered.
	canaryBlocked := false
	if canary != "" {
		cdst, err := net.ResolveUDPAddr("udp4", canary)
		require.NoError(t, err)
		if _, err := conn.WriteTo([]byte("x"), cdst); err != nil {
			canaryBlocked = true
		}
	}

	var stop atomic.Bool
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin) // returns on stdin EOF
		stop.Store(true)
	}()

	var sent, sendErrors int
	firstErr := ""
	payload := []byte("x")
	for !stop.Load() {
		if _, err := conn.WriteTo(payload, dst); err != nil {
			sendErrors++
			if firstErr == "" {
				firstErr = err.Error()
			}
		} else {
			sent++
		}
	}
	fmt.Printf("sent=%d errors=%d canary_blocked=%v first=%q\n", sent, sendErrors, canaryBlocked, firstErr)
}

var udpFloodResultRe = regexp.MustCompile(`sent=(\d+) errors=(\d+) canary_blocked=(true|false) first=(".*")`)

// TestBulkUpdateNoTransientWindowTraffic is the Phase 2C headline traffic
// test: a live allowlisted unconnected-UDP flow from a filtered cgroup must
// see ZERO send failures across a storm of alternating BulkUpdates that all
// keep its CIDR — proving the reconcile-based bulk apply opens no transient
// block window. (The old wipe-then-rebuild apply fails this: each resync
// briefly removed every rule.)
func TestBulkUpdateNoTransientWindowTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	const targetIP = "192.0.2.91"
	if out, err := exec.Command("ip", "addr", "add", targetIP+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("assigning %s to lo: %v: %s", targetIP, err, out)
	}
	defer exec.Command("ip", "addr", "del", targetIP+"/32", "dev", "lo").Run()

	env := newE2ETestEnvWithOptions(t, 33000, 33100, 5*time.Second)
	defer env.cleanup()

	at := setupCgroupAttachment(t, env, "bulk-no-window", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: targetIP + "/32"},
		},
	})
	defer at.cleanup()

	// Launch the sender helper and place it in the filtered cgroup BEFORE
	// it starts sending.
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run", "^TestHelperUDPFlood$", "-test.v")
	cmd.Env = append(os.Environ(),
		"NETFENCE_UDP_FLOOD_TARGET="+targetIP+":33999",
		"NETFENCE_UDP_FLOOD_CANARY=192.0.2.92:33999", // never allowlisted
	)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer cmd.Process.Kill()

	require.NoError(t, os.WriteFile(filepath.Join(at.target, "cgroup.procs"),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0644))
	_, err = io.WriteString(stdin, "go\n")
	require.NoError(t, err)

	// The storm: alternating bulk updates over the real control-plane
	// stream. Every one declares the flow's CIDR; the alternating extra
	// CIDR forces genuine add/remove delta work on each apply.
	const bulkCount = 80
	for i := 0; i < bulkCount; i++ {
		extra := "198.51.100.0/24"
		if i%2 == 1 {
			extra = "203.0.113.0/24"
		}
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{
				Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
				AllowCidrs: []*apiv1.CIDREntry{
					{Cidr: targetIP + "/32"},
					{Cidr: extra},
				},
			}},
		}))
		time.Sleep(2 * time.Millisecond)
	}

	// Let the daemon drain the tail of the storm while the flood continues,
	// then stop the sender and collect its tally.
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, stdin.Close())

	out, err := io.ReadAll(stdout)
	require.NoError(t, err)
	require.NoError(t, cmd.Wait(), "sender helper failed: %s", out)

	m := udpFloodResultRe.FindStringSubmatch(string(out))
	require.NotNil(t, m, "sender output missing tally: %s", out)
	sent, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	sendErrors, err := strconv.Atoi(m[2])
	require.NoError(t, err)

	t.Logf("UDP flood across %d bulk updates: sent=%d errors=%d canary_blocked=%s first=%s",
		bulkCount, sent, sendErrors, m[3], m[4])
	require.Equal(t, "true", m[3],
		"canary send to a non-allowlisted address must be blocked — otherwise the flood socket is not filtered and this test proves nothing")
	assert.Zero(t, sendErrors,
		"allowlisted flow must see ZERO send failures across bulk updates (transient window!) — first error: %s", m[4])
	require.Greater(t, sent, 1000, "sender did not overlap the bulk storm meaningfully")
}
