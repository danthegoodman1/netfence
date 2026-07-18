//go:build linux

package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Topology for the TC direction tests:
//
//	netns (workload)                        root netns (host)
//	nfveth1 10.199.0.2/24  ═════veth═════  nfveth0 10.199.0.1/24
//	                                               10.199.0.3/24 (allowed dest)
//	                                               10.199.0.5/24 (blocked dest)
//
// The workload's outbound packets arrive at the HOST-side peer (nfveth0) as
// INGRESS, so filtering workload egress there requires DirectionIngress:
// there the packet's daddr is the true external destination. Attaching
// EGRESS on nfveth0 instead sees host->workload traffic, whose daddr is the
// workload's own address — the wrong direction bug this test pins down.
const (
	vethNetns  = "nfns-direction"
	vethHostIf = "nfveth0"
	vethNsIf   = "nfveth1"

	vethHostIP    = "10.199.0.1"
	vethNsIP      = "10.199.0.2"
	vethAllowedIP = "10.199.0.3"
	vethBlockedIP = "10.199.0.5"
)

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cleanupVethNetns() {
	// Deleting the netns removes the ns-side veth; deleting either veth end
	// removes the pair. Ignore errors: these fail when nothing exists yet.
	_ = exec.Command("ip", "netns", "del", vethNetns).Run()
	_ = exec.Command("ip", "link", "del", vethHostIf).Run()
}

// setupVethNetns creates the netns + veth pair topology above and returns a
// cleanup function. Requires root and netns support in the environment (the
// Docker gate runs privileged with iproute2 available).
func setupVethNetns(t *testing.T) func() {
	t.Helper()
	cleanupVethNetns() // clear leftovers from a previous failed run

	require.NoError(t, ipCmd("netns", "add", vethNetns))
	require.NoError(t, ipCmd("link", "add", vethHostIf, "type", "veth", "peer", "name", vethNsIf))
	require.NoError(t, ipCmd("link", "set", vethNsIf, "netns", vethNetns))

	for _, addr := range []string{vethHostIP, vethAllowedIP, vethBlockedIP} {
		require.NoError(t, ipCmd("addr", "add", addr+"/24", "dev", vethHostIf))
	}
	require.NoError(t, ipCmd("link", "set", vethHostIf, "up"))

	require.NoError(t, ipCmd("-n", vethNetns, "addr", "add", vethNsIP+"/24", "dev", vethNsIf))
	require.NoError(t, ipCmd("-n", vethNetns, "link", "set", vethNsIf, "up"))
	require.NoError(t, ipCmd("-n", vethNetns, "link", "set", "lo", "up"))

	return cleanupVethNetns
}

// nsConnectTCP attempts a TCP connect from inside the workload netns.
// Returns true if the connection succeeded, false if blocked/timed out.
func nsConnectTCP(host, port string) bool {
	cmd := exec.Command("ip", "netns", "exec", vethNetns, "nc", "-z", "-w", "2", host, port)
	return cmd.Run() == nil
}

// nsSendUDP sends a single UDP datagram from inside the workload netns.
func nsSendUDP(t *testing.T, payload, host, port string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", vethNetns, "sh", "-c",
		fmt.Sprintf("printf %s | nc -u -w 1 %s %s", payload, host, port))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("UDP send from netns failed: %v: %s", err, out)
	}
}

// listenTCP starts a TCP listener bound to a specific host address and
// accepts (and immediately discards) connections until closed.
func listenTCP(t *testing.T, addr string) (port string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(addr, "0"))
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, err = net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return port, func() { ln.Close() }
}

// TestTCVethDirection is the first traffic-level TC test: it proves that on
// the documented host-side veth topology, DirectionIngress filters the
// workload's egress by true destination, and documents why DirectionEgress
// on the same interface is the wrong direction there.
func TestTCVethDirection(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := setupVethNetns(t)
	defer cleanup()

	allowedPort, closeAllowed := listenTCP(t, vethAllowedIP)
	defer closeAllowed()
	blockedPort, closeBlocked := listenTCP(t, vethBlockedIP)
	defer closeBlocked()

	// Sanity: with no filter attached, both destinations are reachable from
	// the workload netns.
	require.True(t, nsConnectTCP(vethAllowedIP, allowedPort), "veth topology broken: allowed dest unreachable without filter")
	require.True(t, nsConnectTCP(vethBlockedIP, blockedPort), "veth topology broken: blocked dest unreachable without filter")

	t.Run("ingress_filters_workload_egress_by_destination", func(t *testing.T) {
		f, err := filter.NewTCFilter(vethHostIf, filter.ModeAllowlist, filter.DirectionIngress)
		require.NoError(t, err)
		defer f.Close()

		cidr, err := filter.ParseCIDR(vethAllowedIP + "/32")
		require.NoError(t, err)
		require.NoError(t, f.AllowIP(cidr))

		assert.True(t, nsConnectTCP(vethAllowedIP, allowedPort),
			"expected connection to allowlisted destination to SUCCEED")
		assert.False(t, nsConnectTCP(vethBlockedIP, blockedPort),
			"expected connection to non-allowlisted destination to be BLOCKED")

		stats, err := f.GetStats()
		require.NoError(t, err)
		assert.Greater(t, stats.Allowed, uint64(0), "expected allowed count > 0")
		assert.Greater(t, stats.Blocked, uint64(0), "expected blocked count > 0")
		t.Logf("Stats: allowed=%d, blocked=%d", stats.Allowed, stats.Blocked)
	})

	// Contrast case: EGRESS on the host-side peer sees host->workload
	// packets, whose daddr is the workload's own address — it cannot filter
	// the workload's egress by true destination. This is the wrong-direction
	// bug the direction field exists to fix.
	t.Run("egress_on_host_peer_filters_wrong_direction", func(t *testing.T) {
		f, err := filter.NewTCFilter(vethHostIf, filter.ModeAllowlist, filter.DirectionEgress)
		require.NoError(t, err)
		defer f.Close()

		// Allowing the true destination does NOT make it reachable: the
		// workload's SYN is unfiltered (it is ingress here), but the host's
		// SYN-ACK egresses with daddr = the workload address, which is not
		// allowlisted, so the handshake never completes.
		destCidr, err := filter.ParseCIDR(vethAllowedIP + "/32")
		require.NoError(t, err)
		require.NoError(t, f.AllowIP(destCidr))
		assert.False(t, nsConnectTCP(vethAllowedIP, allowedPort),
			"EGRESS on a host-side veth peer should NOT be able to allow traffic by true destination")

		// Allowing the workload's own address opens EVERY destination —
		// proving the egress hook keys on the wrong address entirely.
		workloadCidr, err := filter.ParseCIDR(vethNsIP + "/32")
		require.NoError(t, err)
		require.NoError(t, f.AllowIP(workloadCidr))
		assert.True(t, nsConnectTCP(vethAllowedIP, allowedPort),
			"allowing the workload's own address should open the return path")
		assert.True(t, nsConnectTCP(vethBlockedIP, blockedPort),
			"EGRESS on a host-side veth peer cannot block by true destination once the workload address is allowed")
	})

	// README claims established connections are severed when a rule is
	// removed. TC enforcement is per-packet (no conntrack), so removal takes
	// effect on the next packet. A UDP flow shows this deterministically;
	// for TCP the connection stops passing data rather than emitting an RST.
	t.Run("rule_removal_severs_established_flow", func(t *testing.T) {
		f, err := filter.NewTCFilter(vethHostIf, filter.ModeAllowlist, filter.DirectionIngress)
		require.NoError(t, err)
		defer f.Close()

		pc, err := net.ListenPacket("udp4", net.JoinHostPort(vethAllowedIP, "0"))
		require.NoError(t, err)
		defer pc.Close()
		received := make(chan string, 16)
		go func() {
			buf := make([]byte, 2048)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				received <- string(buf[:n])
			}
		}()
		_, udpPort, err := net.SplitHostPort(pc.LocalAddr().String())
		require.NoError(t, err)

		cidr, err := filter.ParseCIDR(vethAllowedIP + "/32")
		require.NoError(t, err)
		require.NoError(t, f.AllowIP(cidr))

		nsSendUDP(t, "flow-1", vethAllowedIP, udpPort)
		select {
		case payload := <-received:
			assert.Equal(t, "flow-1", payload)
		case <-time.After(2 * time.Second):
			t.Fatal("expected packet was not delivered while rule present")
		}

		require.NoError(t, f.RemoveAllowedIP(cidr))

		nsSendUDP(t, "flow-2", vethAllowedIP, udpPort)
		select {
		case payload := <-received:
			t.Fatalf("flow should be severed after rule removal, got %q", payload)
		case <-time.After(700 * time.Millisecond):
		}
	})
}
