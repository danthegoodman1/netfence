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

// flushNeighbors clears the neighbor (ARP) caches inside the workload netns
// and on the given host-side devices. Called AFTER a filter is attached, it
// forces the next connect to perform a real ARP exchange across the filter —
// so if the filter ever drops ARP in allowlist mode, the allowed-connect
// assertions fail deterministically instead of riding a warm cache.
func flushNeighbors(t *testing.T, hostDevs ...string) {
	t.Helper()
	require.NoError(t, ipCmd("-n", vethNetns, "neigh", "flush", "all"))
	for _, dev := range hostDevs {
		require.NoError(t, ipCmd("neigh", "flush", "dev", dev))
	}
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

// VLAN topology layered on top of setupVethNetns for the ethertype tests:
//
//	netns (workload)                        root netns (host)
//	nfveth1.100 10.200.0.2/24  ══ 802.1Q ══  nfveth0.100 10.200.0.1/24
//	                                                     10.200.0.3/24 (allowed)
//	                                                     10.200.0.5/24 (blocked)
//	nfvq1 10.201.0.2/24  ═ 802.1Q-in-802.1Q ═  nfvq0    10.201.0.1/24
//	  (link nfveth1.100, id 200)             (link nfveth0.100, id 200)
//	                                                     10.201.0.3/24 (allowed)
//	                                                     10.201.0.5/24 (blocked)
//
// Single-tagged frames reach the TC ingress hook with the tag already popped
// to skb metadata (skb->protocol = inner proto). QinQ frames arrive with the
// outer tag in metadata and the inner 802.1Q tag still IN THE PAYLOAD, so
// skb->protocol == ETH_P_8021Q at the hook — the exact shape the pre-1C
// program waved through as "non-IP".
const (
	vlanHostOuter = "nfveth0.100"
	vlanNsOuter   = "nfveth1.100"
	vlanHostQinq  = "nfvq0"
	vlanNsQinq    = "nfvq1"

	vlanNsIP        = "10.200.0.2"
	vlanAllowedIP   = "10.200.0.3"
	vlanBlockedIP   = "10.200.0.5"
	qinqNsIP        = "10.201.0.2"
	qinqAllowedIP   = "10.201.0.3"
	qinqBlockedIP   = "10.201.0.5"
	vlanHostGateway = "10.200.0.1"
	qinqHostGateway = "10.201.0.1"
)

// setupVlanOnVeth stacks the 802.1Q and QinQ subinterfaces onto an existing
// veth topology. The subdevices are torn down automatically with the veth
// pair/netns, so no extra cleanup is needed.
func setupVlanOnVeth(t *testing.T) {
	t.Helper()

	// Host side: outer 802.1Q (id 100) and nested 802.1Q (id 200) on top.
	require.NoError(t, ipCmd("link", "add", "link", vethHostIf, "name", vlanHostOuter, "type", "vlan", "id", "100"))
	for _, addr := range []string{vlanHostGateway, vlanAllowedIP, vlanBlockedIP} {
		require.NoError(t, ipCmd("addr", "add", addr+"/24", "dev", vlanHostOuter))
	}
	require.NoError(t, ipCmd("link", "set", vlanHostOuter, "up"))

	require.NoError(t, ipCmd("link", "add", "link", vlanHostOuter, "name", vlanHostQinq, "type", "vlan", "id", "200"))
	for _, addr := range []string{qinqHostGateway, qinqAllowedIP, qinqBlockedIP} {
		require.NoError(t, ipCmd("addr", "add", addr+"/24", "dev", vlanHostQinq))
	}
	require.NoError(t, ipCmd("link", "set", vlanHostQinq, "up"))

	// Workload side mirrors the stack inside the netns.
	require.NoError(t, ipCmd("-n", vethNetns, "link", "add", "link", vethNsIf, "name", vlanNsOuter, "type", "vlan", "id", "100"))
	require.NoError(t, ipCmd("-n", vethNetns, "addr", "add", vlanNsIP+"/24", "dev", vlanNsOuter))
	require.NoError(t, ipCmd("-n", vethNetns, "link", "set", vlanNsOuter, "up"))

	require.NoError(t, ipCmd("-n", vethNetns, "link", "add", "link", vlanNsOuter, "name", vlanNsQinq, "type", "vlan", "id", "200"))
	require.NoError(t, ipCmd("-n", vethNetns, "addr", "add", qinqNsIP+"/24", "dev", vlanNsQinq))
	require.NoError(t, ipCmd("-n", vethNetns, "link", "set", vlanNsQinq, "up"))
}

// TestTCVethVlanAllowlist proves the 1C ethertype fix: VLAN-tagged traffic in
// allowlist mode is filtered by the INNER destination address instead of
// falling through open (pre-1C: any non-IPv4/IPv6 ethertype, including an
// in-payload 802.1Q tag, returned TC_ACT_OK and bypassed the allowlist).
// The neighbor caches are flushed after the filter attaches, so the
// allowed-connect assertions force a real ARP exchange (single-tagged and
// double-tagged) across the fail-closed filter — if ARP were dropped in
// allowlist mode, those assertions would fail.
func TestTCVethVlanAllowlist(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := setupVethNetns(t)
	defer cleanup()
	setupVlanOnVeth(t)

	vlanAllowedPort, closeVA := listenTCP(t, vlanAllowedIP)
	defer closeVA()
	vlanBlockedPort, closeVB := listenTCP(t, vlanBlockedIP)
	defer closeVB()
	qinqAllowedPort, closeQA := listenTCP(t, qinqAllowedIP)
	defer closeQA()
	qinqBlockedPort, closeQB := listenTCP(t, qinqBlockedIP)
	defer closeQB()

	// Sanity: with no filter attached, all four destinations are reachable
	// through their VLAN paths from the workload netns.
	require.True(t, nsConnectTCP(vlanAllowedIP, vlanAllowedPort), "vlan topology broken: allowed dest unreachable without filter")
	require.True(t, nsConnectTCP(vlanBlockedIP, vlanBlockedPort), "vlan topology broken: blocked dest unreachable without filter")
	require.True(t, nsConnectTCP(qinqAllowedIP, qinqAllowedPort), "qinq topology broken: allowed dest unreachable without filter")
	require.True(t, nsConnectTCP(qinqBlockedIP, qinqBlockedPort), "qinq topology broken: blocked dest unreachable without filter")

	// Filter attaches to the BASE host-side peer: every tagged frame from
	// the workload crosses it.
	f, err := filter.NewTCFilter(vethHostIf, filter.ModeAllowlist, filter.DirectionIngress)
	require.NoError(t, err)
	defer f.Close()

	for _, allowed := range []string{vlanAllowedIP, qinqAllowedIP} {
		cidr, err := filter.ParseCIDR(allowed + "/32")
		require.NoError(t, err)
		require.NoError(t, f.AllowIP(cidr))
	}

	// The pre-attach sanity connects warmed the neighbor caches; flush them
	// so every assertion below must ARP through the attached filter.
	flushNeighbors(t, vethHostIf, vlanHostOuter, vlanHostQinq)

	t.Run("vlan_8021q/allowed_dest_succeeds", func(t *testing.T) {
		assert.True(t, nsConnectTCP(vlanAllowedIP, vlanAllowedPort),
			"expected connection over 802.1Q VLAN to allowlisted destination to SUCCEED")
	})

	t.Run("vlan_8021q/blocked_dest_blocked", func(t *testing.T) {
		assert.False(t, nsConnectTCP(vlanBlockedIP, vlanBlockedPort),
			"expected connection over 802.1Q VLAN to non-allowlisted destination to be BLOCKED")
	})

	// QinQ is the pre-1C bypass shape at an ingress attach: the kernel pops
	// only the outer tag to metadata, leaving skb->protocol == ETH_P_8021Q
	// with the inner tag in the payload.
	t.Run("vlan_qinq/allowed_dest_succeeds", func(t *testing.T) {
		assert.True(t, nsConnectTCP(qinqAllowedIP, qinqAllowedPort),
			"expected connection over QinQ to allowlisted destination to SUCCEED (inner unwrap, not blanket drop)")
	})

	t.Run("vlan_qinq/blocked_dest_blocked", func(t *testing.T) {
		assert.False(t, nsConnectTCP(qinqBlockedIP, qinqBlockedPort),
			"expected connection over QinQ to non-allowlisted destination to be BLOCKED (pre-1C bypass)")
	})

	stats, err := f.GetStats()
	require.NoError(t, err)
	assert.Greater(t, stats.Allowed, uint64(0), "expected allowed count > 0")
	assert.Greater(t, stats.Blocked, uint64(0), "expected blocked count > 0")
	t.Logf("Stats: allowed=%d, blocked=%d", stats.Allowed, stats.Blocked)
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

		// Flush neighbor caches (warmed by the pre-attach sanity connects)
		// so the allowed connect must complete a real ARP exchange across
		// the attached allowlist filter — pinning the ARP allowance.
		flushNeighbors(t, vethHostIf)

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

		// Flush so the exchange must re-ARP through this egress filter too:
		// the host's ARP REPLY egresses nfveth0 and relies on the ARP
		// allowance in allowlist mode.
		flushNeighbors(t, vethHostIf)

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

		// Flush so the first datagram's delivery requires a fresh ARP
		// exchange across the attached allowlist filter.
		flushNeighbors(t, vethHostIf)

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
