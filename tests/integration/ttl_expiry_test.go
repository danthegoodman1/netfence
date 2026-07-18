//go:build linux

package integration

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/daemon"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// newTestServerWithConfig builds and starts a daemon server with a caller
// tweaked config (short TTL janitor interval, small rule maps, ...).
func newTestServerWithConfig(t *testing.T, mutate func(*config.Config)) *testServer {
	t.Helper()

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    32000,
			PortMax:    32100,
			Upstream:   "8.8.8.8:53",
		},
	}
	if mutate != nil {
		mutate(cfg)
	}

	st, err := store.New(":memory:")
	require.NoError(t, err, "failed to create store")

	srv, err := daemon.NewServer(cfg, st, zerolog.New(io.Discard), "test")
	require.NoError(t, err, "failed to create server")
	require.NoError(t, srv.Start(), "failed to start server")

	return &testServer{
		server: srv,
		store:  st,
		cleanup: func() {
			srv.Stop()
			st.Close()
		},
	}
}

// startLocalTarget assigns ip (outside every default carve-out) to lo and
// listens on it, so allowlist verdicts are provable with real deliverable
// traffic and no external network dependency.
func startLocalTarget(t *testing.T, ip string) (ncAddr, dialAddr string) {
	t.Helper()

	if out, err := exec.Command("ip", "addr", "add", ip+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("assigning %s to lo: %v: %s", ip, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", ip+"/32", "dev", "lo").Run() })

	ln, err := net.Listen("tcp4", ip+":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return ip + " " + port, ip + ":" + port
}

// TestDaemonCIDRTTLExpiryTraffic is the Phase 2 completion-gate traffic
// test for TTL expiry: a short-TTL control-plane style allow opens the path
// for a real connection from a filtered cgroup, and once the TTL lapses the
// janitor removes the rule and subsequent connects are BLOCKED again in
// allowlist mode.
func TestDaemonCIDRTTLExpiryTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ncAddr, dialAddr := startLocalTarget(t, "192.0.2.80")
	require.True(t, tryConnect(dialAddr, 2*time.Second), "target not reachable without filter")

	ts := newTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.TTLJanitorInterval = 50 * time.Millisecond
	})
	defer ts.cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-ttl-expiry-test")
	defer cgroupCleanup()

	resp, err := ts.server.Attach(context.Background(), &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)
	require.NoError(t, ts.server.SetFilterMode(resp.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))

	require.False(t, runInCgroup(cgroupPath, ncAddr), "expected connection BLOCKED before allow")

	// The TTL is deliberately generous (3s) relative to the allowed-connect
	// assertion right below (nc timeout 2s) so a slow CI runner cannot see
	// the entry expire before the ALLOWED check lands.
	cidr, err := filter.ParseCIDR("192.0.2.80/32")
	require.NoError(t, err)
	require.NoError(t, ts.server.AllowCIDR(resp.Id, cidr, 3*time.Second))

	require.True(t, runInCgroup(cgroupPath, ncAddr), "expected connection ALLOWED while TTL live")

	// After the TTL lapses the janitor (50ms interval) must remove the rule
	// and traffic must be blocked again. Bounded wait, no fixed sleeps.
	require.True(t, waitForCondition(15*time.Second, func() bool {
		return !runInCgroup(cgroupPath, ncAddr)
	}), "expected connection BLOCKED again after TTL expiry")

	// And it stays blocked.
	assert.False(t, runInCgroup(cgroupPath, ncAddr))
}

// TestDaemonMapFullSurfacedAndRecovers configures tiny rule maps
// (filter.max_rule_entries=2), fills them, and verifies that the overflow
// add (a) fails loudly instead of silently, (b) is surfaced via the
// AttachmentStats map_full_drops counter, and (c) succeeds after the TTL
// janitor expires an entry and frees capacity.
func TestDaemonMapFullSurfacedAndRecovers(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.TTLJanitorInterval = 50 * time.Millisecond
		cfg.Filter.MaxRuleEntries = 2
		cfg.DNS.PortMin = 32200
		cfg.DNS.PortMax = 32300
	})
	defer ts.cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-map-full-test")
	defer cgroupCleanup()

	resp, err := ts.server.Attach(context.Background(), &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)
	require.NoError(t, ts.server.SetFilterMode(resp.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))

	mustParse := func(s string) *net.IPNet {
		cidr, err := filter.ParseCIDR(s)
		require.NoError(t, err)
		return cidr
	}

	// Fill the 2-entry allowed_ipv4 map: one short-TTL entry, one permanent.
	require.NoError(t, ts.server.AllowCIDR(resp.Id, mustParse("198.51.100.1/32"), time.Second))
	require.NoError(t, ts.server.AllowCIDR(resp.Id, mustParse("198.51.100.2/32"), 0))

	// Overflow: must fail loudly...
	overflow := mustParse("198.51.100.3/32")
	require.Error(t, ts.server.AllowCIDR(resp.Id, overflow, 0), "add beyond max_rule_entries must fail")

	// ...and be surfaced in the heartbeat stats.
	statFor := func() uint64 {
		for _, s := range ts.server.GetAttachmentStats() {
			if s.Id == resp.Id {
				return s.MapFullDrops
			}
		}
		return 0
	}
	require.GreaterOrEqual(t, statFor(), uint64(1), "map-full drop must be counted in AttachmentStats")

	// Recovery: once the janitor expires the 1s entry, the same add succeeds.
	require.True(t, waitForCondition(10*time.Second, func() bool {
		return ts.server.AllowCIDR(resp.Id, overflow, 0) == nil
	}), "expected add to succeed after janitor frees capacity")
}
