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

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/daemon"
	"github.com/danthegoodman1/netfence/internal/store"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type testServer struct {
	server  *daemon.Server
	store   *store.Store
	cleanup func()
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    19000,
			PortMax:    19100,
			Upstream:   "8.8.8.8:53",
		},
	}

	st, err := store.New(":memory:")
	require.NoError(t, err, "failed to create store")

	logger := zerolog.New(io.Discard)

	srv, err := daemon.NewServer(cfg, st, logger, "test")
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

func isDNSServerRunning(addr string) bool {
	client := &dns.Client{Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	_, _, err := client.Exchange(msg, addr)
	return err == nil
}

func waitForCondition(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestDaemonAttachCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-daemon-cgroup-test")
	defer cgroupCleanup()

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err, "attach should succeed")
	require.NotEmpty(t, resp.Id, "should return attachment ID")
	require.NotEmpty(t, resp.DnsAddress, "should return DNS address")

	t.Run("attachment_tracked", func(t *testing.T) {
		listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
		require.NoError(t, err)
		require.Len(t, listResp.Attachments, 1)
		assert.Equal(t, resp.Id, listResp.Attachments[0].Id)
		assert.Equal(t, cgroupPath, listResp.Attachments[0].Target)
		assert.Equal(t, apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP, listResp.Attachments[0].Type)
	})

	t.Run("dns_server_running", func(t *testing.T) {
		assert.True(t, isDNSServerRunning(resp.DnsAddress),
			"DNS server should be reachable at %s", resp.DnsAddress)
	})
}

func TestDaemonAttachInterface(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	ifaceName := "nf-dmn-test0"
	require.NoError(t, createDummyInterface(ifaceName))
	defer deleteDummyInterface(ifaceName)

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: ifaceName},
	})
	require.NoError(t, err, "attach should succeed")
	require.NotEmpty(t, resp.Id, "should return attachment ID")
	require.NotEmpty(t, resp.DnsAddress, "should return DNS address")

	t.Run("attachment_tracked", func(t *testing.T) {
		listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
		require.NoError(t, err)
		require.Len(t, listResp.Attachments, 1)
		assert.Equal(t, resp.Id, listResp.Attachments[0].Id)
		assert.Equal(t, ifaceName, listResp.Attachments[0].Target)
		assert.Equal(t, apiv1.AttachmentType_ATTACHMENT_TYPE_TC, listResp.Attachments[0].Type)
	})

	t.Run("dns_server_running", func(t *testing.T) {
		assert.True(t, isDNSServerRunning(resp.DnsAddress),
			"DNS server should be reachable at %s", resp.DnsAddress)
	})
}

func TestDaemonManualDetachCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-daemon-detach-cgroup")
	defer cgroupCleanup()

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)

	dnsAddr := resp.DnsAddress
	require.True(t, isDNSServerRunning(dnsAddr), "DNS should be running before detach")

	_, err = ts.server.Detach(ctx, &apiv1.DetachRequest{Id: resp.Id})
	require.NoError(t, err, "detach should succeed")

	t.Run("attachment_removed", func(t *testing.T) {
		listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
		require.NoError(t, err)
		assert.Empty(t, listResp.Attachments, "attachment should be removed")
	})

	t.Run("dns_server_stopped", func(t *testing.T) {
		stopped := waitForCondition(2*time.Second, func() bool {
			return !isDNSServerRunning(dnsAddr)
		})
		assert.True(t, stopped, "DNS server should stop after detach")
	})
}

func TestDaemonManualDetachInterface(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	ifaceName := "nf-det-test0"
	require.NoError(t, createDummyInterface(ifaceName))
	defer deleteDummyInterface(ifaceName)

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: ifaceName},
	})
	require.NoError(t, err)

	dnsAddr := resp.DnsAddress
	require.True(t, isDNSServerRunning(dnsAddr), "DNS should be running before detach")

	_, err = ts.server.Detach(ctx, &apiv1.DetachRequest{Id: resp.Id})
	require.NoError(t, err, "detach should succeed")

	t.Run("attachment_removed", func(t *testing.T) {
		listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
		require.NoError(t, err)
		assert.Empty(t, listResp.Attachments, "attachment should be removed")
	})

	t.Run("dns_server_stopped", func(t *testing.T) {
		stopped := waitForCondition(2*time.Second, func() bool {
			return !isDNSServerRunning(dnsAddr)
		})
		assert.True(t, stopped, "DNS server should stop after detach")
	})
}

func TestDaemonAutoRemoveCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	cgroupPath := "/sys/fs/cgroup/netfence-daemon-autoremove-cgroup"
	err := os.MkdirAll(cgroupPath, 0755)
	require.NoError(t, err, "failed to create test cgroup")

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)

	dnsAddr := resp.DnsAddress
	require.True(t, isDNSServerRunning(dnsAddr), "DNS should be running before removal")

	listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.Attachments, 1, "should have one attachment before removal")

	require.NoError(t, os.Remove(cgroupPath), "failed to remove cgroup")

	t.Run("auto_cleanup", func(t *testing.T) {
		cleaned := waitForCondition(5*time.Second, func() bool {
			listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
			if err != nil {
				return false
			}
			return len(listResp.Attachments) == 0
		})
		assert.True(t, cleaned, "attachment should be auto-removed when cgroup is deleted")
	})

	t.Run("dns_server_stopped", func(t *testing.T) {
		stopped := waitForCondition(2*time.Second, func() bool {
			return !isDNSServerRunning(dnsAddr)
		})
		assert.True(t, stopped, "DNS server should stop after auto-removal")
	})
}

func TestDaemonAutoRemoveInterface(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	ifaceName := "nf-auto-test0"
	require.NoError(t, createDummyInterface(ifaceName))

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: ifaceName},
	})
	require.NoError(t, err)

	dnsAddr := resp.DnsAddress
	require.True(t, isDNSServerRunning(dnsAddr), "DNS should be running before removal")

	listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.Attachments, 1, "should have one attachment before removal")

	cmd := exec.Command("ip", "link", "del", ifaceName)
	require.NoError(t, cmd.Run(), "failed to delete interface")

	t.Run("auto_cleanup", func(t *testing.T) {
		cleaned := waitForCondition(5*time.Second, func() bool {
			listResp, err := ts.server.List(ctx, &apiv1.ListRequest{})
			if err != nil {
				return false
			}
			return len(listResp.Attachments) == 0
		})
		assert.True(t, cleaned, "attachment should be auto-removed when interface is deleted")
	})

	t.Run("dns_server_stopped", func(t *testing.T) {
		stopped := waitForCondition(2*time.Second, func() bool {
			return !isDNSServerRunning(dnsAddr)
		})
		assert.True(t, stopped, "DNS server should stop after auto-removal")
	})
}

func TestDaemonDNSServerResponds(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ts := newTestServer(t)
	defer ts.cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-daemon-dns-test")
	defer cgroupCleanup()

	ctx := context.Background()
	resp, err := ts.server.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)

	client := &dns.Client{Timeout: 5 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	reply, _, err := client.Exchange(msg, resp.DnsAddress)
	require.NoError(t, err, "DNS query should succeed")
	require.NotNil(t, reply, "should receive DNS response")

	t.Run("valid_response", func(t *testing.T) {
		assert.True(t, reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeRefused,
			"should receive valid DNS response code, got %s", dns.RcodeToString[reply.Rcode])
	})

	t.Run("udp_reachable", func(t *testing.T) {
		conn, err := net.DialTimeout("udp", resp.DnsAddress, 2*time.Second)
		require.NoError(t, err, "should be able to connect to DNS server")
		conn.Close()
	})
}
