//go:build linux

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/daemon"
	"github.com/danthegoodman1/netfence/internal/store"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// attachmentTest provides a unified interface for testing both cgroup and TC attachments.
type attachmentTest struct {
	t            *testing.T
	env          *e2eTestEnv
	attachmentID string
	target       string
	attachType   apiv1.AttachmentType
	runCmd       func(addr string) bool
	cleanup      func()
}

// attachmentSetupFunc creates an attachment and returns the test context.
type attachmentSetupFunc func(t *testing.T, env *e2eTestEnv, name string, cfg *apiv1.SubscribedAck) *attachmentTest

func setupCgroupAttachment(t *testing.T, env *e2eTestEnv, name string, cfg *apiv1.SubscribedAck) *attachmentTest {
	t.Helper()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-e2e-"+name)

	env.controlPlane.SetConfig(cgroupPath, cfg)

	ctx := context.Background()
	resp, err := env.daemonServer.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	return &attachmentTest{
		t:            t,
		env:          env,
		attachmentID: resp.Id,
		target:       cgroupPath,
		attachType:   apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP,
		runCmd:       func(addr string) bool { return runInCgroup(cgroupPath, addr) },
		cleanup:      cgroupCleanup,
	}
}

func setupTCAttachment(t *testing.T, env *e2eTestEnv, name string, cfg *apiv1.SubscribedAck) *attachmentTest {
	t.Helper()

	ifaceName := "nf-" + name
	require.NoError(t, createDummyInterface(ifaceName))

	env.controlPlane.SetConfig(ifaceName, cfg)

	ctx := context.Background()
	resp, err := env.daemonServer.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: ifaceName},
	})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	return &attachmentTest{
		t:            t,
		env:          env,
		attachmentID: resp.Id,
		target:       ifaceName,
		attachType:   apiv1.AttachmentType_ATTACHMENT_TYPE_TC,
		runCmd:       nil, // TC on dummy interface can't test real traffic
		cleanup:      func() { deleteDummyInterface(ifaceName) },
	}
}

func (at *attachmentTest) sendCommand(cmd *apiv1.ControlCommand) error {
	cmd.Id = at.attachmentID
	return at.env.controlPlane.SendCommand(at.attachmentID, cmd)
}

// dnsResponse configures how the test control plane responds to DNS queries.
type dnsResponse struct {
	Allow       bool
	AddToFilter bool
	IPs         []string
}

// testControlPlane is a minimal control plane server for end-to-end testing.
type testControlPlane struct {
	apiv1.UnimplementedControlPlaneServer

	mu            sync.RWMutex
	pendingConfig map[string]*apiv1.SubscribedAck
	streams       map[string]grpc.BidiStreamingServer[apiv1.DaemonEvent, apiv1.ControlCommand]
	dnsResponses  map[string]*dnsResponse // domain -> response
}

func newTestControlPlane() *testControlPlane {
	return &testControlPlane{
		pendingConfig: make(map[string]*apiv1.SubscribedAck),
		streams:       make(map[string]grpc.BidiStreamingServer[apiv1.DaemonEvent, apiv1.ControlCommand]),
		dnsResponses:  make(map[string]*dnsResponse),
	}
}

func (cp *testControlPlane) SetDnsResponse(domain string, resp *dnsResponse) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.dnsResponses[domain] = resp
}

func (cp *testControlPlane) SetConfig(target string, ack *apiv1.SubscribedAck) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.pendingConfig[target] = ack
}

func (cp *testControlPlane) SendCommand(attachmentID string, cmd *apiv1.ControlCommand) error {
	cp.mu.RLock()
	stream, ok := cp.streams[attachmentID]
	cp.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no stream for attachment %s", attachmentID)
	}
	return stream.Send(cmd)
}

func (cp *testControlPlane) Connect(stream grpc.BidiStreamingServer[apiv1.DaemonEvent, apiv1.ControlCommand]) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch e := event.Event.(type) {
		case *apiv1.DaemonEvent_Sync:
			if err := stream.Send(&apiv1.ControlCommand{
				Command: &apiv1.ControlCommand_SyncAck{SyncAck: &apiv1.SyncAck{}},
			}); err != nil {
				return err
			}

		case *apiv1.DaemonEvent_Subscribed:
			cp.mu.Lock()
			cp.streams[e.Subscribed.Id] = stream

			ack := cp.pendingConfig[e.Subscribed.Target]
			if ack == nil {
				ack = &apiv1.SubscribedAck{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED}
			}
			cp.mu.Unlock()

			if err := stream.Send(&apiv1.ControlCommand{
				Id:      e.Subscribed.Id,
				Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: ack},
			}); err != nil {
				return err
			}

		case *apiv1.DaemonEvent_Unsubscribed:
			cp.mu.Lock()
			delete(cp.streams, e.Unsubscribed.Id)
			cp.mu.Unlock()
		}
	}
}

func (cp *testControlPlane) QueryDns(ctx context.Context, req *apiv1.DnsQueryRequest) (*apiv1.DnsQueryResponse, error) {
	cp.mu.RLock()
	resp, ok := cp.dnsResponses[req.Domain]
	cp.mu.RUnlock()

	if !ok {
		return &apiv1.DnsQueryResponse{Allow: true}, nil
	}

	return &apiv1.DnsQueryResponse{
		Allow:       resp.Allow,
		AddToFilter: resp.AddToFilter,
		Ips:         resp.IPs,
	}, nil
}

type e2eTestEnv struct {
	controlPlane   *testControlPlane
	grpcServer     *grpc.Server
	grpcAddr       string
	daemonServer   *daemon.Server
	daemonStore    *store.Store
	cpClientCancel context.CancelFunc
	cleanupFuncs   []func()
}

func newE2ETestEnv(t *testing.T) *e2eTestEnv {
	t.Helper()

	cp := newTestControlPlane()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	apiv1.RegisterControlPlaneServer(grpcServer, cp)

	go grpcServer.Serve(listener)

	grpcAddr := listener.Addr().String()

	st, err := store.New(":memory:")
	require.NoError(t, err)

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    19000,
			PortMax:    29000,
			Upstream:   "8.8.8.8:53",
		},
		ControlPlane: config.ControlPlaneConfig{
			URL: grpcAddr,
		},
	}

	logger := zerolog.New(io.Discard)

	srv, err := daemon.NewServer(cfg, st, logger, "test")
	require.NoError(t, err)

	cpClient := daemon.NewControlPlaneClient(grpcAddr, srv, logger, nil, 5*time.Second)
	srv.SetControlPlaneClient(cpClient)

	require.NoError(t, srv.Start())

	cpCtx, cpCancel := context.WithCancel(context.Background())
	go cpClient.Run(cpCtx)

	require.Eventually(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 5*time.Second, 50*time.Millisecond, "control plane should connect")

	return &e2eTestEnv{
		controlPlane:   cp,
		grpcServer:     grpcServer,
		grpcAddr:       grpcAddr,
		daemonServer:   srv,
		daemonStore:    st,
		cpClientCancel: cpCancel,
	}
}

func (env *e2eTestEnv) cleanup() {
	for _, f := range env.cleanupFuncs {
		f()
	}
	env.cpClientCancel()
	env.daemonServer.Stop()
	env.grpcServer.Stop()
	env.daemonStore.Close()
}

// runE2ETests runs all E2E test scenarios for a given attachment type.
func runE2ETests(t *testing.T, typeName string, setup attachmentSetupFunc) {
	t.Run("BlockAll", func(t *testing.T) {
		testBlockAll(t, setup)
	})
	t.Run("Allowlist", func(t *testing.T) {
		testAllowlist(t, setup)
	})
	t.Run("Denylist", func(t *testing.T) {
		testDenylist(t, setup)
	})
	t.Run("CIDR", func(t *testing.T) {
		testCIDR(t, setup)
	})
	t.Run("ModeSwitch", func(t *testing.T) {
		testModeSwitch(t, setup)
	})
	t.Run("InitialConfig", func(t *testing.T) {
		testInitialConfig(t, setup)
	})
}

func TestE2E_Cgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	runE2ETests(t, "cgroup", setupCgroupAttachment)
}

func TestE2E_TC(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	runE2ETests(t, "tc", setupTCAttachment)
}

func testBlockAll(t *testing.T, setup attachmentSetupFunc) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := startTestServer(t)
	defer cleanup()

	env := newE2ETestEnv(t)
	defer env.cleanup()

	at := setup(t, env, "blockall", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL,
	})
	defer at.cleanup()

	if at.runCmd == nil {
		t.Log("Skipping traffic tests - attachment type doesn't support traffic testing")
		return
	}

	t.Run("IPv4_blocked", func(t *testing.T) {
		assert.False(t, at.runCmd(testServerNcV4), "expected IPv4 connection to be BLOCKED")
	})

	t.Run("IPv6_blocked", func(t *testing.T) {
		assert.False(t, at.runCmd(testServerNcV6), "expected IPv6 connection to be BLOCKED")
	})
}

func testAllowlist(t *testing.T, setup attachmentSetupFunc) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	env := newE2ETestEnv(t)
	defer env.cleanup()

	at := setup(t, env, "allowlist", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
	})
	defer at.cleanup()

	canTestTraffic := at.runCmd != nil

	t.Run("IPv4/add_to_allowlist", func(t *testing.T) {
		if canTestTraffic {
			assert.False(t, at.runCmd(googleDNSv4), "expected IPv4 connection to be BLOCKED (not in allowlist)")
		}

		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "8.8.8.8/32"}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.True(t, at.runCmd(googleDNSv4), "expected IPv4 connection to SUCCEED (in allowlist)")
		}
	})

	t.Run("IPv4/remove_from_allowlist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "8.8.8.8/32"},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.False(t, at.runCmd(googleDNSv4), "expected IPv4 connection to be BLOCKED (removed from allowlist)")
		}
	})

	if canTestTraffic {
		t.Run("IPv4/localhost_always_allowed", func(t *testing.T) {
			cleanup := startTestServer(t)
			defer cleanup()
			assert.True(t, at.runCmd(testServerNcV4), "expected IPv4 localhost to SUCCEED (always allowed)")
		})
	}

	t.Run("IPv6/add_to_allowlist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "2001:4860:4860::8888/128"}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic && hasIPv6() {
			assert.True(t, at.runCmd(googleDNSv6), "expected IPv6 connection to SUCCEED (in allowlist)")
		}
	})

	t.Run("IPv6/remove_from_allowlist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "2001:4860:4860::8888/128"},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic && hasIPv6() {
			assert.False(t, at.runCmd(googleDNSv6), "expected IPv6 connection to be BLOCKED (removed from allowlist)")
		}
	})
}

func testDenylist(t *testing.T, setup attachmentSetupFunc) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	env := newE2ETestEnv(t)
	defer env.cleanup()

	at := setup(t, env, "denylist", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST,
	})
	defer at.cleanup()

	canTestTraffic := at.runCmd != nil

	t.Run("IPv4/add_to_denylist", func(t *testing.T) {
		if canTestTraffic {
			assert.True(t, at.runCmd(googleDNSv4), "expected IPv4 connection to SUCCEED (not in denylist)")
		}

		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "8.8.8.8/32"}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.False(t, at.runCmd(googleDNSv4), "expected IPv4 connection to be BLOCKED (in denylist)")
		}
	})

	t.Run("IPv4/remove_from_denylist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "8.8.8.8/32"},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.True(t, at.runCmd(googleDNSv4), "expected IPv4 connection to SUCCEED (removed from denylist)")
		}
	})

	t.Run("IPv6/add_to_denylist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "2001:4860:4860::8888/128"}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic && hasIPv6() {
			assert.False(t, at.runCmd(googleDNSv6), "expected IPv6 connection to be BLOCKED (in denylist)")
		}
	})

	t.Run("IPv6/remove_from_denylist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "2001:4860:4860::8888/128"},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic && hasIPv6() {
			assert.True(t, at.runCmd(googleDNSv6), "expected IPv6 connection to SUCCEED (removed from denylist)")
		}
	})
}

func testCIDR(t *testing.T, setup attachmentSetupFunc) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	env := newE2ETestEnv(t)
	defer env.cleanup()

	at := setup(t, env, "cidr", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST,
	})
	defer at.cleanup()

	canTestTraffic := at.runCmd != nil

	t.Run("IPv4/deny_cidr_range", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "8.8.0.0/16"}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.False(t, at.runCmd("8.8.8.8 53"), "expected 8.8.8.8 to be BLOCKED (in denied /16)")
			assert.False(t, at.runCmd("8.8.4.4 53"), "expected 8.8.4.4 to be BLOCKED (in denied /16)")
			assert.True(t, at.runCmd(cloudflareDNSv4), "expected 1.1.1.1 to SUCCEED (not in denied range)")
		}

		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "8.8.0.0/16"},
		}))
	})

	t.Run("IPv6/deny_cidr_range", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "2001:4860::/32"}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic && hasIPv6() {
			assert.False(t, at.runCmd(googleDNSv6), "expected Google IPv6 DNS to be BLOCKED (in denied /32)")
			assert.True(t, at.runCmd(cloudflareDNSv6), "expected Cloudflare IPv6 DNS to SUCCEED (not in denied range)")
		}

		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "2001:4860::/32"},
		}))
	})
}

func testModeSwitch(t *testing.T, setup attachmentSetupFunc) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := startTestServer(t)
	defer cleanup()

	env := newE2ETestEnv(t)
	defer env.cleanup()

	at := setup(t, env, "modeswitch", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED,
	})
	defer at.cleanup()

	canTestTraffic := at.runCmd != nil

	t.Run("switch_to_block_all", func(t *testing.T) {
		if canTestTraffic {
			assert.True(t, at.runCmd(testServerNcV4), "IPv4 should succeed in disabled mode")
		}

		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.False(t, at.runCmd(testServerNcV4), "IPv4 should be blocked")
		}
	})

	t.Run("switch_to_allowlist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST}},
		}))
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("switch_to_denylist", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST}},
		}))
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("switch_back_to_disabled", func(t *testing.T) {
		require.NoError(t, at.sendCommand(&apiv1.ControlCommand{
			Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED}},
		}))
		time.Sleep(50 * time.Millisecond)

		if canTestTraffic {
			assert.True(t, at.runCmd(testServerNcV4), "IPv4 should succeed after switching back to disabled")
		}
	})
}

func testInitialConfig(t *testing.T, setup attachmentSetupFunc) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	env := newE2ETestEnv(t)
	defer env.cleanup()

	at := setup(t, env, "initconfig", &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: "8.8.8.8/32"},
		},
	})
	defer at.cleanup()

	canTestTraffic := at.runCmd != nil

	if canTestTraffic {
		t.Run("allowed_cidr_works_on_attach", func(t *testing.T) {
			assert.True(t, at.runCmd(googleDNSv4), "expected 8.8.8.8 to SUCCEED (pre-configured in allowlist)")
		})

		t.Run("other_cidr_blocked", func(t *testing.T) {
			assert.False(t, at.runCmd(cloudflareDNSv4), "expected 1.1.1.1 to be BLOCKED (not in allowlist)")
		})
	} else {
		t.Log("Initial config applied via SubscribedAck - traffic testing skipped for this attachment type")
	}
}

func TestE2E_DynamicDNS(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	env := newE2ETestEnv(t)
	defer env.cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-e2e-dns")
	defer cgroupCleanup()

	testDomain := "dns.google."
	testIP := "8.8.8.8"

	env.controlPlane.SetDnsResponse(testDomain, &dnsResponse{
		Allow:       true,
		AddToFilter: true,
		IPs:         []string{testIP},
	})

	env.controlPlane.SetConfig(cgroupPath, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		Dns:  &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_PROXY},
	})

	ctx := context.Background()
	resp, err := env.daemonServer.Attach(ctx, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)
	defer func() {
		env.daemonServer.Detach(ctx, &apiv1.DetachRequest{Id: resp.Id})
	}()

	time.Sleep(100 * time.Millisecond)

	t.Run("unresolved_ip_blocked", func(t *testing.T) {
		assert.False(t, runInCgroup(cgroupPath, "1.1.1.1 53"),
			"expected connection to unresolved IP to be BLOCKED")
	})

	t.Run("dns_resolution_allows_traffic", func(t *testing.T) {
		ips := queryDNS(t, resp.DnsAddress, testDomain)
		require.Len(t, ips, 1, "expected 1 IP from DNS response")
		assert.Equal(t, testIP, ips[0], "DNS should return IP from control plane")

		time.Sleep(50 * time.Millisecond)

		assert.True(t, runInCgroup(cgroupPath, testIP+" 53"),
			"expected connection to resolved IP to SUCCEED (added to filter)")
	})

	t.Run("dns_query_blocked_when_denied", func(t *testing.T) {
		blockedDomain := "blocked.example.com."
		env.controlPlane.SetDnsResponse(blockedDomain, &dnsResponse{
			Allow: false,
		})

		ips := queryDNS(t, resp.DnsAddress, blockedDomain)
		assert.Empty(t, ips, "expected no IPs for blocked domain")
	})
}

func queryDNS(t *testing.T, serverAddr, domain string) []string {
	t.Helper()

	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeA)

	r, _, err := c.Exchange(m, serverAddr)
	if err != nil {
		t.Logf("DNS query failed: %v", err)
		return nil
	}

	if r.Rcode == dns.RcodeRefused {
		return nil
	}

	var ips []string
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}
