//go:build linux

package integration

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	apiv1 "github.com/danthegoodman1/netfence/v1"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestResolverIsolationHelper(t *testing.T) {
	address := os.Getenv("NETFENCE_ISOLATION_ADDRESS")
	if address == "" {
		t.Skip("workload subprocess")
	}
	req := new(dns.Msg)
	req.SetQuestion(os.Getenv("NETFENCE_ISOLATION_DOMAIN")+".", dns.TypeA)
	for _, transport := range []string{"udp", "tcp"} {
		resp, _, err := (&dns.Client{Net: transport, Timeout: 200 * time.Millisecond}).Exchange(req, address)
		if os.Getenv("NETFENCE_ISOLATION_BLOCKED") == "true" {
			require.Error(t, err, "sibling %s endpoint must be unreachable", transport)
			continue
		}
		require.NoError(t, err)
		want, err := strconv.Atoi(os.Getenv("NETFENCE_ISOLATION_RCODE"))
		require.NoError(t, err)
		require.Equal(t, want, resp.Rcode)
	}
}

func runResolverIsolationQuery(t *testing.T, cgroup string, inNetns bool, address, domain string, blocked bool, rcode int) {
	t.Helper()
	var cmd *exec.Cmd
	if inNetns {
		cmd = exec.Command("ip", "netns", "exec", vethNetns, os.Args[0], "-test.run=^TestResolverIsolationHelper$", "-test.count=1")
	} else {
		cmd = exec.Command("sh", "-c", `echo $$ > "$NETFENCE_CGROUP_PATH/cgroup.procs"; exec "$NETFENCE_TEST_BINARY" -test.run '^TestResolverIsolationHelper$' -test.count=1`)
	}
	cmd.Env = append(os.Environ(), "NETFENCE_TEST_BINARY="+os.Args[0], "NETFENCE_CGROUP_PATH="+cgroup,
		"NETFENCE_ISOLATION_ADDRESS="+address, "NETFENCE_ISOLATION_DOMAIN="+domain,
		"NETFENCE_ISOLATION_BLOCKED="+strconv.FormatBool(blocked), "NETFENCE_ISOLATION_RCODE="+strconv.Itoa(rcode))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
}

func TestCgroupSiblingResolverIsolation(t *testing.T) { exerciseResolverIsolation(t, false) }
func TestTCSiblingResolverIsolation(t *testing.T)     { exerciseResolverIsolation(t, true) }

func exerciseResolverIsolation(t *testing.T, tc bool) {
	for _, v6 := range []bool{false, true} {
		name := "ipv4"
		if v6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			listenIP := "127.0.0.1"
			if v6 {
				listenIP = "::1"
			}
			if tc {
				t.Cleanup(setupVethNetns(t))
				listenIP = vethHostIP
				if v6 {
					setupVethIPv6(t)
					listenIP = vethHostIPv6
				}
			}
			upstream := startWorkloadDNSUpstream(t, "203.0.113.10")
			srv := newDNSWorkloadDaemon(t, listenIP, 34800, 34801, upstream.addr)
			aGroup, aCleanup := setupTestCgroup(t, "nf-isolation-a")
			t.Cleanup(aCleanup)
			bGroup, bCleanup := setupTestCgroup(t, "nf-isolation-b")
			t.Cleanup(bCleanup)
			aReq := &apiv1.AttachRequest{Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: aGroup}}
			if tc {
				aReq = &apiv1.AttachRequest{Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: vethHostIf}, TcDirection: apiv1.TcDirection_TC_DIRECTION_INGRESS}
			}
			a, err := srv.Attach(context.Background(), aReq)
			require.NoError(t, err)
			t.Cleanup(func() { srv.Detach(context.Background(), &apiv1.DetachRequest{Id: a.Id}) })
			bReq := &apiv1.AttachRequest{Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: bGroup}}
			b, err := srv.Attach(context.Background(), bReq)
			require.NoError(t, err)
			t.Cleanup(func() { srv.Detach(context.Background(), &apiv1.DetachRequest{Id: b.Id}) })
			require.NoError(t, srv.ReplaceDNSRules(a.Id, apiv1.DnsMode_DNS_MODE_ALLOWLIST, []*apiv1.DomainEntry{{Domain: "allowed.test"}}, nil))
			require.NoError(t, srv.SetFilterMode(a.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
			// A's own policy is effective; B's policy would forward the secret.
			runResolverIsolationQuery(t, aGroup, tc, a.DnsAddress, "allowed.test", false, dns.RcodeSuccess)
			runResolverIsolationQuery(t, aGroup, tc, a.DnsAddress, "secret.test", false, dns.RcodeRefused)
			runResolverIsolationQuery(t, bGroup, false, b.DnsAddress, "secret.test", false, dns.RcodeSuccess)
			before := upstream.udpQueries.Load() + upstream.tcpQueries.Load()
			runResolverIsolationQuery(t, aGroup, tc, b.DnsAddress, "secret.test", true, 0)
			require.Equal(t, before, upstream.udpQueries.Load()+upstream.tcpQueries.Load(), "forbidden query reached upstream")
			// A packet-policy change cannot disable the identity boundary.
			require.NoError(t, srv.SetFilterMode(a.Id, apiv1.PolicyMode_POLICY_MODE_DISABLED))
			runResolverIsolationQuery(t, aGroup, tc, b.DnsAddress, "secret.test", true, 0)
			oldAddr := b.DnsAddress
			_, err = srv.Detach(context.Background(), &apiv1.DetachRequest{Id: b.Id})
			require.NoError(t, err)
			b, err = srv.Attach(context.Background(), bReq)
			require.NoError(t, err)
			require.Equal(t, oldAddr, b.DnsAddress, "fixture must exercise port reuse")
			runResolverIsolationQuery(t, aGroup, tc, b.DnsAddress, "secret.test", true, 0)
			require.Equal(t, before, upstream.udpQueries.Load()+upstream.tcpQueries.Load())
			// Ensure the listener still works after overload-style failed access.
			runResolverIsolationQuery(t, aGroup, tc, a.DnsAddress, "allowed.test", false, dns.RcodeSuccess)
		})
	}
}
