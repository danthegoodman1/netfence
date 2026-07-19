//go:build linux

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
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

const dnsWorkloadHelperEnv = "NETFENCE_DNS_WORKLOAD_HELPER"

type workloadDNSUpstream struct {
	addr       string
	answerIP   string
	udpQueries atomic.Uint64
	tcpQueries atomic.Uint64
}

func startWorkloadDNSUpstream(t *testing.T, answerIP string) *workloadDNSUpstream {
	t.Helper()
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	tcpLn, err := net.Listen("tcp4", udpConn.LocalAddr().String())
	require.NoError(t, err)

	upstream := &workloadDNSUpstream{addr: udpConn.LocalAddr().String(), answerIP: answerIP}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		_, tcp := w.RemoteAddr().(*net.TCPAddr)
		if tcp {
			upstream.tcpQueries.Add(1)
		} else {
			upstream.udpQueries.Add(1)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(upstream.answerIP).To4(),
				})
			case dns.TypeTXT:
				if !tcp {
					resp.Truncated = true
					break
				}
				for i := 0; i < 30; i++ {
					resp.Answer = append(resp.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
						Txt: []string{fmt.Sprintf("large-answer-%02d-%064d", i, i)},
					})
				}
			}
		}
		_ = w.WriteMsg(resp)
	})
	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpLn, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return upstream
}

func newDNSWorkloadDaemon(t *testing.T, listenIP string, portMin, portMax int, globalUpstream string) *daemon.Server {
	t.Helper()
	st, err := store.New(":memory:")
	require.NoError(t, err)
	srv, err := daemon.NewServer(&config.Config{DNS: config.DNSConfig{
		ListenAddr: listenIP,
		PortMin:    portMin,
		PortMax:    portMax,
		Upstream:   globalUpstream,
	}}, st, zerolog.New(io.Discard), "test")
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() {
		srv.Stop()
		_ = st.Close()
	})
	return srv
}

func configureDNSWorkloadAttachment(t *testing.T, srv *daemon.Server, req *apiv1.AttachRequest, upstreams []string) *apiv1.AttachResponse {
	t.Helper()
	resp, err := srv.Attach(context.Background(), req)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.Detach(context.Background(), &apiv1.DetachRequest{Id: resp.Id})
	})
	require.NoError(t, srv.ReplaceDNSRules(resp.Id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{
			{Domain: "override.test"},
			{Domain: "large.test"},
		}, nil, upstreams))
	require.NoError(t, srv.SetFilterMode(resp.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	return resp
}

func dnsHelperEnvironment(server, domain, qtype, expectedIP string, expectedTXT int, expectTruncated bool) []string {
	return append(os.Environ(),
		dnsWorkloadHelperEnv+"=1",
		"NETFENCE_DNS_SERVER="+server,
		"NETFENCE_DNS_DOMAIN="+domain,
		"NETFENCE_DNS_QTYPE="+qtype,
		"NETFENCE_DNS_EXPECT_IP="+expectedIP,
		"NETFENCE_DNS_EXPECT_TXT="+strconv.Itoa(expectedTXT),
		"NETFENCE_DNS_EXPECT_TRUNCATED="+strconv.FormatBool(expectTruncated),
	)
}

func runDNSHelperInCgroup(t *testing.T, cgroupPath, server, domain, qtype, expectedIP string, expectedTXT int, expectTruncated bool) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `echo $$ > "$NETFENCE_CGROUP_PATH/cgroup.procs"; exec "$NETFENCE_TEST_BINARY" -test.run '^TestDNSWorkloadHelperProcess$' -test.count=1`)
	cmd.Env = append(dnsHelperEnvironment(server, domain, qtype, expectedIP, expectedTXT, expectTruncated),
		"NETFENCE_CGROUP_PATH="+cgroupPath,
		"NETFENCE_TEST_BINARY="+os.Args[0],
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "DNS workload helper failed in cgroup: %s", out)
}

func runDNSHelperInNetns(t *testing.T, server, domain, qtype, expectedIP string, expectedTXT int, expectTruncated bool) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", vethNetns, os.Args[0],
		"-test.run", "^TestDNSWorkloadHelperProcess$", "-test.count=1")
	cmd.Env = dnsHelperEnvironment(server, domain, qtype, expectedIP, expectedTXT, expectTruncated)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "DNS workload helper failed in netns: %s", out)
}

// TestDNSWorkloadHelperProcess is re-executed inside the target cgroup or
// network namespace so its UDP/TCP sockets traverse the real attached filter.
func TestDNSWorkloadHelperProcess(t *testing.T) {
	if os.Getenv(dnsWorkloadHelperEnv) != "1" {
		t.Skip("helper process")
	}
	qtype, ok := dns.StringToType[os.Getenv("NETFENCE_DNS_QTYPE")]
	require.True(t, ok)
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(os.Getenv("NETFENCE_DNS_DOMAIN")), qtype)

	udpResp, _, err := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(req, os.Getenv("NETFENCE_DNS_SERVER"))
	require.NoError(t, err)
	resp := udpResp
	expectTruncated, err := strconv.ParseBool(os.Getenv("NETFENCE_DNS_EXPECT_TRUNCATED"))
	require.NoError(t, err)
	if expectTruncated {
		require.True(t, udpResp.Truncated, "legacy UDP query must be truncated before workload TCP retry")
		resp, _, err = (&dns.Client{Net: "tcp", Timeout: 2 * time.Second}).Exchange(req, os.Getenv("NETFENCE_DNS_SERVER"))
		require.NoError(t, err)
		require.False(t, resp.Truncated)
	}
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)

	if expectedIP := os.Getenv("NETFENCE_DNS_EXPECT_IP"); expectedIP != "" {
		require.Len(t, resp.Answer, 1)
		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		require.Equal(t, expectedIP, a.A.String())
	}
	expectedTXT, err := strconv.Atoi(os.Getenv("NETFENCE_DNS_EXPECT_TXT"))
	require.NoError(t, err)
	if expectedTXT > 0 {
		require.Len(t, resp.Answer, expectedTXT)
		for _, answer := range resp.Answer {
			_, ok := answer.(*dns.TXT)
			require.True(t, ok)
		}
	}
}

func TestCgroupDaemonDNSWorkloadTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	const (
		listenerIP = "198.18.0.1"
		overrideIP = "198.18.0.2"
		blockedIP  = "198.18.0.3"
		fallbackIP = "198.18.0.4"
		dnsPortMin = 32450
		dnsPortMax = 32451
	)
	for _, ip := range []string{listenerIP, overrideIP, blockedIP, fallbackIP} {
		_ = ipCmd("addr", "del", ip+"/32", "dev", "lo")
		require.NoError(t, ipCmd("addr", "add", ip+"/32", "dev", "lo"))
		ip := ip
		t.Cleanup(func() { _ = ipCmd("addr", "del", ip+"/32", "dev", "lo") })
	}
	overridePort, closeOverride := listenTCP(t, overrideIP)
	t.Cleanup(closeOverride)
	blockedPort, closeBlocked := listenTCP(t, blockedIP)
	t.Cleanup(closeBlocked)
	fallbackPort, closeFallback := listenTCP(t, fallbackIP)
	t.Cleanup(closeFallback)

	global := startWorkloadDNSUpstream(t, fallbackIP)
	override := startWorkloadDNSUpstream(t, overrideIP)
	srv := newDNSWorkloadDaemon(t, listenerIP, dnsPortMin, dnsPortMax, global.addr)
	overrideCgroup, cleanupOverrideCgroup := setupTestCgroup(t, "netfence-dns-override-workload")
	t.Cleanup(cleanupOverrideCgroup)
	fallbackCgroup, cleanupFallbackCgroup := setupTestCgroup(t, "netfence-dns-fallback-workload")
	t.Cleanup(cleanupFallbackCgroup)
	for _, cgroupPath := range []string{overrideCgroup, fallbackCgroup} {
		require.True(t, runInCgroup(cgroupPath, overrideIP+" "+overridePort), "override topology must work before filter attach")
		require.True(t, runInCgroup(cgroupPath, fallbackIP+" "+fallbackPort), "fallback topology must work before filter attach")
		require.True(t, runInCgroup(cgroupPath, blockedIP+" "+blockedPort), "blocked-control topology must work before filter attach")
	}
	overrideResp := configureDNSWorkloadAttachment(t, srv, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: overrideCgroup},
	}, []string{override.addr})
	fallbackResp := configureDNSWorkloadAttachment(t, srv, &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: fallbackCgroup},
	}, nil)

	assert.False(t, runInCgroup(overrideCgroup, overrideIP+" "+overridePort), "unresolved override destination must start blocked")
	assert.False(t, runInCgroup(fallbackCgroup, fallbackIP+" "+fallbackPort), "unresolved fallback destination must start blocked")
	runDNSHelperInCgroup(t, overrideCgroup, overrideResp.DnsAddress, "override.test", "A", overrideIP, 0, false)
	assert.True(t, runInCgroup(overrideCgroup, overrideIP+" "+overridePort), "override DNS-admitted destination must become reachable")
	assert.False(t, runInCgroup(overrideCgroup, fallbackIP+" "+fallbackPort), "other attachment's destination must remain blocked")
	assert.False(t, runInCgroup(overrideCgroup, blockedIP+" "+blockedPort), "unrelated destination must remain blocked after override admission")
	assert.Zero(t, global.udpQueries.Load(), "non-empty per-attachment upstreams must bypass the daemon-global fallback")

	runDNSHelperInCgroup(t, fallbackCgroup, fallbackResp.DnsAddress, "override.test", "A", fallbackIP, 0, false)
	assert.True(t, runInCgroup(fallbackCgroup, fallbackIP+" "+fallbackPort), "empty upstream list must use global fallback and admit its answer")
	assert.False(t, runInCgroup(fallbackCgroup, overrideIP+" "+overridePort), "override attachment's destination must remain blocked")
	assert.False(t, runInCgroup(fallbackCgroup, blockedIP+" "+blockedPort), "unrelated destination must remain blocked after fallback admission")
	assert.GreaterOrEqual(t, global.udpQueries.Load(), uint64(1), "empty per-attachment upstream list must positively use the global fallback")

	overrideUDPBefore, overrideTCPBefore := override.udpQueries.Load(), override.tcpQueries.Load()
	globalUDPBefore, globalTCPBefore := global.udpQueries.Load(), global.tcpQueries.Load()
	runDNSHelperInCgroup(t, overrideCgroup, overrideResp.DnsAddress, "large.test", "TXT", "", 30, true)
	assert.GreaterOrEqual(t, override.udpQueries.Load()-overrideUDPBefore, uint64(2),
		"each workload UDP/TCP attempt must begin with the override upstream over UDP")
	assert.GreaterOrEqual(t, override.tcpQueries.Load()-overrideTCPBefore, uint64(2),
		"each truncated override UDP answer must retry against that same upstream over TCP")
	assert.Equal(t, globalUDPBefore, global.udpQueries.Load(), "override large query must not fall through to global UDP")
	assert.Equal(t, globalTCPBefore, global.tcpQueries.Load(), "override large query must not fall through to global TCP")
}

func TestTCDaemonDNSWorkloadTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	cleanupVeth := setupVethNetns(t)
	t.Cleanup(cleanupVeth)
	answerPort, closeAnswer := listenTCP(t, vethAllowedIP)
	t.Cleanup(closeAnswer)
	blockedPort, closeBlocked := listenTCP(t, vethBlockedIP)
	t.Cleanup(closeBlocked)
	require.True(t, nsConnectTCP(vethAllowedIP, answerPort), "allowed topology must work before filter attach")
	require.True(t, nsConnectTCP(vethBlockedIP, blockedPort), "blocked-control topology must work before filter attach")

	global := startWorkloadDNSUpstream(t, "192.0.2.20")
	override := startWorkloadDNSUpstream(t, vethAllowedIP)
	srv := newDNSWorkloadDaemon(t, vethHostIP, 32452, 32452, global.addr)
	resp := configureDNSWorkloadAttachment(t, srv, &apiv1.AttachRequest{
		Target:      &apiv1.AttachRequest_InterfaceName{InterfaceName: vethHostIf},
		TcDirection: apiv1.TcDirection_TC_DIRECTION_INGRESS,
	}, []string{override.addr})
	flushNeighbors(t, vethHostIf)

	assert.False(t, nsConnectTCP(vethAllowedIP, answerPort), "unresolved destination must start blocked")
	assert.False(t, nsConnectTCP(vethBlockedIP, blockedPort), "unrelated destination must start blocked")
	runDNSHelperInNetns(t, resp.DnsAddress, "override.test", "A", vethAllowedIP, 0, false)
	assert.True(t, nsConnectTCP(vethAllowedIP, answerPort), "DNS-admitted destination must become reachable")
	assert.False(t, nsConnectTCP(vethBlockedIP, blockedPort), "unrelated destination must remain blocked after DNS admission")
	overrideUDPBefore, overrideTCPBefore := override.udpQueries.Load(), override.tcpQueries.Load()
	runDNSHelperInNetns(t, resp.DnsAddress, "large.test", "TXT", "", 30, true)

	assert.Zero(t, global.udpQueries.Load(), "per-attachment upstream must override the daemon-global fallback")
	assert.Zero(t, global.tcpQueries.Load())
	assert.GreaterOrEqual(t, override.udpQueries.Load()-overrideUDPBefore, uint64(2),
		"each workload UDP/TCP attempt must begin with the override upstream over UDP")
	assert.GreaterOrEqual(t, override.tcpQueries.Load()-overrideTCPBefore, uint64(2),
		"each truncated override UDP answer must retry against that same upstream over TCP")
}
