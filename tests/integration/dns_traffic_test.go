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
	"strings"
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

const dnsExactTrafficChurnWindow = 10 * time.Second

type workloadDNSUpstream struct {
	addr       string
	answers    map[string][]string
	ttl        uint32
	udpQueries atomic.Uint64
	tcpQueries atomic.Uint64
}

func startWorkloadDNSUpstream(t *testing.T, answerIP string) *workloadDNSUpstream {
	return startWorkloadDNSUpstreamAnswers(t, map[string][]string{"": {answerIP}})
}

func startWorkloadDNSUpstreamAnswers(t *testing.T, answers map[string][]string) *workloadDNSUpstream {
	return startWorkloadDNSUpstreamAnswersTTL(t, answers, 60)
}

func startWorkloadDNSUpstreamAnswersTTL(t *testing.T, answers map[string][]string, ttl uint32) *workloadDNSUpstream {
	t.Helper()
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	tcpLn, err := net.Listen("tcp4", udpConn.LocalAddr().String())
	require.NoError(t, err)

	upstream := &workloadDNSUpstream{addr: udpConn.LocalAddr().String(), answers: answers, ttl: ttl}
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
				domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")
				answerIPs, ok := upstream.answers[domain]
				if !ok {
					answerIPs = upstream.answers[""]
				}
				for _, answerIP := range answerIPs {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: upstream.ttl},
						A:   net.ParseIP(answerIP).To4(),
					})
				}
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
	return newDNSWorkloadDaemonConfig(t, &config.Config{DNS: config.DNSConfig{
		ListenAddr: listenIP,
		PortMin:    portMin,
		PortMax:    portMax,
		Upstream:   globalUpstream,
	}})
}

func newDNSWorkloadDaemonConfig(t *testing.T, cfg *config.Config) *daemon.Server {
	t.Helper()
	st, err := store.New(":memory:")
	require.NoError(t, err)
	srv, err := daemon.NewServer(cfg, st, zerolog.New(io.Discard), "test")
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

type dnsExactTrafficMatrix struct {
	sharedIP, sharedPort     string
	workingIP, workingPort   string
	capacityIP, capacityPort string
	budgetIP, budgetPort     string
	flipIP, flipPort         string
	resolve                  func(domain, expectedIP string)
	resolveRcode             func(domain string, expectedRcode int)
	connect                  func(ip, port string) bool
}

func exerciseDNSExactOwnershipTraffic(t *testing.T, srv *daemon.Server, attachment *apiv1.AttachResponse, upstream *workloadDNSUpstream, matrix dnsExactTrafficMatrix) {
	t.Helper()
	allowDomains := []*apiv1.DomainEntry{
		{Domain: "owner-one.test"},
		{Domain: "owner-two.test"},
		{Domain: "working.test"},
		{Domain: "capacity.test"},
		{Domain: "budget.test"},
		{Domain: "mode-flip.test"},
	}
	require.NoError(t, srv.ReplaceDNSRules(attachment.Id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		allowDomains, nil, []string{upstream.addr}))
	require.NoError(t, srv.SetFilterMode(attachment.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))

	assert.False(t, matrix.connect(matrix.sharedIP, matrix.sharedPort), "unresolved shared destination must start blocked")
	assert.False(t, matrix.connect(matrix.workingIP, matrix.workingPort), "unresolved working destination must start blocked")

	budgetStarted := time.Now()
	matrix.resolve("owner-one.test", matrix.sharedIP)
	matrix.resolve("owner-two.test", matrix.sharedIP)
	matrix.resolve("working.test", matrix.workingIP)
	assert.True(t, matrix.connect(matrix.sharedIP, matrix.sharedPort))
	assert.True(t, matrix.connect(matrix.workingIP, matrix.workingPort))

	// Dropping one of two query owners keeps the shared exact key. Protected
	// control-plane allow and deny rules are installed before LRU pressure so
	// traffic can prove that neither independent LPM tier is reclaimed.
	require.NoError(t, srv.RemoveDomain(attachment.Id, "owner-one.test"))
	assert.True(t, matrix.connect(matrix.sharedIP, matrix.sharedPort), "the second query owner must keep the shared exact key")
	_, sharedCIDR, err := net.ParseCIDR(matrix.sharedIP + "/32")
	require.NoError(t, err)
	require.NoError(t, srv.AllowCIDR(attachment.Id, sharedCIDR, 0))
	_, workingCIDR, err := net.ParseCIDR(matrix.workingIP + "/32")
	require.NoError(t, err)
	require.NoError(t, srv.DenyCIDR(attachment.Id, workingCIDR, 0))

	// The exact tier is full with shared (oldest) and working. The first new
	// answer deterministically replaces shared for two physical churn units;
	// together with the two initial admissions this reaches the configured
	// four-unit ceiling. A second replacement is immediately throttled, returns
	// no address, and preserves the admitted pair.
	matrix.resolve("capacity.test", matrix.capacityIP)
	lastChargedAt := time.Now()
	matrix.resolveRcode("budget.test", dns.RcodeServerFailure)
	require.Less(t, time.Since(budgetStarted), dnsExactTrafficChurnWindow,
		"the throttle discriminator must run before any initial admission can age out of the rolling window")
	attachmentStats := requireDNSAttachmentStats(t, srv, attachment.Id)
	assert.Equal(t, uint32(2), attachmentStats.DnsExactIpv4Entries)
	assert.Equal(t, uint32(2), attachmentStats.DnsExactIpv4Capacity)
	assert.Equal(t, uint32(2), attachmentStats.DnsExactIpv4HighWater)
	assert.Equal(t, uint64(1), attachmentStats.DnsLruEvictions)
	assert.Equal(t, uint64(1), attachmentStats.DnsAdmissionFailures)
	assert.Equal(t, uint64(1), attachmentStats.DnsBudgetThrottles)
	assert.Zero(t, attachmentStats.MapFullDrops, "rolling budget pressure must not masquerade as map-full pressure")

	assert.True(t, matrix.connect(matrix.sharedIP, matrix.sharedPort),
		"the protected CP allow must survive eviction of the shared DNS exact key")
	assert.True(t, matrix.connect(matrix.workingIP, matrix.workingPort),
		"packet ALLOWLIST must still reach the non-evicted working exact key")
	assert.True(t, matrix.connect(matrix.capacityIP, matrix.capacityPort), "the successful replacement must be reachable")
	assert.False(t, matrix.connect(matrix.budgetIP, matrix.budgetPort), "the throttled answer must never become reachable")
	require.NoError(t, srv.SetFilterMode(attachment.Id, apiv1.PolicyMode_POLICY_MODE_DENYLIST))
	assert.False(t, matrix.connect(matrix.workingIP, matrix.workingPort),
		"packet DENYLIST must prove that the protected CP deny survived DNS LRU")
	require.NoError(t, srv.RemoveDeniedCIDR(attachment.Id, workingCIDR))
	assert.True(t, matrix.connect(matrix.workingIP, matrix.workingPort),
		"removing the protected deny must immediately restore DENYLIST default access")
	require.NoError(t, srv.SetFilterMode(attachment.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	assert.True(t, matrix.connect(matrix.workingIP, matrix.workingPort),
		"switching back to ALLOWLIST must reveal that the working exact key survived")

	// Removing the last stale query owner cannot disturb CP coverage. Removing
	// that CP allow then exposes that LRU already removed the exact key. The
	// non-evicted working exact key remains installed throughout these independent
	// LPM and packet-mode transitions.
	require.NoError(t, srv.RemoveDomain(attachment.Id, "owner-two.test"))
	assert.True(t, matrix.connect(matrix.sharedIP, matrix.sharedPort))
	require.NoError(t, srv.RemoveAllowedCIDR(attachment.Id, sharedCIDR))
	assert.False(t, matrix.connect(matrix.sharedIP, matrix.sharedPort))
	assert.True(t, matrix.connect(matrix.workingIP, matrix.workingPort))
	assert.True(t, matrix.connect(matrix.capacityIP, matrix.capacityPort))

	// Every charged event precedes lastChargedAt. Waiting one complete immutable
	// window from that captured post-commit instant is therefore sufficient on
	// slow CI without guessing how much setup time remains. The next answer is
	// admitted, evicts the now-oldest working key, and visibly recovers budget
	// service while cumulative failure counters remain stable.
	recoveryAt := lastChargedAt.Add(dnsExactTrafficChurnWindow + 500*time.Millisecond)
	if wait := time.Until(recoveryAt); wait > 0 {
		t.Logf("waiting %s for exact DNS churn-window recovery", wait.Round(time.Millisecond))
		time.Sleep(wait)
	}
	matrix.resolve("budget.test", matrix.budgetIP)
	assert.False(t, matrix.connect(matrix.workingIP, matrix.workingPort), "recovered replacement must evict the oldest exact key")
	assert.True(t, matrix.connect(matrix.capacityIP, matrix.capacityPort))
	assert.True(t, matrix.connect(matrix.budgetIP, matrix.budgetPort))
	attachmentStats = requireDNSAttachmentStats(t, srv, attachment.Id)
	assert.Equal(t, uint32(2), attachmentStats.DnsExactIpv4Entries)
	assert.Equal(t, uint32(2), attachmentStats.DnsExactIpv4HighWater)
	assert.Equal(t, uint64(2), attachmentStats.DnsLruEvictions)
	assert.Equal(t, uint64(1), attachmentStats.DnsAdmissionFailures)
	assert.Equal(t, uint64(1), attachmentStats.DnsBudgetThrottles)
	assert.Zero(t, attachmentStats.MapFullDrops)

	// DNS DENYLIST still maintains exact default-allow ownership even while
	// packet DENYLIST ignores that tier. Flipping packet policy to ALLOWLIST
	// must make the cached destination reachable without another query. Free a
	// slot first so this discriminator is independent of another pressure-plan
	// allowance in the just-recovered rolling window.
	require.NoError(t, srv.RemoveDomain(attachment.Id, "capacity.test"))
	require.NoError(t, srv.ReplaceDNSRules(attachment.Id, apiv1.DnsMode_DNS_MODE_DENYLIST,
		nil, nil, []string{upstream.addr}))
	require.NoError(t, srv.SetFilterMode(attachment.Id, apiv1.PolicyMode_POLICY_MODE_DENYLIST))
	queriesBeforeFlip := upstream.udpQueries.Load()
	matrix.resolve("mode-flip.test", matrix.flipIP)
	queriesAfterAnswer := upstream.udpQueries.Load()
	assert.Equal(t, queriesBeforeFlip+1, queriesAfterAnswer)
	require.NoError(t, srv.SetFilterMode(attachment.Id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	assert.True(t, matrix.connect(matrix.flipIP, matrix.flipPort),
		"packet ALLOWLIST must immediately consult the exact key admitted under DNS DENYLIST")
	assert.True(t, matrix.connect(matrix.budgetIP, matrix.budgetPort), "surviving ownership must remain reachable across the mode flip")
	assert.False(t, matrix.connect(matrix.capacityIP, matrix.capacityPort), "prompt policy removal must free the exact slot used by the mode-flip answer")
	assert.False(t, matrix.connect(matrix.workingIP, matrix.workingPort), "the recovered LRU replacement must remain effective")
	assert.False(t, matrix.connect(matrix.sharedIP, matrix.sharedPort), "packet ALLOWLIST must block the now-ownerless shared destination")
	assert.Equal(t, queriesAfterAnswer, upstream.udpQueries.Load(), "mode flip and connects must not rely on a DNS requery")
}

func requireDNSAttachmentStats(t testing.TB, srv *daemon.Server, id string) *apiv1.AttachmentStats {
	t.Helper()
	for _, stats := range srv.GetAttachmentStats() {
		if stats.Id == id {
			return stats
		}
	}
	t.Fatalf("attachment %s missing from stats", id)
	return nil
}

func dnsHelperEnvironment(server, domain, qtype, expectedIP string, expectedTXT int, expectTruncated bool, expectedRcode int) []string {
	return append(os.Environ(),
		dnsWorkloadHelperEnv+"=1",
		"NETFENCE_DNS_SERVER="+server,
		"NETFENCE_DNS_DOMAIN="+domain,
		"NETFENCE_DNS_QTYPE="+qtype,
		"NETFENCE_DNS_EXPECT_IP="+expectedIP,
		"NETFENCE_DNS_EXPECT_TXT="+strconv.Itoa(expectedTXT),
		"NETFENCE_DNS_EXPECT_TRUNCATED="+strconv.FormatBool(expectTruncated),
		"NETFENCE_DNS_EXPECT_RCODE="+strconv.Itoa(expectedRcode),
	)
}

func runDNSHelperInCgroup(t *testing.T, cgroupPath, server, domain, qtype, expectedIP string, expectedTXT int, expectTruncated bool) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `echo $$ > "$NETFENCE_CGROUP_PATH/cgroup.procs"; exec "$NETFENCE_TEST_BINARY" -test.run '^TestDNSWorkloadHelperProcess$' -test.count=1`)
	cmd.Env = append(dnsHelperEnvironment(server, domain, qtype, expectedIP, expectedTXT, expectTruncated, dns.RcodeSuccess),
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
	cmd.Env = dnsHelperEnvironment(server, domain, qtype, expectedIP, expectedTXT, expectTruncated, dns.RcodeSuccess)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "DNS workload helper failed in netns: %s", out)
}

func runDNSRcodeHelperInCgroup(t *testing.T, cgroupPath, server, domain string, expectedRcode int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `echo $$ > "$NETFENCE_CGROUP_PATH/cgroup.procs"; exec "$NETFENCE_TEST_BINARY" -test.run '^TestDNSWorkloadHelperProcess$' -test.count=1`)
	cmd.Env = append(dnsHelperEnvironment(server, domain, "A", "", 0, false, expectedRcode),
		"NETFENCE_CGROUP_PATH="+cgroupPath,
		"NETFENCE_TEST_BINARY="+os.Args[0],
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "DNS workload helper failed in cgroup: %s", out)
}

func runDNSRcodeHelperInNetns(t *testing.T, server, domain string, expectedRcode int) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", vethNetns, os.Args[0],
		"-test.run", "^TestDNSWorkloadHelperProcess$", "-test.count=1")
	cmd.Env = dnsHelperEnvironment(server, domain, "A", "", 0, false, expectedRcode)
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
	expectedRcode, err := strconv.Atoi(os.Getenv("NETFENCE_DNS_EXPECT_RCODE"))
	require.NoError(t, err)
	require.Equal(t, expectedRcode, resp.Rcode)
	if expectedRcode != dns.RcodeSuccess {
		return
	}

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

func TestCgroupDNSExactOwnershipLRUAndBudgetTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	const (
		listenerIP = "198.18.1.1"
		sharedIP   = "198.18.1.2"
		workingIP  = "198.18.1.3"
		capacityIP = "198.18.1.4"
		flipIP     = "198.18.1.5"
		budgetIP   = "198.18.1.6"
	)
	for _, ip := range []string{listenerIP, sharedIP, workingIP, capacityIP, flipIP, budgetIP} {
		_ = ipCmd("addr", "del", ip+"/32", "dev", "lo")
		require.NoError(t, ipCmd("addr", "add", ip+"/32", "dev", "lo"))
		ip := ip
		t.Cleanup(func() { _ = ipCmd("addr", "del", ip+"/32", "dev", "lo") })
	}
	sharedPort, closeShared := listenTCP(t, sharedIP)
	t.Cleanup(closeShared)
	workingPort, closeWorking := listenTCP(t, workingIP)
	t.Cleanup(closeWorking)
	capacityPort, closeCapacity := listenTCP(t, capacityIP)
	t.Cleanup(closeCapacity)
	budgetPort, closeBudget := listenTCP(t, budgetIP)
	t.Cleanup(closeBudget)
	flipPort, closeFlip := listenTCP(t, flipIP)
	t.Cleanup(closeFlip)

	upstream := startWorkloadDNSUpstreamAnswersTTL(t, map[string][]string{
		"owner-one.test": {sharedIP},
		"owner-two.test": {sharedIP},
		"working.test":   {workingIP},
		"capacity.test":  {capacityIP},
		"budget.test":    {budgetIP},
		"mode-flip.test": {flipIP},
	}, 300)
	cgroupPath, cleanupCgroup := setupTestCgroup(t, "netfence-dns-exact-ownership")
	t.Cleanup(cleanupCgroup)
	for ip, port := range map[string]string{
		sharedIP: sharedPort, workingIP: workingPort, capacityIP: capacityPort,
		budgetIP: budgetPort, flipIP: flipPort,
	} {
		require.True(t, runInCgroup(cgroupPath, ip+" "+port), "cgroup exact-ownership topology is broken for %s", ip)
	}
	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr:            listenerIP,
			PortMin:               32453,
			PortMax:               32453,
			Upstream:              upstream.addr,
			MaxIPsPerFamily:       2,
			MaxIPsPerResponse:     2,
			MaxIPsPerPolicyDomain: 2,
			MaxTrackedDomains:     16,
			MaxOwnershipEdges:     16,
			MaxChurnUnits:         4,
			ChurnWindow:           dnsExactTrafficChurnWindow,
		},
		Filter: config.FilterConfig{MaxDNSRuleEntries: 2},
	}
	require.NoError(t, cfg.Validate())
	srv := newDNSWorkloadDaemonConfig(t, cfg)
	attachment, err := srv.Attach(context.Background(), &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.Detach(context.Background(), &apiv1.DetachRequest{Id: attachment.Id})
	})

	exerciseDNSExactOwnershipTraffic(t, srv, attachment, upstream, dnsExactTrafficMatrix{
		sharedIP: sharedIP, sharedPort: sharedPort,
		workingIP: workingIP, workingPort: workingPort,
		capacityIP: capacityIP, capacityPort: capacityPort,
		budgetIP: budgetIP, budgetPort: budgetPort,
		flipIP: flipIP, flipPort: flipPort,
		resolve: func(domain, expectedIP string) {
			runDNSHelperInCgroup(t, cgroupPath, attachment.DnsAddress, domain, "A", expectedIP, 0, false)
		},
		resolveRcode: func(domain string, expectedRcode int) {
			runDNSRcodeHelperInCgroup(t, cgroupPath, attachment.DnsAddress, domain, expectedRcode)
		},
		connect: func(ip, port string) bool { return runInCgroup(cgroupPath, ip+" "+port) },
	})
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

func TestTCDNSExactOwnershipLRUAndBudgetTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	cleanupVeth := setupVethNetns(t)
	t.Cleanup(cleanupVeth)
	const (
		capacityIP = "10.199.0.6"
		flipIP     = "10.199.0.7"
		budgetIP   = "10.199.0.8"
	)
	for _, ip := range []string{capacityIP, flipIP, budgetIP} {
		require.NoError(t, ipCmd("addr", "add", ip+"/24", "dev", vethHostIf))
	}
	sharedPort, closeShared := listenTCP(t, vethAllowedIP)
	t.Cleanup(closeShared)
	workingPort, closeWorking := listenTCP(t, vethBlockedIP)
	t.Cleanup(closeWorking)
	capacityPort, closeCapacity := listenTCP(t, capacityIP)
	t.Cleanup(closeCapacity)
	budgetPort, closeBudget := listenTCP(t, budgetIP)
	t.Cleanup(closeBudget)
	flipPort, closeFlip := listenTCP(t, flipIP)
	t.Cleanup(closeFlip)
	for ip, port := range map[string]string{
		vethAllowedIP: sharedPort,
		vethBlockedIP: workingPort,
		capacityIP:    capacityPort,
		budgetIP:      budgetPort,
		flipIP:        flipPort,
	} {
		require.True(t, nsConnectTCP(ip, port), "TC exact-ownership topology is broken for %s", ip)
	}

	upstream := startWorkloadDNSUpstreamAnswersTTL(t, map[string][]string{
		"owner-one.test": {vethAllowedIP},
		"owner-two.test": {vethAllowedIP},
		"working.test":   {vethBlockedIP},
		"capacity.test":  {capacityIP},
		"budget.test":    {budgetIP},
		"mode-flip.test": {flipIP},
	}, 300)
	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr:            vethHostIP,
			PortMin:               32454,
			PortMax:               32454,
			Upstream:              upstream.addr,
			MaxIPsPerFamily:       2,
			MaxIPsPerResponse:     2,
			MaxIPsPerPolicyDomain: 2,
			MaxTrackedDomains:     16,
			MaxOwnershipEdges:     16,
			MaxChurnUnits:         4,
			ChurnWindow:           dnsExactTrafficChurnWindow,
		},
		Filter: config.FilterConfig{MaxDNSRuleEntries: 2},
	}
	require.NoError(t, cfg.Validate())
	srv := newDNSWorkloadDaemonConfig(t, cfg)
	attachment, err := srv.Attach(context.Background(), &apiv1.AttachRequest{
		Target:      &apiv1.AttachRequest_InterfaceName{InterfaceName: vethHostIf},
		TcDirection: apiv1.TcDirection_TC_DIRECTION_INGRESS,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.Detach(context.Background(), &apiv1.DetachRequest{Id: attachment.Id})
	})
	flushNeighbors(t, vethHostIf)

	exerciseDNSExactOwnershipTraffic(t, srv, attachment, upstream, dnsExactTrafficMatrix{
		sharedIP: vethAllowedIP, sharedPort: sharedPort,
		workingIP: vethBlockedIP, workingPort: workingPort,
		capacityIP: capacityIP, capacityPort: capacityPort,
		budgetIP: budgetIP, budgetPort: budgetPort,
		flipIP: flipIP, flipPort: flipPort,
		resolve: func(domain, expectedIP string) {
			runDNSHelperInNetns(t, attachment.DnsAddress, domain, "A", expectedIP, 0, false)
		},
		resolveRcode: func(domain string, expectedRcode int) {
			runDNSRcodeHelperInNetns(t, attachment.DnsAddress, domain, expectedRcode)
		},
		connect: nsConnectTCP,
	})
}
