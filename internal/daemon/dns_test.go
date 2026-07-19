package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// recordingSink is a fake exact-tier DNSFilterSink capturing each atomically
// admitted response address and TTL.
type recordingSink struct {
	mu    sync.Mutex
	cidrs []string
	ttls  []time.Duration
	err   error
}

func (r *recordingSink) BeginAdmission() (func(), error) { return func() {}, nil }

func (r *recordingSink) AdmitCanonicalResponse(req dnsCanonicalAdmissionRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	for _, record := range req.records {
		ip := normalizeIP(record.ip)
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		r.cidrs = append(r.cidrs, (&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}).String())
		r.ttls = append(r.ttls, record.ttl)
	}
	return nil
}

func (r *recordingSink) ReconcilePolicy(dnsAdmissionLimits, dnsChurnLimits, map[string]struct{}, dnsOwnershipResolver, bool) error {
	return nil
}
func (r *recordingSink) PreflightPolicy(dnsAdmissionLimits, dnsChurnLimits, map[string]struct{}, dnsOwnershipResolver, bool) error {
	return nil
}
func (r *recordingSink) Expire(time.Time) error                  { return nil }
func (r *recordingSink) SeedPinned() error                       { return nil }
func (r *recordingSink) ValidateLimits(dnsAdmissionLimits) error { return nil }
func (r *recordingSink) FailClosedIfAmbiguous(error) error       { return nil }
func (r *recordingSink) QuarantineAmbiguity(error) error         { return nil }

func (r *recordingSink) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *recordingSink) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cidrs)
}

func (r *recordingSink) entries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cidrs...)
}

func (r *recordingSink) requestedTTLs() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.ttls...)
}

type captureDNSWriter struct {
	msg *dns.Msg
}

func (w *captureDNSWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *captureDNSWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *captureDNSWriter) Close() error                { return nil }
func (w *captureDNSWriter) TsigStatus() error           { return nil }
func (w *captureDNSWriter) TsigTimersOnly(bool)         {}
func (w *captureDNSWriter) Hijack()                     {}
func (w *captureDNSWriter) Write([]byte) (int, error)   { return 0, errors.New("not implemented") }
func (w *captureDNSWriter) WriteMsg(msg *dns.Msg) error { w.msg = msg; return nil }

type failingDNSWriter struct {
	captureDNSWriter
}

type blockingDNSWriter struct {
	captureDNSWriter
	entered chan struct{}
	release <-chan struct{}
}

type blockingDeadlinePacketConn struct {
	mu                sync.Mutex
	deadlineCalls     int
	writeCalls        int
	firstWriteEntered chan struct{}
	firstWriteRelease <-chan struct{}
}

func (c *blockingDeadlinePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *blockingDeadlinePacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.writeCalls++
	call := c.writeCalls
	if call == 1 {
		close(c.firstWriteEntered)
	}
	c.mu.Unlock()
	if call == 1 {
		<-c.firstWriteRelease
	}
	return len(payload), nil
}

func (c *blockingDeadlinePacketConn) Close() error                    { return nil }
func (c *blockingDeadlinePacketConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (c *blockingDeadlinePacketConn) SetDeadline(time.Time) error     { return nil }
func (c *blockingDeadlinePacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *blockingDeadlinePacketConn) SetWriteDeadline(time.Time) error {
	c.mu.Lock()
	c.deadlineCalls++
	c.mu.Unlock()
	return nil
}

func (c *blockingDeadlinePacketConn) calls() (deadlines, writes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlineCalls, c.writeCalls
}

func (w *blockingDNSWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	close(w.entered)
	<-w.release
	return nil
}

func (w *failingDNSWriter) WriteMsg(*dns.Msg) error {
	return errors.New("injected response write failure")
}

func dnsQuery(domain string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	return msg
}
func queryServer(s *DNSServer, domain string, qtype uint16) *dns.Msg {
	writer := &captureDNSWriter{}
	s.handleDNS(writer, dnsQuery(domain, qtype))
	return writer.msg
}

func startTestUpstream(t testing.TB) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: conn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			for _, q := range req.Question {
				switch q.Qtype {
				case dns.TypeA:
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("203.0.113.10").To4(),
					})
				case dns.TypeAAAA:
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: net.ParseIP("2001:db8::10"),
					})
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return conn.LocalAddr().String()
}

func startDualProtocolUpstream(t testing.TB, handler dns.Handler) (string, *atomic.Uint64, *atomic.Uint64) {
	t.Helper()
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpLn, err := net.Listen("tcp", udpConn.LocalAddr().String())
	require.NoError(t, err)

	var udpQueries, tcpQueries atomic.Uint64
	counting := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			tcpQueries.Add(1)
		} else {
			udpQueries.Add(1)
		}
		handler.ServeDNS(w, req)
	})
	udpServer := &dns.Server{PacketConn: udpConn, Handler: counting}
	tcpServer := &dns.Server{Listener: tcpLn, Handler: counting}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return udpConn.LocalAddr().String(), &udpQueries, &tcpQueries
}

func freeDNSListenAddress(t testing.TB) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())
	return addr
}

func TestDNSServerDomainPolicySemantics(t *testing.T) {
	upstream := startTestUpstream(t)
	filter := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), filter, nil)
	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{
			{Domain: "Example.COM.", IncludeSubdomains: true},
			{Domain: "allowed.bad.example.com", IncludeSubdomains: true},
			{Domain: "tie.example.com"},
			{Domain: "nosubs.other.com"},
		},
		[]*apiv1.DomainEntry{
			{Domain: "bad.example.com", IncludeSubdomains: true},
			{Domain: "tie.example.com"},
		},
	)

	tests := []struct {
		name   string
		domain string
		want   domainDecision
	}{
		{name: "case and trailing dot normalize", domain: "WWW.EXAMPLE.COM.", want: domainDecisionAllow},
		{name: "more specific deny beats parent allow", domain: "deep.bad.example.com", want: domainDecisionDeny},
		{name: "more specific allow beats parent deny", domain: "deep.allowed.bad.example.com", want: domainDecisionAllow},
		{name: "deny wins exact tie", domain: "tie.example.com", want: domainDecisionDeny},
		{name: "exact allow without subdomains", domain: "nosubs.other.com", want: domainDecisionAllow},
		{name: "subdomain excluded without includeSubdomains", domain: "child.nosubs.other.com", want: domainDecisionNone},
		{name: "unknown", domain: "unknown.test", want: domainDecisionNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.mu.RLock()
			got := server.evaluateDomainLocked(tt.domain)
			server.mu.RUnlock()
			assert.Equal(t, tt.want, got)
		})
	}

	resp := queryServer(server, "unknown.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)

	resp = queryServer(server, "www.example.com", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Equal(t, []string{"203.0.113.10/32"}, filter.entries())

	server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DENYLIST, nil, []*apiv1.DomainEntry{{Domain: "blocked.test", IncludeSubdomains: true}})
	resp = queryServer(server, "blocked.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)

	resp = queryServer(server, "unknown.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

func TestDNSRootDomainNormalizationAndPolicySemantics(t *testing.T) {
	normalized, err := validateAndNormalizeDomain(".")
	require.NoError(t, err)
	assert.Equal(t, ".", normalized)

	exactRoot := map[string]bool{".": false}
	decision, owner := evaluateDomainRules(".", exactRoot, nil)
	assert.Equal(t, domainDecisionAllow, decision)
	assert.Equal(t, ".", owner)
	decision, owner = evaluateDomainRules("example", exactRoot, nil)
	assert.Equal(t, domainDecisionNone, decision)
	assert.Empty(t, owner, "a root rule without include_subdomains is exact-only")

	rootAndDescendants := map[string]bool{".": true}
	decision, owner = evaluateDomainRules("deep.example.", rootAndDescendants, nil)
	assert.Equal(t, domainDecisionAllow, decision)
	assert.Equal(t, ".", owner, "suffix evaluation must reach the root after the TLD")
	decision, owner = evaluateDomainRules(".", rootAndDescendants, map[string]bool{".": false})
	assert.Equal(t, domainDecisionDeny, decision, "deny still wins an exact root tie")
	assert.Equal(t, ".", owner)
}

func TestDNSEscapedLabelPolicySuffixesAreNotAuthorizationBoundaries(t *testing.T) {
	allowed := map[string]bool{"allowed.example": true}
	denied := map[string]bool{"allowed.example": true}

	decision, owner := evaluateDomainRules(`evil\.allowed.example.`, allowed, nil)
	assert.Equal(t, domainDecisionNone, decision,
		"an escaped literal dot must not manufacture an allowed parent label")
	assert.Empty(t, owner)
	decision, owner = evaluateDomainRules(`evil\.allowed.example.`, nil, denied)
	assert.Equal(t, domainDecisionNone, decision,
		"an escaped literal dot must not manufacture a denied parent label")
	assert.Empty(t, owner)

	decision, owner = evaluateDomainRules("evil.allowed.example.", allowed, nil)
	assert.Equal(t, domainDecisionAllow, decision)
	assert.Equal(t, "allowed.example", owner,
		"a real label boundary must still select the normalized parent owner")
	decision, owner = evaluateDomainRules("evil.allowed.example.", allowed, denied)
	assert.Equal(t, domainDecisionDeny, decision, "deny must still win at the real parent")
	assert.Equal(t, "allowed.example", owner)

	normalized, err := validateAndNormalizeDomain(`literal\.`)
	require.NoError(t, err)
	assert.Equal(t, `literal\.`, normalized,
		"a terminal escaped dot belongs to the label and is not an FQDN root separator")
}

func TestDNSWireCanonicalAliasesSelectOnePolicyAndOwnershipKey(t *testing.T) {
	tests := []struct {
		name  string
		rule  string
		query string
	}{
		{name: "encoded ascii and case", rule: `\066AD.Example`, query: "bad.example."},
		{name: "literal dot", rule: `BAD\046Name.Example`, query: `bad\.name.example.`},
		{name: "literal backslash", rule: `BAD\092Name.Example`, query: `bad\\name.example.`},
		{name: "literal space", rule: `BAD\032Name.Example`, query: `bad\ name.example.`},
		{name: "utf8 bytes", rule: "café.example", query: `caf\195\169.example.`},
	}
	limits := dnsAdmissionLimits{
		maxIPsPerFamily:       2,
		maxIPsPerResponse:     1,
		maxIPsPerPolicyDomain: 1,
		maxTrackedDomains:     1,
		maxOwnershipEdges:     1,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalRule, err := validateAndNormalizeDomain(tt.rule)
			require.NoError(t, err)
			canonicalQuery, err := validateAndNormalizeDomain(tt.query)
			require.NoError(t, err)
			require.Equal(t, canonicalRule, canonicalQuery,
				"wire-equivalent presentation spellings must share one key")

			server := NewDNSServer("canonical", "127.0.0.1:0", "127.0.0.1:53", zerolog.Nop(), nil, nil)
			require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
				[]*apiv1.DomainEntry{{Domain: tt.rule}}, nil))
			snapshot, shouldResolve, err := server.snapshotQuery(tt.query)
			require.NoError(t, err)
			assert.True(t, shouldResolve)
			assert.False(t, snapshot.blocked)
			assert.Equal(t, canonicalRule, snapshot.queryDomain)
			assert.Equal(t, dnsPolicyOwner{kind: dnsOwnerRule, domain: canonicalRule}, snapshot.owner)

			require.NoError(t, server.RemoveDomain(tt.query),
				"an alternate wire-equivalent spelling must remove the canonical rule")
			_, shouldResolve, err = server.snapshotQuery(tt.query)
			require.NoError(t, err)
			assert.False(t, shouldResolve)

			require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DENYLIST,
				nil, []*apiv1.DomainEntry{{Domain: tt.rule}}))
			snapshot, shouldResolve, err = server.snapshotQuery(tt.query)
			require.NoError(t, err)
			assert.False(t, shouldResolve)
			assert.True(t, snapshot.blocked,
				"an exact deny must match every wire-equivalent presentation spelling")
			decision, owner := evaluateCanonicalDomainRules(canonicalQuery,
				server.allowedDomains, server.deniedDomains)
			assert.Equal(t, domainDecisionDeny, decision)
			assert.Equal(t, canonicalRule, owner)

			prepared, err := prepareDNSRules(apiv1.DnsMode_DNS_MODE_DENYLIST,
				[]*apiv1.DomainEntry{{Domain: tt.rule}},
				[]*apiv1.DomainEntry{{Domain: tt.query}}, nil, "127.0.0.1:53", limits,
				dnsAdmissionLimitOverrides{}, resolveDNSChurnCeiling(0, 0), 0)
			require.NoError(t, err)
			assert.Equal(t, map[string]struct{}{canonicalRule: {}}, prepared.policyDomains,
				"the tracked-domain cap must count wire aliases once")
			_, err = prepareDNSRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
				[]*apiv1.DomainEntry{{Domain: tt.rule}, {Domain: tt.query}}, nil,
				nil, "127.0.0.1:53", limits, dnsAdmissionLimitOverrides{}, resolveDNSChurnCeiling(0, 0), 0)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "duplicate canonical DNS allow domain")

			ff := &fakeFilter{dnsCapacity4: 2, dnsCapacity6: 2}
			manager, err := newDNSOwnershipManager(ff, limits, time.Second, time.Now)
			require.NoError(t, err)
			ip := net.ParseIP("192.0.2.70")
			for _, admission := range []dnsAdmissionRequest{
				{
					queryDomain: tt.rule,
					owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: tt.rule},
					records:     []dnsAdmissionRecord{{ip: ip, ttl: time.Minute}},
				},
				{
					queryDomain: tt.query,
					owner:       dnsPolicyOwner{kind: dnsOwnerRule, domain: tt.query},
					records:     []dnsAdmissionRecord{{ip: ip, ttl: 2 * time.Minute}},
				},
			} {
				require.NoError(t, manager.admit(admission))
			}
			assert.Equal(t, map[string]uint64{canonicalRule: 1}, manager.queryRefs)
			assert.Equal(t, uint64(1), manager.edgeCount)
			canonicalOwner := dnsPolicyOwner{kind: dnsOwnerRule, domain: canonicalRule}
			assert.Len(t, manager.ownerIPRefs, 1)
			assert.Equal(t, 1, manager.ownerIPRefs[canonicalOwner].uniqueLen())
			entry := manager.entries[netipMustParse(t, "192.0.2.70")]
			_, owned := entry.owners.get(dnsOwnershipKey{query: canonicalRule, owner: canonicalOwner})
			assert.True(t, owned)
			_, addCalls := ff.dnsSnapshot()
			assert.Equal(t, 1, addCalls, "alias refresh must not consume another physical key")
			assertDNSOwnershipIndexes(t, manager)
		})
	}
}

func TestDNSWireCanonicalDomainSyntaxAndLengthBoundaries(t *testing.T) {
	label := func(length int) string { return strings.Repeat("a", length) }
	maxName := strings.Join([]string{label(63), label(63), label(63), label(61)}, ".")
	canonical, err := validateAndNormalizeDomain(maxName)
	require.NoError(t, err)
	assert.Equal(t, maxName, canonical)
	canonicalFQDN, err := validateAndNormalizeDomain(maxName + ".")
	require.NoError(t, err)
	assert.Equal(t, canonical, canonicalFQDN)

	escapedLabel := func(length int) string { return strings.Repeat(`\001`, length) }
	escapedMax := strings.Join([]string{escapedLabel(63), escapedLabel(63), escapedLabel(63), escapedLabel(61)}, ".")
	escapedCanonical, err := validateAndNormalizeDomain(escapedMax)
	require.NoError(t, err)
	assert.Equal(t, escapedMax, escapedCanonical,
		"maximum wire name must remain valid even with a much longer escaped presentation")

	for _, tooLong := range []string{
		strings.Join([]string{label(63), label(63), label(63), label(62)}, "."),
		strings.Join([]string{escapedLabel(63), escapedLabel(63), escapedLabel(63), escapedLabel(62)}, "."),
	} {
		var boundaryErr error
		assert.NotPanics(t, func() {
			_, boundaryErr = validateAndNormalizeDomain(tooLong)
		}, "a one-byte-over wire name must return an error, never slice past the pack buffer")
		require.Error(t, boundaryErr)
	}

	for _, malformed := range []string{"", "..", "a..", "example..", strings.Repeat("a", 64) + ".example"} {
		_, err := validateAndNormalizeDomain(malformed)
		require.Error(t, err, "malformed presentation %q must be rejected before canonicalization", malformed)
	}

	aliases := [][2]string{
		{`literal\046`, `literal\.`},
		{`literal\092`, `literal\\`},
		{`literal\032`, "literal "},
		{`\032literal\032`, " literal "},
		{`literal\.`, `literal\..`},
		{`literal\\`, `literal\\.`},
		{`literal\ `, `literal\ .`},
	}
	for _, pair := range aliases {
		left, err := validateAndNormalizeDomain(pair[0])
		require.NoError(t, err)
		right, err := validateAndNormalizeDomain(pair[1])
		require.NoError(t, err)
		assert.Equal(t, left, right)
	}
	spaced, err := validateAndNormalizeDomain(" name ")
	require.NoError(t, err)
	plain, err := validateAndNormalizeDomain("name")
	require.NoError(t, err)
	assert.NotEqual(t, plain, spaced, "boundary whitespace is a DNS label byte, not trim padding")
}

func TestDNSRootQueriesPassThroughAndDefaultDenylistOwnsAddresses(t *testing.T) {
	upstream, queries, _ := startDualProtocolUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		switch q.Qtype {
		case dns.TypeNS:
			resp.Answer = append(resp.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "a.root.test.",
			})
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.60").To4(),
			})
		}
		_ = w.WriteMsg(resp)
	}))
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)

	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DISABLED,
		nil, nil, []string{upstream}))
	resp := queryServer(dnsServer, ".", dns.TypeNS)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
	_, ok := resp.Answer[0].(*dns.NS)
	assert.True(t, ok)
	assert.Equal(t, uint64(1), queries.Load(), "disabled root query must reach the upstream")
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed, "disabled pass-through must not populate the exact tier")

	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST,
		nil, nil, []string{upstream}))
	resp = queryServer(dnsServer, ".", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, uint64(2), queries.Load(), "default-allowed root query must reach the upstream")
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Equal(t, []string{"192.0.2.60"}, dnsAllowed)

	manager := server.attachments[id].dnsSink.manager
	addr := netipMustParse(t, "192.0.2.60")
	entry, exists := manager.entries[addr]
	require.True(t, exists)
	rootEdge := dnsOwnershipKey{
		query: ".",
		owner: dnsPolicyOwner{kind: dnsOwnerDenylistDefault, domain: "."},
	}
	_, owned := entry.owners.get(rootEdge)
	assert.True(t, owned, "root must remain representable in the ownership graph")
	assertDNSOwnershipIndexes(t, manager)
}

func TestDNSServerProxyFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		proxyFunc DnsProxyFunc
	}{
		{name: "nil proxy", proxyFunc: nil},
		{name: "proxy error", proxyFunc: func(context.Context, string, string) (DnsProxyDecision, error) {
			return DnsProxyDecision{}, errors.New("control plane down")
		}},
		{name: "disconnected control plane proxy", proxyFunc: NewControlPlaneClient("", nil, zerolog.Nop(), nil, 0, nil).MakeProxyFunc("att-1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &recordingSink{}
			server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), filter, tt.proxyFunc)
			server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

			resp := queryServer(server, "example.com", dns.TypeA)
			require.NotNil(t, resp)
			assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
			assert.Zero(t, filter.calls())
			_, blocked, queryErrors := server.Stats()
			assert.Zero(t, blocked)
			assert.Equal(t, uint64(1), queryErrors)
		})
	}
}

func TestDNSServerProxyExplicitDenyRefuses(t *testing.T) {
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, func(context.Context, string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{Allow: false}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

	resp := queryServer(server, "blocked.test", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
}

func TestDNSProxyReceivesCanonicalFQDNAndPreservesResponseNames(t *testing.T) {
	const original = `MiXeD\046Label.Example.`
	var policyDomain, policyType string
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), sink,
		func(_ context.Context, domain, queryType string) (DnsProxyDecision, error) {
			policyDomain, policyType = domain, queryType
			return DnsProxyDecision{
				Allow:       true,
				AddToFilter: true,
				IPs:         []string{"192.0.2.71"},
				TTLSeconds:  60,
			}, nil
		})
	require.NoError(t, server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY))

	req := dnsQuery(original, dns.TypeA)
	w := &captureDNSWriter{}
	server.handleDNS(w, req)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	canonical, err := validateAndNormalizeDomain(original)
	require.NoError(t, err)
	assert.Equal(t, dns.Fqdn(canonical), policyDomain,
		"control-plane policy and local ownership must receive the same canonical identity")
	assert.Equal(t, "A", policyType)
	require.Len(t, w.msg.Question, 1)
	assert.Equal(t, req.Question[0].Name, w.msg.Question[0].Name,
		"canonical policy handoff must not rewrite the client-visible question")
	require.Len(t, w.msg.Answer, 1)
	assert.Equal(t, req.Question[0].Name, w.msg.Answer[0].Header().Name,
		"canonical policy handoff must not rewrite the synthesized RR owner name")
	assert.Equal(t, []string{"192.0.2.71/32"}, sink.entries())
}

func TestDNSServerProxyResponseHonorsTTLQueryTypeAndFiltering(t *testing.T) {
	filter := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), filter, func(context.Context, string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{
			Allow:       true,
			AddToFilter: true,
			IPs:         []string{"198.51.100.10", "2001:db8::1"},
			TTLSeconds:  42,
		}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

	resp := queryServer(server, "example.com", dns.TypeA)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, uint32(42), a.Hdr.Ttl)
	assert.Equal(t, "198.51.100.10", a.A.String())
	assert.Equal(t, []string{"198.51.100.10/32"}, filter.entries())

	resp = queryServer(server, "example.com", dns.TypeAAAA)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	require.True(t, ok)
	assert.Equal(t, uint32(42), aaaa.Hdr.Ttl)
	assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	assert.Equal(t, []string{"198.51.100.10/32", "2001:db8::1/128"}, filter.entries())

	noFilter := &recordingSink{}
	server = NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), noFilter, func(context.Context, string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{Allow: true, AddToFilter: false, IPs: []string{"198.51.100.11"}}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)

	resp = queryServer(server, "example.com", dns.TypeA)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	assert.Empty(t, resp.Answer, "filtering PROXY mode cannot return an address it was told not to admit")
	assert.Zero(t, noFilter.calls())
}

// TestDNSServerForwardsEveryResolutionToSink: with the old per-server ipCache
// gone, the DNS server forwards every resolution (with the record TTL) to the
// sink, which owns dedup, the TTL floor, and janitor-driven expiry (see the
// ownership-manager tests in dns_ownership_test.go). This internal helper's
// explicit ttlSeconds=0 retains its historical 300s default; production
// upstream RR TTL=0 reaches the manager as zero and is floored to min_filter_ttl.
func TestDNSServerForwardsEveryResolutionToSink(t *testing.T) {
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), sink, nil)

	ip := net.ParseIP("203.0.113.77")
	server.addIPToFilter("example.com", ip, 32, 60)
	server.addIPToFilter("example.com", ip, 32, 0)
	assert.Equal(t, 2, sink.calls())
	assert.Equal(t, []string{"203.0.113.77/32", "203.0.113.77/32"}, sink.entries())
	assert.Equal(t, []time.Duration{
		60 * time.Second,
		time.Duration(defaultDNSTTLSeconds) * time.Second,
	}, sink.requestedTTLs())
}

func TestDNSServerStopClosesSocketAndAllowsRebind(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())

	server := NewDNSServer("att-1", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	require.NoError(t, server.Start())
	require.NoError(t, server.Stop())
	require.NoError(t, server.Stop())

	server = NewDNSServer("att-2", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	require.NoError(t, server.Start())
	require.NoError(t, server.Stop())
}

func TestDNSServerServesTCPAndRetriesTruncatedUpstream(t *testing.T) {
	upstream, udpQueries, tcpQueries := startDualProtocolUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
			resp.Truncated = true
			_ = w.WriteMsg(resp)
			return
		}
		for i := 0; i < 30; i++ {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{strings.Repeat("x", 40)},
			})
		}
		_ = w.WriteMsg(resp)
	}))
	var fallbackQueries atomic.Uint64
	fallback := startCountingUpstream(t, &fallbackQueries, dns.RcodeSuccess, "192.0.2.200")

	listen := freeDNSListenAddress(t)
	server := NewDNSServer("att-1", listen, upstream, zerolog.Nop(), nil, nil)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil, []string{upstream, fallback}))
	require.NoError(t, server.Start())
	t.Cleanup(func() { require.NoError(t, server.Stop()) })

	legacyReq := dnsQuery("large.example", dns.TypeTXT)
	udpResp, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(legacyReq, listen)
	require.NoError(t, err)
	assert.True(t, udpResp.Truncated, "a legacy request without OPT must default to 512 bytes and carry TC")
	// Unpack cannot retain whether the wire used name compression. Re-enable
	// the same compression used by Truncate/WriteMsg before measuring the
	// equivalent on-wire payload.
	udpResp.Compress = true
	assert.LessOrEqual(t, udpResp.Len(), dns.MinMsgSize, "TC response must also fit the workload's advertised UDP size")

	ednsReq := dnsQuery("large.example", dns.TypeTXT)
	ednsReq.SetEdns0(700, false)
	ednsResp, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(ednsReq, listen)
	require.NoError(t, err)
	assert.True(t, ednsResp.Truncated)
	ednsResp.Compress = true
	assert.LessOrEqual(t, ednsResp.Len(), 700)

	tcpResp, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(legacyReq, listen)
	require.NoError(t, err)
	assert.False(t, tcpResp.Truncated)
	assert.Len(t, tcpResp.Answer, 30)
	assert.GreaterOrEqual(t, udpQueries.Load(), uint64(2))
	assert.GreaterOrEqual(t, tcpQueries.Load(), uint64(2), "each upstream TC response must retry over TCP")
	assert.Zero(t, fallbackQueries.Load(), "TCP must be retried against the same upstream before ordered failover")
}

func TestDNSUDPWriterRespectsAdvertisedEDNSSize(t *testing.T) {
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, nil)
	req := dnsQuery("large.example", dns.TypeTXT)
	req.SetEdns0(700, false)
	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := 0; i < 30; i++ {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{strings.Repeat("x", 40)},
		})
	}
	writer := &captureDNSWriter{}
	server.writeOutcome(writer, req, resp, dnsOutcomeAllowed)
	require.NotNil(t, writer.msg)
	assert.True(t, writer.msg.Truncated)
	wire, err := writer.msg.Pack()
	require.NoError(t, err)
	assert.LessOrEqual(t, len(wire), 700)
}

func TestExchangeUpstreamsNeverReturnsTruncatedAnswerWhenTCPRetryFails(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Truncated = true
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	resp, err := exchangeUpstreams(context.Background(), dnsQuery("truncated.example", dns.TypeA), []string{conn.LocalAddr().String()})
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestDNSServerStartRollsBackUDPWhenTCPBindFails(t *testing.T) {
	tcpBlocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpBlocker.Close() })
	addr := tcpBlocker.Addr().String()

	server := NewDNSServer("att-1", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	require.ErrorContains(t, server.Start(), "binding TCP")
	udp, err := net.ListenPacket("udp", addr)
	require.NoError(t, err, "failed dual-protocol startup must not leak the UDP listener")
	require.NoError(t, udp.Close())
	require.NoError(t, server.Stop())
}

func TestDNSServerPerAttachmentUpstreamsAndOrderedFailover(t *testing.T) {
	makeUpstream := func(ip string) string {
		return startTestUpstreamWithIP(t, ip)
	}
	global := makeUpstream("192.0.2.10")
	override := makeUpstream("192.0.2.20")
	server := NewDNSServer("att-1", "127.0.0.1:0", global, zerolog.Nop(), nil, nil)

	resp := queryServer(server, "upstream.example", dns.TypeA)
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, "192.0.2.10", resp.Answer[0].(*dns.A).A.String())

	dead := freeDNSListenAddress(t)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil, []string{dead, override}))
	resp = queryServer(server, "upstream.example", dns.TypeA)
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, "192.0.2.20", resp.Answer[0].(*dns.A).A.String())

	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil, nil))
	resp = queryServer(server, "upstream.example", dns.TypeA)
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, "192.0.2.10", resp.Answer[0].(*dns.A).A.String())
}

func TestDNSServerReplaceRulesRacesQueriesSafely(t *testing.T) {
	upstream := startTestUpstream(t)
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), &recordingSink{}, nil)

	const iterations = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			mode := apiv1.DnsMode_DNS_MODE_ALLOWLIST
			if i%2 == 0 {
				mode = apiv1.DnsMode_DNS_MODE_DENYLIST
			}
			require.NoError(t, server.ReplaceRules(mode,
				[]*apiv1.DomainEntry{{Domain: "race.example", IncludeSubdomains: true}},
				[]*apiv1.DomainEntry{{Domain: "blocked.example"}},
				[]string{upstream}))
		}
	}()
	for worker := 0; worker < 2; worker++ {
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				resp := queryServer(server, "race.example", dns.TypeA)
				require.NotNil(t, resp)
				assert.Contains(t, []int{dns.RcodeSuccess, dns.RcodeRefused, dns.RcodeServerFailure}, resp.Rcode)
			}
		}()
	}
	close(start)
	wg.Wait()

	allowed, blocked, queryErrors := server.Stats()
	assert.Equal(t, uint64(2*iterations), allowed+blocked+queryErrors,
		"each concurrent query must land in exactly one outcome bucket")
}

func TestDNSInFlightProxyDecisionRevalidatesGeneration(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprintf("allow_%t", allowed), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			sink := &recordingSink{}
			server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), sink,
				func(context.Context, string, string) (DnsProxyDecision, error) {
					close(entered)
					<-release
					return DnsProxyDecision{Allow: allowed, AddToFilter: allowed, IPs: []string{"192.0.2.44"}}, nil
				})
			require.NoError(t, server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY))
			writer := &captureDNSWriter{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.handleDNS(writer, dnsQuery("race.example", dns.TypeA))
			}()
			<-entered
			require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil))
			close(release)
			<-done
			require.NotNil(t, writer.msg)
			assert.Equal(t, dns.RcodeServerFailure, writer.msg.Rcode,
				"neither a stale allow nor stale deny decision may cross generations")
			assert.Zero(t, sink.calls())
		})
	}
}

func TestDNSInFlightStaticAllowRevalidatesGenerationAfterHeldUpstream(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	upstream, _, _ := startDualProtocolUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		close(entered)
		<-release
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.46").To4(),
		})
		_ = w.WriteMsg(resp)
	}))
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), sink, nil)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "race.example"}}, nil))

	writer := &captureDNSWriter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleDNS(writer, dnsQuery("race.example", dns.TypeA))
	}()
	<-entered
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST, nil, nil))
	close(release)
	<-done

	require.NotNil(t, writer.msg)
	assert.Equal(t, dns.RcodeServerFailure, writer.msg.Rcode)
	assert.Empty(t, writer.msg.Answer)
	assert.Zero(t, sink.calls(), "a stale static allow answer must never reach exact admission")
}

func TestDNSStaleStaticDenySnapshotCannotReturnRefused(t *testing.T) {
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), &recordingSink{}, nil)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DENYLIST, nil,
		[]*apiv1.DomainEntry{{Domain: "race.example"}}))
	snapshot, shouldResolve, err := server.snapshotQuery("race.example")
	require.NoError(t, err)
	assert.False(t, shouldResolve)
	assert.True(t, snapshot.blocked)

	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil))
	writer := &captureDNSWriter{}
	req := dnsQuery("race.example", dns.TypeA)
	server.writeIfCurrent(writer, req, refusedResponse(req), snapshot, dnsOutcomeBlocked)

	require.NotNil(t, writer.msg)
	assert.Equal(t, dns.RcodeServerFailure, writer.msg.Rcode,
		"a static deny from an old generation must never cross the policy cutover as REFUSED")
}

func TestDNSPolicyLeaseCoversResponseWrite(t *testing.T) {
	release := make(chan struct{})
	writer := &blockingDNSWriter{entered: make(chan struct{}), release: release}
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), sink,
		func(context.Context, string, string) (DnsProxyDecision, error) {
			return DnsProxyDecision{Allow: true, AddToFilter: true, IPs: []string{"192.0.2.45"}}, nil
		})
	require.NoError(t, server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY))
	queryDone := make(chan struct{})
	go func() {
		defer close(queryDone)
		server.handleDNS(writer, dnsQuery("lease.example", dns.TypeA))
	}()
	<-writer.entered
	assert.False(t, server.mu.TryLock(), "the response write must hold the DNS policy read lease")

	replaceDone := make(chan error, 1)
	go func() {
		replaceDone <- server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil)
	}()
	close(release)
	<-queryDone
	require.NoError(t, <-replaceDone)
	assert.Equal(t, dns.RcodeSuccess, writer.msg.Rcode)
}

func TestDNSWriteDeadlineConnActuallyBoundsBlockedWrite(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	defer left.Close()
	wrapped := &dnsWriteDeadlineConn{Conn: left, timeout: 25 * time.Millisecond}
	start := time.Now()
	_, err := wrapped.Write(make([]byte, 1<<20))
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
}

func TestDNSUDPWriteDeadlineCannotBeResetByConcurrentResponse(t *testing.T) {
	releaseFirst := make(chan struct{})
	underlying := &blockingDeadlinePacketConn{
		firstWriteEntered: make(chan struct{}),
		firstWriteRelease: releaseFirst,
	}
	wrapped := &dnsWriteDeadlinePacketConn{PacketConn: underlying, timeout: time.Second}
	firstDone := make(chan error, 1)
	go func() {
		_, err := wrapped.WriteTo([]byte("first"), &net.UDPAddr{})
		firstDone <- err
	}()
	<-underlying.firstWriteEntered
	if wrapped.mu.TryLock() {
		wrapped.mu.Unlock()
		t.Fatal("the first UDP write did not retain the deadline/write critical section")
	}
	deadlines, writes := underlying.calls()
	assert.Equal(t, 1, deadlines)
	assert.Equal(t, 1, writes)

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := wrapped.WriteTo([]byte("second"), &net.UDPAddr{})
		secondDone <- err
	}()
	<-secondStarted
	deadlines, writes = underlying.calls()
	assert.Equal(t, 1, deadlines,
		"a later response must not reset the connection-wide deadline while the first write is blocked")
	assert.Equal(t, 1, writes)

	close(releaseFirst)
	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
	deadlines, writes = underlying.calls()
	assert.Equal(t, 2, deadlines)
	assert.Equal(t, 2, writes)
}

func startTestUpstreamWithIP(t testing.TB, answer string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(answer).To4(),
		})
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().String()
}

func TestNormalizeDNSAddressesAndUpstreams(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
	}{
		{input: "1.1.1.1:53", want: "1.1.1.1:53"},
		{input: "[2001:db8::1]:5353", want: "[2001:db8::1]:5353"},
		{input: "DNS.Example.:0053", want: "dns.example:53"},
	} {
		got, err := normalizeUpstreamServer(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
	for _, invalid := range []string{"2001:db8::1:53", "0.0.0.0:53", "host", "host:0", "host:65536"} {
		_, err := normalizeUpstreamServer(invalid)
		assert.Error(t, err, invalid)
	}

	assert.Equal(t, "127.0.0.1", mustResolveListenIP(t, "127.0.0.1"))
	assert.Equal(t, "::1", mustResolveListenIP(t, "::1"))
	assert.Equal(t, "127.0.0.1", mustResolveListenIP(t, "localhost"))
	for _, unusable := range []string{"0.0.0.0", "::", "fe80::1%lo0"} {
		_, err := resolveConcreteDNSListenIP(unusable)
		assert.Error(t, err, unusable)
	}

	ordered, err := normalizeUpstreamServers([]string{
		"DNS.Example.:0053",
		"dns.example:53",
		"[2001:0db8:0:0::53]:0053",
		"[2001:db8::53]:53",
		"1.1.1.1:53",
	}, "9.9.9.9:53")
	require.NoError(t, err)
	assert.Equal(t, []string{"dns.example:53", "[2001:db8::53]:53", "1.1.1.1:53"}, ordered,
		"canonical duplicates must be removed without changing first-seen order")
	fallback, err := normalizeUpstreamServers(nil, "DNS.Fallback.:0053")
	require.NoError(t, err)
	assert.Equal(t, []string{"dns.fallback:53"}, fallback)
}

func mustResolveListenIP(t *testing.T, input string) string {
	t.Helper()
	resolved, err := resolveConcreteDNSListenIP(input)
	require.NoError(t, err)
	return resolved
}

func TestSanitizeAddressHintsCopiesAndPreservesOtherParameters(t *testing.T) {
	values := func() []dns.SVCBKeyValue {
		return []dns.SVCBKeyValue{
			&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT}},
			&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.30").To4()}},
			&dns.SVCBPort{Port: 8443},
			&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::30")}},
		}
	}
	original := new(dns.Msg)
	original.Answer = []dns.RR{
		&dns.SVCB{Hdr: dns.RR_Header{Name: "svc.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}, Priority: 1, Target: ".", Value: values()},
	}
	original.Ns = []dns.RR{
		&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: "https.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}, Priority: 1, Target: ".", Value: values()}},
	}
	original.Extra = []dns.RR{
		&dns.SVCB{Hdr: dns.RR_Header{Name: "extra-svc.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}, Priority: 1, Target: ".", Value: values()},
		&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: "extra-https.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}, Priority: 1, Target: ".", Value: values()}},
	}

	for _, mode := range []apiv1.DnsMode{
		apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		apiv1.DnsMode_DNS_MODE_DENYLIST,
		apiv1.DnsMode_DNS_MODE_PROXY,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			filtered := sanitizeAddressHints(original, mode)
			for _, section := range [][]dns.RR{filtered.Answer, filtered.Ns, filtered.Extra} {
				for _, rr := range section {
					var got []dns.SVCBKeyValue
					switch value := rr.(type) {
					case *dns.SVCB:
						got = value.Value
					case *dns.HTTPS:
						got = value.Value
					}
					require.Len(t, got, 3)
					mandatory, ok := got[0].(*dns.SVCBMandatory)
					require.True(t, ok)
					assert.Equal(t, []dns.SVCBKey{dns.SVCB_ALPN}, mandatory.Code)
					_, alpn := got[1].(*dns.SVCBAlpn)
					_, port := got[2].(*dns.SVCBPort)
					assert.True(t, alpn)
					assert.True(t, port)
				}
			}
		})
	}

	// The upstream object remains untouched, including its mixed mandatory
	// declaration, and disabled mode returns a semantically exact deep copy.
	for _, section := range [][]dns.RR{original.Answer, original.Ns, original.Extra} {
		for _, rr := range section {
			var got []dns.SVCBKeyValue
			switch value := rr.(type) {
			case *dns.SVCB:
				got = value.Value
			case *dns.HTTPS:
				got = value.Value
			}
			require.Len(t, got, 5)
			mandatory, ok := got[0].(*dns.SVCBMandatory)
			require.True(t, ok)
			assert.Equal(t, []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT}, mandatory.Code)
		}
	}

	passThrough := sanitizeAddressHints(original, apiv1.DnsMode_DNS_MODE_DISABLED)
	assert.Equal(t, original, passThrough)
	assert.NotSame(t, original, passThrough)
}

func TestDNSStatsOutcomesAreExclusiveAndAdmissionFailureServfails(t *testing.T) {
	upstream := startTestUpstream(t)
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), sink, nil)

	assert.Equal(t, dns.RcodeSuccess, queryServer(server, "allowed.example", dns.TypeA).Rcode)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST, nil, nil))
	assert.Equal(t, dns.RcodeRefused, queryServer(server, "blocked.example", dns.TypeA).Rcode)

	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "admission.example"}}, nil))
	sink.setError(errors.New("injected admission failure"))
	assert.Equal(t, dns.RcodeServerFailure, queryServer(server, "admission.example", dns.TypeA).Rcode)

	allowed, blocked, queryErrors := server.Stats()
	assert.Equal(t, uint64(1), allowed)
	assert.Equal(t, uint64(1), blocked)
	assert.Equal(t, uint64(1), queryErrors)
}

func TestDNSResponseWriteFailureCountsOnlyAsError(t *testing.T) {
	for _, outcome := range []dnsOutcome{dnsOutcomeAllowed, dnsOutcomeBlocked} {
		server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, nil)
		req := dnsQuery("write-failure.example", dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(req)
		server.writeOutcome(&failingDNSWriter{}, req, resp, outcome)
		allowed, blocked, queryErrors := server.Stats()
		assert.Zero(t, allowed)
		assert.Zero(t, blocked)
		assert.Equal(t, uint64(1), queryErrors)
	}
}

func TestDNSStatsExportErrorsWithoutChangingAllowedBlocked(t *testing.T) {
	server, _, id, _, dnsServer := newTestServerWithAttachment(t)
	dnsServer.queriesAllowed.Store(7)
	dnsServer.queriesBlocked.Store(5)
	dnsServer.queriesErrors.Store(3)

	listed, err := server.List(context.Background(), &apiv1.ListRequest{PageSize: 10})
	require.NoError(t, err)
	require.Len(t, listed.Attachments, 1)
	assert.Equal(t, id, listed.Attachments[0].Id)
	assert.Equal(t, uint64(7), listed.Attachments[0].DnsQueriesAllowed)
	assert.Equal(t, uint64(5), listed.Attachments[0].DnsQueriesBlocked)
	assert.Equal(t, uint64(3), listed.Attachments[0].DnsQueriesErrors)

	stats := server.GetAttachmentStats()
	require.Len(t, stats, 1)
	assert.Equal(t, id, stats[0].Id)
	assert.Equal(t, uint64(7), stats[0].DnsQueriesAllowed)
	assert.Equal(t, uint64(5), stats[0].DnsQueriesBlocked)
	assert.Equal(t, uint64(3), stats[0].DnsQueriesErrors)
}

func TestDNSProxyOverrideAdmissionFailureServfailsWithoutReturningAddress(t *testing.T) {
	sink := &recordingSink{err: errors.New("map full")}
	server := NewDNSServer("att-1", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), sink, func(context.Context, string, string) (DnsProxyDecision, error) {
		return DnsProxyDecision{Allow: true, AddToFilter: true, IPs: []string{"192.0.2.99"}}, nil
	})
	server.SetMode(apiv1.DnsMode_DNS_MODE_PROXY)
	resp := queryServer(server, "proxy.example", dns.TypeA)
	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	assert.Empty(t, resp.Answer)
	allowed, blocked, queryErrors := server.Stats()
	assert.Zero(t, allowed)
	assert.Zero(t, blocked)
	assert.Equal(t, uint64(1), queryErrors)
}

func TestDNSRejectsMultiQuestionBeforePolicySideEffects(t *testing.T) {
	var upstreamQueries atomic.Uint64
	upstream := startCountingUpstream(t, &upstreamQueries, dns.RcodeSuccess, "192.0.2.10")
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), sink, nil)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "allowed.example"}}, nil))
	req := dnsQuery("allowed.example", dns.TypeA)
	req.Question = append(req.Question, dns.Question{Name: "blocked.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	w := &captureDNSWriter{}
	server.handleDNS(w, req)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeServerFailure, w.msg.Rcode)
	assert.Zero(t, upstreamQueries.Load())
	assert.Zero(t, sink.calls())
	allowed, blocked, queryErrors := server.Stats()
	assert.Zero(t, allowed)
	assert.Zero(t, blocked)
	assert.Equal(t, uint64(1), queryErrors)
}

func TestDNSAdmissionCoversAllReturnedSections(t *testing.T) {
	upstream := startSectionAddressUpstream(t, dns.RcodeSuccess)
	sink := &recordingSink{}
	server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), sink, nil)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "sections.example"}}, nil))
	resp := queryServer(server, "sections.example", dns.TypeA)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.ElementsMatch(t, []string{"192.0.2.10/32", "2001:db8::10/128", "192.0.2.11/32"}, sink.entries())

	failing := &recordingSink{}
	failingServer := NewDNSServer("att-2", "127.0.0.1:0", upstream, zerolog.Nop(), &failOnNthSink{wrapped: failing, failAt: 1}, nil)
	require.NoError(t, failingServer.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "sections.example"}}, nil))
	resp = queryServer(failingServer, "sections.example", dns.TypeA)
	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	assert.Empty(t, resp.Answer, "an admission failure must not leak any upstream section")
	assert.Empty(t, resp.Ns)
	assert.Empty(t, resp.Extra)
}

type failOnNthSink struct {
	wrapped *recordingSink
	failAt  int
	calls   int
}

func (s *failOnNthSink) BeginAdmission() (func(), error) { return func() {}, nil }

func (s *failOnNthSink) AdmitCanonicalResponse(req dnsCanonicalAdmissionRequest) error {
	s.calls++
	if s.calls == s.failAt {
		return errors.New("injected additional-section admission failure")
	}
	return s.wrapped.AdmitCanonicalResponse(req)
}

func (s *failOnNthSink) ReconcilePolicy(l dnsAdmissionLimits, c dnsChurnLimits, d map[string]struct{}, r dnsOwnershipResolver, a bool) error {
	return s.wrapped.ReconcilePolicy(l, c, d, r, a)
}
func (s *failOnNthSink) PreflightPolicy(l dnsAdmissionLimits, c dnsChurnLimits, d map[string]struct{}, r dnsOwnershipResolver, a bool) error {
	return s.wrapped.PreflightPolicy(l, c, d, r, a)
}
func (s *failOnNthSink) Expire(now time.Time) error              { return s.wrapped.Expire(now) }
func (s *failOnNthSink) SeedPinned() error                       { return nil }
func (s *failOnNthSink) ValidateLimits(dnsAdmissionLimits) error { return nil }
func (s *failOnNthSink) FailClosedIfAmbiguous(error) error       { return nil }
func (s *failOnNthSink) QuarantineAmbiguity(error) error         { return nil }

func TestDNSAddressBearingErrorRcodesAreAdmittedOrSuppressed(t *testing.T) {
	for _, rcode := range []int{dns.RcodeNameError, dns.RcodeServerFailure} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			upstream := startSectionAddressUpstream(t, rcode)
			sink := &recordingSink{}
			server := NewDNSServer("att-1", "127.0.0.1:0", upstream, zerolog.Nop(), sink, nil)
			require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
				[]*apiv1.DomainEntry{{Domain: "sections.example"}}, nil))
			resp := queryServer(server, "sections.example", dns.TypeA)
			assert.Equal(t, rcode, resp.Rcode)
			if rcode == dns.RcodeNameError {
				assert.Equal(t, 3, sink.calls(), "NXDOMAIN authority/additional addresses must be admitted before return")
			} else {
				assert.Zero(t, sink.calls(), "upstream SERVFAIL is suppressed by failover and its sections never return")
			}
			allowed, blocked, queryErrors := server.Stats()
			assert.Zero(t, blocked)
			if rcode == dns.RcodeNameError {
				assert.Equal(t, uint64(1), allowed)
				assert.Zero(t, queryErrors)
			} else {
				assert.Zero(t, allowed)
				assert.Equal(t, uint64(1), queryErrors)
			}
		})
	}
}

func startSectionAddressUpstream(t testing.TB, rcode int) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.10").To4()})
		resp.Ns = append(resp.Ns, &dns.AAAA{Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::10")})
		resp.Extra = append(resp.Extra, &dns.A{Hdr: dns.RR_Header{Name: "extra.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.11").To4()})
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().String()
}

func startCountingUpstream(t testing.TB, queries *atomic.Uint64, rcode int, answer string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		queries.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		if answer != "" {
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(answer).To4()})
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().String()
}

func TestDNSOrderedFailoverContinuesAfterRetryableRcode(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			var first, second atomic.Uint64
			bad := startCountingUpstream(t, &first, rcode, "")
			good := startCountingUpstream(t, &second, dns.RcodeSuccess, "192.0.2.77")
			server := NewDNSServer("att-1", "127.0.0.1:0", good, zerolog.Nop(), nil, nil)
			require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil, []string{bad, good}))
			resp := queryServer(server, "failover.example", dns.TypeA)
			require.Len(t, resp.Answer, 1)
			assert.Equal(t, "192.0.2.77", resp.Answer[0].(*dns.A).A.String())
			assert.Equal(t, uint64(1), first.Load())
			assert.Equal(t, uint64(1), second.Load())
			allowed, blocked, queryErrors := server.Stats()
			assert.Equal(t, uint64(1), allowed)
			assert.Zero(t, blocked)
			assert.Zero(t, queryErrors)
		})
	}
}

func TestDNSOrderedFailoverContinuesAfterTruncatedUpstreamTCPFailure(t *testing.T) {
	badConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var badUDPQueries atomic.Uint64
	badServer := &dns.Server{PacketConn: badConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		badUDPQueries.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Truncated = true
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = badServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = badServer.Shutdown() })

	var goodQueries atomic.Uint64
	good := startCountingUpstream(t, &goodQueries, dns.RcodeSuccess, "192.0.2.88")
	server := NewDNSServer("att-1", "127.0.0.1:0", good, zerolog.Nop(), nil, nil)
	require.NoError(t, server.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil,
		[]string{badConn.LocalAddr().String(), good}))

	resp := queryServer(server, "tcp-failover.example", dns.TypeA)
	require.Len(t, resp.Answer, 1)
	assert.Equal(t, "192.0.2.88", resp.Answer[0].(*dns.A).A.String())
	assert.Equal(t, uint64(1), badUDPQueries.Load())
	assert.Equal(t, uint64(1), goodQueries.Load(),
		"a failed same-upstream TCP retry must continue to the next configured upstream")
	allowed, blocked, queryErrors := server.Stats()
	assert.Equal(t, uint64(1), allowed)
	assert.Zero(t, blocked)
	assert.Zero(t, queryErrors)
}

func TestDNSServerObservesListenerDeathAndStopsSibling(t *testing.T) {
	addr := freeDNSListenAddress(t)
	server := NewDNSServer("att-1", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	require.NoError(t, server.Start())
	server.serverMu.Lock()
	udpConn := server.udpConn
	done := server.serveDone
	server.serverMu.Unlock()
	require.NoError(t, udpConn.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener failure was not supervised")
	}
	require.ErrorContains(t, server.Err(), "udp DNS listener stopped unexpectedly")
	udp, err := net.ListenPacket("udp", addr)
	require.NoError(t, err)
	require.NoError(t, udp.Close())
	tcp, err := net.Listen("tcp", addr)
	require.NoError(t, err, "TCP sibling must be shut down after UDP death")
	require.NoError(t, tcp.Close())
	require.NoError(t, server.Stop())
	// Fatal cleanup fully completes the lifecycle; the same object can safely
	// reset all lifecycle-local state and bind the same dual-protocol endpoint.
	require.NoError(t, server.Start())
	require.NoError(t, server.Stop())
}

func TestDNSServerCanRunTwoCompleteLifecycles(t *testing.T) {
	addr := freeDNSListenAddress(t)
	server := NewDNSServer("att-1", addr, "127.0.0.1:1", zerolog.Nop(), nil, nil)
	for i := 0; i < 2; i++ {
		require.NoError(t, server.Start())
		const callers = 16
		done := make(chan error, callers)
		for j := 0; j < callers; j++ {
			go func() { done <- server.Stop() }()
		}
		for j := 0; j < callers; j++ {
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatalf("lifecycle %d concurrent Stop %d hung", i+1, j+1)
			}
		}
	}
	udp, err := net.ListenPacket("udp", addr)
	require.NoError(t, err)
	require.NoError(t, udp.Close())
	tcp, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, tcp.Close())
}

func TestDNSServerStopCancelsBlockedUpstreamQuery(t *testing.T) {
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = blackhole.Close() })
	received := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, dns.MaxMsgSize)
		_, _, readErr := blackhole.ReadFrom(buf)
		if readErr == nil {
			received <- struct{}{}
		}
	}()

	addr := freeDNSListenAddress(t)
	server := NewDNSServer("att-1", addr, blackhole.LocalAddr().String(), zerolog.Nop(), nil, nil)
	require.NoError(t, server.Start())
	queryDone := make(chan struct{})
	go func() {
		_, _, _ = (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(dnsQuery("blocked-upstream.example", dns.TypeA), addr)
		close(queryDone)
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("query never reached blackhole upstream")
	}
	started := time.Now()
	require.NoError(t, server.Stop())
	assert.Less(t, time.Since(started), time.Second)
	select {
	case <-queryDone:
	case <-time.After(time.Second):
		t.Fatal("workload query did not terminate after Stop")
	}
	_, _, queryErrors := server.Stats()
	assert.Equal(t, uint64(1), queryErrors)
}

func TestNormalizeUpstreamsEnforcesBound(t *testing.T) {
	values := make([]string, maxDNSUpstreams+1)
	for i := range values {
		values[i] = fmt.Sprintf("192.0.2.%d:53", i+1)
	}
	_, err := normalizeUpstreamServers(values, "1.1.1.1:53")
	require.ErrorContains(t, err, "too many unique DNS upstreams")

	duplicates := make([]string, maxDNSUpstreams+1)
	for i := range duplicates {
		if i%2 == 0 {
			duplicates[i] = "DNS.Example.:0053"
		} else {
			duplicates[i] = "dns.example:53"
		}
	}
	deduplicated, err := normalizeUpstreamServers(duplicates, "1.1.1.1:53")
	require.NoError(t, err)
	assert.Equal(t, []string{"dns.example:53"}, deduplicated)
}
