package daemon

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	apiv1 "github.com/danthegoodman1/netfence/v1"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestDNSQueryLimitsBoundWorkAcrossAttachmentsAndReleaseOnStop(t *testing.T) {
	global := &dnsResources{queries: make(chan struct{}, 2), connections: make(chan struct{}, 4)}
	started := make(chan string, 4)
	makeServer := func(id string) *DNSServer {
		s := NewDNSServer(id, "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil,
			func(ctx context.Context, _, _ string) (DnsProxyDecision, error) {
				started <- id
				<-ctx.Done()
				return DnsProxyDecision{}, ctx.Err()
			})
		s.globalResources = global
		s.resources.queries = make(chan struct{}, 1)
		require.NoError(t, s.SetMode(apiv1.DnsMode_DNS_MODE_PROXY))
		require.NoError(t, s.Start())
		t.Cleanup(func() { s.Stop() })
		return s
	}
	a, b, c := makeServer("a"), makeServer("b"), makeServer("c")
	send := func(s *DNSServer) {
		conn, err := net.Dial("udp", s.udpConn.LocalAddr().String())
		require.NoError(t, err)
		defer conn.Close()
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		wire, err := req.Pack()
		require.NoError(t, err)
		_, err = conn.Write(wire)
		require.NoError(t, err)
	}
	send(a)
	require.Equal(t, "a", <-started)
	send(a)
	require.Eventually(t, func() bool { return a.queriesErrors.Load() == 1 }, time.Second, time.Millisecond)
	send(b)
	require.Equal(t, "b", <-started)
	send(c)
	require.Eventually(t, func() bool { return c.queriesErrors.Load() == 1 }, time.Second, time.Millisecond)
	require.Empty(t, started)
	require.Len(t, global.queries, 2)
	require.NoError(t, a.Stop())
	require.Len(t, global.queries, 1)
	send(c)
	require.Equal(t, "c", <-started)
	require.NoError(t, b.Stop())
	require.NoError(t, c.Stop())
	require.Empty(t, global.queries)
	require.Empty(t, a.resources.queries)
}

func TestDNSTCPConnectionLimitsIncludeIdleConnections(t *testing.T) {
	global := &dnsResources{queries: make(chan struct{}, 8), connections: make(chan struct{}, 2)}
	makeServer := func(id string) *DNSServer {
		s := NewDNSServer(id, "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil, nil)
		s.globalResources = global
		s.resources.connections = make(chan struct{}, 1)
		require.NoError(t, s.Start())
		t.Cleanup(func() { s.Stop() })
		return s
	}
	a, b, c := makeServer("a"), makeServer("b"), makeServer("c")
	dial := func(s *DNSServer) net.Conn {
		conn, err := net.Dial("tcp", s.tcpLn.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	first := dial(a)
	require.Eventually(t, func() bool { return len(a.resources.connections) == 1 }, time.Second, time.Millisecond)
	assertClosed := func(conn net.Conn) {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
		var buf [1]byte
		_, err := conn.Read(buf[:])
		require.Error(t, err)
		if e, ok := err.(net.Error); ok {
			require.False(t, e.Timeout(), "excess connection must close immediately")
		}
	}
	assertClosed(dial(a))
	dial(b)
	require.Eventually(t, func() bool { return len(global.connections) == 2 }, time.Second, time.Millisecond)
	assertClosed(dial(c))
	first.Close()
	require.Eventually(t, func() bool { return len(global.connections) == 1 }, time.Second, time.Millisecond)
	dial(c)
	require.Eventually(t, func() bool { return len(global.connections) == 2 }, time.Second, time.Millisecond)
	require.NoError(t, a.Stop())
	require.NoError(t, b.Stop())
	require.NoError(t, c.Stop())
	require.Empty(t, global.connections)
}

func TestDNSQueryDeadlineIncludesProxyAndAllUpstreams(t *testing.T) {
	var calls atomic.Int32
	s := NewDNSServer("deadline", "127.0.0.1:0", "127.0.0.1:1", zerolog.Nop(), nil,
		func(ctx context.Context, _, _ string) (DnsProxyDecision, error) {
			calls.Add(1)
			<-ctx.Done()
			return DnsProxyDecision{}, ctx.Err()
		})
	s.queryTimeout = 40 * time.Millisecond
	require.NoError(t, s.SetMode(apiv1.DnsMode_DNS_MODE_PROXY))
	require.NoError(t, s.Start())
	defer s.Stop()
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	client := &dns.Client{Timeout: time.Second}
	start := time.Now()
	resp, _, err := client.Exchange(req, s.udpConn.LocalAddr().String())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, int32(1), calls.Load())
	// A blackhole consumes the shared deadline; later upstreams must never
	// receive a query once it expires.
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blackhole.Close()
	later, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer later.Close()
	require.NoError(t, s.ReplaceRules(apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil, []string{blackhole.LocalAddr().String(), later.LocalAddr().String()}))
	start = time.Now()
	resp, _, err = client.Exchange(req, s.udpConn.LocalAddr().String())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, resp.Rcode)
	require.Less(t, time.Since(start), time.Second)
	require.NoError(t, later.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	var buf [512]byte
	_, _, err = later.ReadFrom(buf[:])
	require.Error(t, err)
	require.Empty(t, s.resources.queries)
}
