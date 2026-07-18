//go:build linux

// Phase 4B integration test: HTTP/2 keepalive must detect a silently dead
// control-plane path (cable pull, dropped NAT mapping, blackhole) within
// ~keepalive_time + keepalive_timeout — NOT the kernel's multi-minute TCP
// retransmission timeout — and the jittered-backoff reconnect loop must
// re-establish the stream once the path recovers.
package integration

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// stallableProxy is a TCP proxy in front of the test control plane whose
// forwarding can be stalled. Stall() simulates a silently dead network path:
// bytes stop flowing in BOTH directions but every TCP connection is held
// open — no FIN or RST ever reaches the daemon, exactly like a blackholed
// route (the userspace equivalent of iptables -j DROP on the CP port, with
// no root/iptables dependency and nothing to clean up). While stalled, a
// pipe parks before writing its next chunk, so in-flight bytes are
// preserved and delivered when the stall is lifted.
type stallableProxy struct {
	ln      net.Listener
	backend string
	stalled atomic.Bool
	done    chan struct{}

	mu    sync.Mutex
	conns []net.Conn
}

func newStallableProxy(t *testing.T, backend string) *stallableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &stallableProxy{ln: ln, backend: backend, done: make(chan struct{})}
	go p.acceptLoop()
	t.Cleanup(p.Close)
	return p
}

func (p *stallableProxy) Addr() string { return p.ln.Addr().String() }

// Stall blackholes the path: nothing is forwarded, nothing is closed.
func (p *stallableProxy) Stall() { p.stalled.Store(true) }

// Unstall restores the path; parked pipes resume within one poll interval.
func (p *stallableProxy) Unstall() { p.stalled.Store(false) }

func (p *stallableProxy) Close() {
	select {
	case <-p.done:
		return
	default:
	}
	close(p.done)
	p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
}

func (p *stallableProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		backend, err := net.Dial("tcp", p.backend)
		if err != nil {
			conn.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, conn, backend)
		p.mu.Unlock()
		go p.pipe(backend, conn)
		go p.pipe(conn, backend)
	}
}

func (p *stallableProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Park while stalled: the chunk (and everything queued behind
			// it in the kernel) is withheld, not dropped, so forwarding
			// resumes cleanly on Unstall.
			for p.stalled.Load() {
				select {
				case <-p.done:
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			// Propagate a real close only when the path is healthy — a
			// stalled (dead) path must never surface a FIN to the peer.
			if !p.stalled.Load() {
				dst.Close()
			}
			return
		}
	}
}

// TestControlPlane_KeepaliveDetectsDeadPeer is the 4B headline test: with
// client keepalive configured, a blackholed control-plane connection leaves
// CONNECTED within a bounded multiple of keepalive_time + keepalive_timeout,
// and the daemon reconnects once the path is restored. Pre-4B (no keepalive
// dial option) the daemon sits CONNECTED far past the bound and this test
// fails — that is the negative verification.
func TestControlPlane_KeepaliveDetectsDeadPeer(t *testing.T) {
	_, cpAddr, stop := startControlPlaneServer(t, nil, nil)
	defer stop()

	proxy := newStallableProxy(t, cpAddr)

	cpClient := startTLSClient(t, proxy.Addr(), config.ControlPlaneConfig{
		URL:      proxy.Addr(),
		Insecure: true,
		// Short values keep the test fast. grpc-go clamps the ping
		// interval to a 10s client-side minimum, so detection is bounded
		// by ~10s (idle before ping, worst-case alignment) + 2s (ack
		// timeout) — well inside the 30s assertion below, and orders of
		// magnitude under the kernel TCP timeout this replaces.
		KeepaliveTime:       time.Second,
		KeepaliveTimeout:    2 * time.Second,
		ReconnectBackoffMax: 2 * time.Second,
		SubscribeAckTimeout: 5 * time.Second,
	})

	require.Eventually(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 10*time.Second, 50*time.Millisecond, "daemon should connect through the live proxy")

	// Blackhole the path mid-connection: no FIN/RST, packets just stop.
	proxy.Stall()
	stalledAt := time.Now()

	require.Eventually(t, func() bool {
		return cpClient.State() != apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 30*time.Second, 100*time.Millisecond,
		"keepalive should tear down the blackholed connection within ~keepalive_time+timeout, not the kernel TCP timeout")
	t.Logf("dead peer detected after %v (bound 30s; kernel TCP timeout would be minutes)", time.Since(stalledAt))

	// Restore the path: the backoff'd reconnect loop (capped at 2s here)
	// must re-establish the stream. The generous bound absorbs a reconnect
	// attempt that started while the path was still black-holed (gRPC's
	// ~20s connect timeout) plus one backoff delay.
	proxy.Unstall()
	restoredAt := time.Now()
	require.Eventually(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 40*time.Second, 100*time.Millisecond, "daemon should reconnect once the path is restored")
	t.Logf("reconnected %v after path restore", time.Since(restoredAt))
}
