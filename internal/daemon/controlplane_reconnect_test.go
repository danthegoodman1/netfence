package daemon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// Phase 4C unit tests: sendCh persists across reconnects, so events queued
// against a dead connection must NOT be replayed after the fresh SyncRequest
// on the next connection (Sync supersedes them) — with the one exception of
// a Subscribed whose SubscribedAck is still pending, which a caller blocked
// in SubscribeAndWait still needs delivered on the new stream.

// testCPConn records the DaemonEvents one Connect stream received, in
// arrival order, and can be killed to simulate the control plane dropping
// the connection.
type testCPConn struct {
	mu     sync.Mutex
	events []*apiv1.DaemonEvent

	killOnce sync.Once
	kill     chan struct{}
}

func (c *testCPConn) snapshot() []*apiv1.DaemonEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*apiv1.DaemonEvent, len(c.events))
	copy(out, c.events)
	return out
}

func (c *testCPConn) killConn() { c.killOnce.Do(func() { close(c.kill) }) }

// testControlPlane is a real gRPC control plane on a loopback listener. It
// records every DaemonEvent per connection, acks SyncRequests, and
// optionally acks Subscribed events.
type testControlPlane struct {
	apiv1.UnimplementedControlPlaneServer
	ackSubscribed bool

	mu    sync.Mutex
	conns []*testCPConn
}

func (cp *testControlPlane) connCount() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.conns)
}

func (cp *testControlPlane) conn(i int) *testCPConn {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.conns[i]
}

func (cp *testControlPlane) Connect(stream grpc.BidiStreamingServer[apiv1.DaemonEvent, apiv1.ControlCommand]) error {
	conn := &testCPConn{kill: make(chan struct{})}
	cp.mu.Lock()
	cp.conns = append(cp.conns, conn)
	cp.mu.Unlock()

	recvErr := make(chan error, 1)
	go func() {
		for {
			ev, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			conn.mu.Lock()
			conn.events = append(conn.events, ev)
			conn.mu.Unlock()

			switch v := ev.Event.(type) {
			case *apiv1.DaemonEvent_Sync:
				_ = stream.Send(&apiv1.ControlCommand{
					Command: &apiv1.ControlCommand_SyncAck{SyncAck: &apiv1.SyncAck{}},
				})
			case *apiv1.DaemonEvent_Subscribed:
				if cp.ackSubscribed {
					_ = stream.Send(&apiv1.ControlCommand{
						Id: v.Subscribed.Id,
						Command: &apiv1.ControlCommand_SubscribedAck{
							SubscribedAck: &apiv1.SubscribedAck{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED},
						},
					})
				}
			}
		}
	}()

	select {
	case err := <-recvErr:
		return err
	case <-conn.kill:
		return fmt.Errorf("connection killed by test")
	}
}

func startTestControlPlane(t *testing.T, cp *testControlPlane) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	apiv1.RegisterControlPlaneServer(srv, cp)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func newReconnectTestClient(t *testing.T, addr string, server *Server, ackTimeout time.Duration) *ControlPlaneClient {
	t.Helper()
	return NewControlPlaneClient(addr, server, zerolog.Nop(), nil, ackTimeout,
		&ControlPlaneCreds{Transport: insecure.NewCredentials()})
}

// startConnect runs one c.connect and closes the returned channel when it
// ends (stream died or ctx cancelled).
func startConnect(c *ControlPlaneClient, ctx context.Context) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.connect(ctx)
	}()
	return done
}

func waitDone(t *testing.T, done chan struct{}, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}

func staleHeartbeat() outboundEvent {
	return outboundEvent{event: &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Heartbeat{Heartbeat: &apiv1.Heartbeat{}},
	}}
}

func eventKind(ev *apiv1.DaemonEvent) string {
	switch v := ev.Event.(type) {
	case *apiv1.DaemonEvent_Sync:
		return "sync"
	case *apiv1.DaemonEvent_Subscribed:
		return "subscribed:" + v.Subscribed.Id
	case *apiv1.DaemonEvent_Unsubscribed:
		return "unsubscribed:" + v.Unsubscribed.Id
	case *apiv1.DaemonEvent_Heartbeat:
		return "heartbeat"
	case *apiv1.DaemonEvent_CommandResult:
		return "command_result:" + v.CommandResult.CommandId
	default:
		return "unknown"
	}
}

func eventKinds(events []*apiv1.DaemonEvent) []string {
	kinds := make([]string, len(events))
	for i, ev := range events {
		kinds[i] = eventKind(ev)
	}
	return kinds
}

// TestControlPlaneReconnectPurgesStaleQueuedEvents is the core 4C
// invariant: events queued against a dead connection (a Heartbeat, an
// Unsubscribed for an attachment already absent from the Sync list, a
// CommandResult) are NOT replayed after the fresh SyncRequest on the next
// connection — the Sync supersedes them — while a Subscribed whose ack is
// still pending IS re-delivered (after the Sync), and events generated
// after the reconnect flow normally.
func TestControlPlaneReconnectPurgesStaleQueuedEvents(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	cp := &testControlPlane{}
	addr := startTestControlPlane(t, cp)
	c := newReconnectTestClient(t, addr, server, time.Second)

	// Connection 1: establish, let the CP see its SyncRequest, then kill it
	// from the CP side (simulating a dropped connection).
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	done1 := startConnect(c, ctx1)
	require.Eventually(t, func() bool {
		return cp.connCount() >= 1 && len(cp.conn(0).snapshot()) >= 1
	}, 5*time.Second, 5*time.Millisecond, "connection 1 never delivered its SyncRequest")
	cp.conn(0).killConn()
	waitDone(t, done1, "connect() did not return after the CP killed connection 1")

	// Queue the leftovers of the dead connection. The heartbeat goes first
	// on purpose: connection 1's sendLoop is not joined by connect(), so it
	// may consume at most one more queued event before its Send fails on
	// the closed connection and it exits — sacrificing the heartbeat keeps
	// the rest of the queue deterministic (and the assertions below hold
	// whether it was consumed there or dropped by the purge).
	require.True(t, c.enqueue(staleHeartbeat()))
	c.SendUnsubscribed(&apiv1.Unsubscribed{Id: "gone-att", Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_REMOVED})
	c.sendCommandResult("cmd-stale", "gone-att", nil)

	// A Subscribed whose SubscribedAck is still pending: the caller is
	// still blocked in SubscribeAndWait, so this one MUST survive the
	// purge and be re-delivered after the fresh SyncRequest.
	c.pendingAcksMu.Lock()
	c.pendingAcks[id] = make(chan SubscribedAckResult, 1)
	c.pendingAcksMu.Unlock()
	require.True(t, c.enqueue(outboundEvent{
		event: &apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: &apiv1.Subscribed{Id: id}},
		},
		subscribedID:      id,
		requirePendingAck: true,
	}))

	// Connection 2: the fresh SyncRequest must be first, then only the
	// still-pending Subscribed may follow from the old queue.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := startConnect(c, ctx2)
	require.Eventually(t, func() bool {
		if cp.connCount() < 2 {
			return false
		}
		for _, ev := range cp.conn(1).snapshot() {
			if sub := ev.GetSubscribed(); sub != nil && sub.Id == id {
				return true
			}
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "pending Subscribed was not re-delivered on connection 2")

	// An event generated AFTER the reconnect must flow normally. It was
	// enqueued after everything above, so once it arrives every earlier
	// queue entry has been either sent or purged — making the final
	// assertion race-free.
	c.SendUnsubscribed(&apiv1.Unsubscribed{Id: "live-att", Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_DETACHED})
	require.Eventually(t, func() bool {
		for _, ev := range cp.conn(1).snapshot() {
			if unsub := ev.GetUnsubscribed(); unsub != nil && unsub.Id == "live-att" {
				return true
			}
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "post-reconnect Unsubscribed was not delivered")

	got := eventKinds(cp.conn(1).snapshot())
	// SyncRequest is always the first event on the new connection, the
	// re-delivered pending Subscribed comes after it, and NONE of the
	// stale events (heartbeat, unsubscribed for an id absent from the
	// sync, command result) leak through.
	assert.Equal(t, []string{"sync", "subscribed:" + id, "unsubscribed:live-att"}, got,
		"stale pre-disconnect events must be purged on reconnect (Sync supersedes them)")

	cancel2()
	waitDone(t, done2, "connect() did not return after ctx cancellation")
}

// TestControlPlaneSubscribeAndWaitResolvesAcrossReconnect: a caller blocked
// in SubscribeAndWait when the connection drops must still get its
// SubscribedAck — its pending Subscribed is re-delivered on the new
// connection (after the SyncRequest) and the CP's ack resolves the wait.
func TestControlPlaneSubscribeAndWaitResolvesAcrossReconnect(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	cp := &testControlPlane{ackSubscribed: true}
	addr := startTestControlPlane(t, cp)
	c := newReconnectTestClient(t, addr, server, 10*time.Second)

	// Connection 1 comes up and dies before the subscribe happens.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	done1 := startConnect(c, ctx1)
	require.Eventually(t, func() bool {
		return cp.connCount() >= 1 && len(cp.conn(0).snapshot()) >= 1
	}, 5*time.Second, 5*time.Millisecond, "connection 1 never delivered its SyncRequest")
	cp.conn(0).killConn()
	waitDone(t, done1, "connect() did not return after the CP killed connection 1")

	// Sacrificial stale event: connection 1's sendLoop may consume at most
	// one more queued event before exiting on a failed Send; it must not
	// be the pending Subscribed.
	require.True(t, c.enqueue(staleHeartbeat()))

	// The subscribe straddles the outage: queued while disconnected, the
	// caller blocks awaiting the ack.
	type subResult struct {
		ack *apiv1.SubscribedAck
		err error
	}
	resultCh := make(chan subResult, 1)
	go func() {
		ack, err := c.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: id})
		resultCh <- subResult{ack: ack, err: err}
	}()
	require.Eventually(t, func() bool { return c.hasPendingAck(id) },
		5*time.Second, 5*time.Millisecond, "SubscribeAndWait never registered its pending ack")

	// Reconnect: the pending Subscribed must be re-delivered after the
	// fresh SyncRequest and the CP's SubscribedAck must unblock the caller.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := startConnect(c, ctx2)

	select {
	case res := <-resultCh:
		require.NoError(t, res.err, "SubscribeAndWait must resolve via the re-delivered Subscribed, not time out")
		require.NotNil(t, res.ack, "SubscribeAndWait must return the CP's ack, not silently succeed without config")
		assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_DISABLED, res.ack.Mode)
	case <-time.After(5 * time.Second):
		t.Fatal("SubscribeAndWait still blocked after reconnect: pending Subscribed was dropped")
	}

	got := eventKinds(cp.conn(1).snapshot())
	require.NotEmpty(t, got)
	assert.Equal(t, "sync", got[0], "SyncRequest must be the first event on the new connection")
	assert.Contains(t, got, "subscribed:"+id)
	assert.NotContains(t, got, "heartbeat", "stale heartbeat must not be replayed after the sync")

	cancel2()
	waitDone(t, done2, "connect() did not return after ctx cancellation")
}

// TestControlPlaneReconnectDrainsFullBacklogWithoutDeadlock: a sendCh
// completely full of stale events must neither deadlock the reconnect nor
// leak a single stale event to the CP, and once the purge drains the
// backlog, newly generated events flow normally.
func TestControlPlaneReconnectDrainsFullBacklogWithoutDeadlock(t *testing.T) {
	server, _, _, _, _ := newTestServerWithAttachment(t)
	cp := &testControlPlane{}
	addr := startTestControlPlane(t, cp)
	c := newReconnectTestClient(t, addr, server, time.Second)

	// Fill the channel to capacity with stale heartbeats, as if the
	// connection died long ago and producers kept (non-blockingly) queueing.
	for i := 0; i < cap(c.sendCh); i++ {
		require.True(t, c.enqueue(staleHeartbeat()))
	}
	require.False(t, c.enqueue(staleHeartbeat()), "channel should be full")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := startConnect(c, ctx)

	// The purge must drain the full backlog without wedging.
	require.Eventually(t, func() bool { return len(c.sendCh) == 0 },
		5*time.Second, 5*time.Millisecond, "stale backlog was never drained")
	require.Eventually(t, func() bool {
		return c.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 5*time.Second, 5*time.Millisecond)

	// A post-reconnect event flows through.
	c.SendUnsubscribed(&apiv1.Unsubscribed{Id: "live-att", Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_DETACHED})
	require.Eventually(t, func() bool {
		for _, ev := range cp.conn(0).snapshot() {
			if unsub := ev.GetUnsubscribed(); unsub != nil && unsub.Id == "live-att" {
				return true
			}
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "post-reconnect Unsubscribed was not delivered")

	got := eventKinds(cp.conn(0).snapshot())
	assert.Equal(t, []string{"sync", "unsubscribed:live-att"}, got,
		"none of the stale backlog may reach the CP")

	cancel()
	waitDone(t, done, "connect() did not return after ctx cancellation")
}
