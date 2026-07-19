package daemon

import (
	"context"
	"errors"
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
	"google.golang.org/grpc/metadata"

	"github.com/danthegoodman1/netfence/pkg/filter"
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
	pending := &pendingSubscription{
		sub:      &apiv1.Subscribed{Id: id},
		purpose:  subscriptionPurposeAttach,
		resultCh: make(chan SubscribedAckResult, 1),
	}
	c.pendingAcksMu.Lock()
	c.pendingAcks[id] = pending
	c.pendingAcksMu.Unlock()
	require.True(t, c.enqueue(outboundEvent{
		event: &apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: pending.sub},
		},
		pending: pending,
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

// scriptedBidiClient is a focused sendLoop test stream. ClientStream's generic
// message methods are unused; Send records exact DaemonEvent order and can fail
// deterministically on Subscribed.
type scriptedBidiClient struct {
	ctx context.Context

	mu             sync.Mutex
	events         []*apiv1.DaemonEvent
	failSubscribed bool
}

func (s *scriptedBidiClient) Send(event *apiv1.DaemonEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSubscribed && event.GetSubscribed() != nil {
		return fmt.Errorf("scripted subscribed send failure")
	}
	s.events = append(s.events, event)
	return nil
}

func (s *scriptedBidiClient) Recv() (*apiv1.ControlCommand, error) {
	return nil, fmt.Errorf("scripted Recv is unused")
}

func (s *scriptedBidiClient) Header() (metadata.MD, error) { return nil, nil }
func (s *scriptedBidiClient) Trailer() metadata.MD         { return nil }
func (s *scriptedBidiClient) CloseSend() error             { return nil }
func (s *scriptedBidiClient) Context() context.Context     { return s.ctx }
func (s *scriptedBidiClient) SendMsg(any) error            { return nil }
func (s *scriptedBidiClient) RecvMsg(any) error            { return nil }

func (s *scriptedBidiClient) snapshot() []*apiv1.DaemonEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*apiv1.DaemonEvent(nil), s.events...)
}

// blockingEpochStream models a transport whose SendMsg and Recv are both
// blocked until the stream context is canceled. It also records whether a
// CloseSend call raced the active sender; grpc-go explicitly forbids that
// overlap.
type blockingEpochStream struct {
	ctx         context.Context
	sendEntered chan struct{}
	sendOnce    sync.Once

	mu             sync.Mutex
	sendActive     bool
	closeSendCalls int
	closeSendRaced bool
}

func (s *blockingEpochStream) Send(event *apiv1.DaemonEvent) error {
	if event.GetSubscribed() == nil {
		return nil
	}
	s.mu.Lock()
	s.sendActive = true
	s.mu.Unlock()
	s.sendOnce.Do(func() { close(s.sendEntered) })
	<-s.ctx.Done()
	s.mu.Lock()
	s.sendActive = false
	s.mu.Unlock()
	return s.ctx.Err()
}

func (s *blockingEpochStream) Recv() (*apiv1.ControlCommand, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func (s *blockingEpochStream) Header() (metadata.MD, error) { return nil, nil }
func (s *blockingEpochStream) Trailer() metadata.MD         { return nil }
func (s *blockingEpochStream) Context() context.Context     { return s.ctx }
func (s *blockingEpochStream) SendMsg(any) error            { return nil }
func (s *blockingEpochStream) RecvMsg(any) error            { return nil }
func (s *blockingEpochStream) CloseSend() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeSendCalls++
	if s.sendActive {
		s.closeSendRaced = true
	}
	return nil
}

func (s *blockingEpochStream) closeSnapshot() (calls int, raced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeSendCalls, s.closeSendRaced
}

// Stream cancellation, not CloseSend, must release blocked transport calls.
// runStreamEpoch cannot return until both Send and Recv have observed that
// cancellation and all four epoch workers have joined.
func TestRunStreamEpochCancelsBlockedSendAndJoinsWithoutCloseSend(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, time.Second, nil)
	pending := &pendingSubscription{
		sub:      &apiv1.Subscribed{Id: id},
		purpose:  subscriptionPurposeAttach,
		resultCh: make(chan SubscribedAckResult, 1),
	}
	require.NoError(t, client.publishPendingSubscription(pending))

	ctx, cancel := context.WithCancel(context.Background())
	stream := &blockingEpochStream{ctx: ctx, sendEntered: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- client.runStreamEpoch(ctx, cancel, stream, 1)
	}()

	select {
	case <-stream.sendEntered:
	case <-time.After(time.Second):
		t.Fatal("send loop did not enter blocked Send")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runStreamEpoch did not cancel and join blocked stream workers")
	}

	calls, raced := stream.closeSnapshot()
	assert.Zero(t, calls, "cancellation owns stream shutdown; CloseSend must not race Send")
	assert.False(t, raced)
	client.cancelSubscription(id, errors.New("test cleanup"))
}

// If Send(Subscribed) itself fails, its queue item has already been consumed.
// The exact pending entry must retain the payload, be re-driven after the next
// connection's Sync, and resolve from that new epoch's ack.
func TestNormalPendingSubscribeRedrivesAfterSendFailure(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 10*time.Second, nil)

	type result struct {
		ack *apiv1.SubscribedAck
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		ack, err := client.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: id})
		resultCh <- result{ack: ack, err: err}
	}()
	require.Eventually(t, func() bool { return client.hasPendingAck(id) }, time.Second, time.Millisecond)

	stream1 := &scriptedBidiClient{ctx: context.Background(), failSubscribed: true}
	errCh1 := make(chan error, 1)
	client.sendLoop(context.Background(), stream1, 1, errCh1)
	require.Error(t, <-errCh1)
	pending := pendingSubscriptionFor(t, client, id)
	assert.Zero(t, pending.sentEpoch, "failed Send must make the exact pending eligible for redrive")

	ctx2, cancel2 := context.WithCancel(context.Background())
	stream2 := &scriptedBidiClient{ctx: ctx2}
	require.NoError(t, stream2.Send(&apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Sync{Sync: &apiv1.SyncRequest{}},
	}))
	errCh2 := make(chan error, 1)
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		client.sendLoop(ctx2, stream2, 2, errCh2)
	}()
	require.Eventually(t, func() bool {
		return len(stream2.snapshot()) >= 2
	}, time.Second, time.Millisecond)
	assert.Equal(t, []string{"sync", "subscribed:" + id}, eventKinds(stream2.snapshot()))

	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id: id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED,
		}},
	}, 2)
	select {
	case got := <-resultCh:
		require.NoError(t, got.err)
		require.NotNil(t, got.ack)
	case <-time.After(time.Second):
		t.Fatal("redriven normal subscription did not resolve")
	}
	cancel2()
	waitDone(t, done2, "epoch 2 sendLoop did not stop")
}

// A delayed ack from epoch E must not claim a restore retry that belongs to
// epoch E+1, even though both use the same attachment ID.
func TestRestoreRetryIgnoresDelayedAckFromOlderEpoch(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	server.mu.Lock()
	state := server.attachments[id]
	state.needsResync = true
	server.mu.Unlock()
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, time.Second, nil)

	client.startRestoreResyncs(context.Background(), 1)
	first := pendingSubscriptionFor(t, client, id)
	require.True(t, client.beginPendingSend(first, 1))
	client.cancelRestoreSubscriptions(1, errors.New("epoch 1 disconnected"))

	client.startRestoreResyncs(context.Background(), 2)
	second := pendingSubscriptionFor(t, client, id)
	require.NotSame(t, first, second)
	require.True(t, client.beginPendingSend(second, 2))

	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id: id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL,
		}},
	}, 1)
	assert.Same(t, second, pendingSubscriptionFor(t, client, id))
	assert.True(t, server.restoreResyncStillNeeded(id, state))
	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeDisabled, mode, "stale epoch ack must not mutate enforcement")

	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id: id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED,
		}},
	}, 2)
	assert.False(t, server.restoreResyncStillNeeded(id, state))
}

func TestRestoreSubscribedFollowsFreshSync(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	server.mu.Lock()
	server.attachments[id].needsResync = true
	server.mu.Unlock()
	cp := &testControlPlane{}
	addr := startTestControlPlane(t, cp)
	client := newReconnectTestClient(t, addr, server, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := startConnect(client, ctx)
	require.Eventually(t, func() bool {
		return cp.connCount() == 1 && len(cp.conn(0).snapshot()) >= 2
	}, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"sync", "subscribed:" + id}, eventKinds(cp.conn(0).snapshot())[:2])

	cancel()
	waitDone(t, done, "connect did not join all epoch workers after cancellation")
}
