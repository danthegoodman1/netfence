package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

const (
	// defaultKeepaliveTime/-Timeout drive HTTP/2 keepalive pings on the
	// control-plane connection: a ping is sent after keepaliveTime of
	// inactivity and the connection is torn down if no ack arrives within
	// keepaliveTimeout, so a silently dead path (cable pull, dropped NAT
	// mapping, blackhole) is detected in ~Time+Timeout instead of waiting
	// for the kernel's multi-minute TCP retransmission timeout. Note that
	// grpc-go clamps the ping interval to a 10s minimum client-side.
	defaultKeepaliveTime    = 30 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second
	// A configured subscribe_ack_timeout of zero deliberately lets a new
	// Attach return without waiting, but restored attachments must still be
	// ack-driven: otherwise their needsResync flag could never be cleared
	// safely. Background restore attempts use this bounded timeout and retry
	// on a later connection.
	defaultRestoreSubscribeAckTimeout = 5 * time.Second
)

// SubscribedAckResult contains the result of waiting for a SubscribedAck.
type SubscribedAckResult struct {
	Ack *apiv1.SubscribedAck
	Err error
}

type subscriptionPurpose uint8

const (
	subscriptionPurposeAttach subscriptionPurpose = iota
	subscriptionPurposeRestore
)

// pendingSubscription is the exact ownership token for one effective
// Subscribed -> SubscribedAck handshake. The pending map is put-if-absent by
// attachment ID, and outbound queue entries point back to this object, so a
// canceled attempt's stale event cannot become valid merely because a later
// attempt reused the same attachment ID.
type pendingSubscription struct {
	sub      *apiv1.Subscribed
	purpose  subscriptionPurpose
	resultCh chan SubscribedAckResult // nil for background/fire-and-forget waits
	// callerApplies is set only by Server.Attach. A bounded waiter receives a
	// validated ack and atomically commits/applies it itself; a zero-timeout
	// ack waits for Attach's setup barrier before applying in the recv path.
	callerApplies bool
	// state is the exact server attachment this ack may reconcile. It is set
	// for daemon Attach and restore handshakes and provides the per-state
	// reconcile-vs-teardown lock/identity token. It may be nil when callers use
	// SubscribeAndWait directly as a transport handshake without a registered
	// server attachment (kept for API/backward compatibility).
	state *attachmentState

	// Restore-only ownership. restoreEpoch scopes the attempt to one connection
	// so disconnect cleanup cannot clobber a newer retry or a normal Attach
	// subscription.
	restoreEpoch uint64
	// sentEpoch is the connection epoch on which this exact Subscribed was
	// most recently dispatched. Ack claims must match it, preventing a delayed
	// command from an older stream from consuming a newer retry. Guarded by
	// pendingAcksMu; zero means not dispatched in production (epochs start at 1).
	sentEpoch uint64
	timer     *time.Timer // guarded by pendingAcksMu
}

type ControlPlaneClient struct {
	url                 string
	server              *Server
	logger              zerolog.Logger
	metadata            map[string]string
	subscribeAckTimeout time.Duration
	// creds holds the transport (and optional per-RPC) credentials used to
	// dial the control plane, resolved once at startup. May be nil for
	// clients that never dial (unit tests); connect() refuses to dial
	// without a transport credential — there is no insecure fallback.
	creds *ControlPlaneCreds

	// Transport tuning (see SetTransportTuning): keepalive ping cadence for
	// dead-peer detection and the reconnect backoff cap. Always non-zero
	// after NewControlPlaneClient (defaults applied there).
	keepaliveTime       time.Duration
	keepaliveTimeout    time.Duration
	reconnectBackoffMax time.Duration

	mu     sync.RWMutex
	state  apiv1.ConnectionState
	conn   *grpc.ClientConn
	client apiv1.ControlPlaneClient
	stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand]
	cancel context.CancelFunc

	// sendCh is created once and PERSISTS across reconnects, so events
	// queued against a dead connection are still sitting in it when the
	// next connection comes up. Each connection's sendLoop drops those
	// stale events instead of replaying them after the fresh SyncRequest —
	// see sendEpoch and sendLoop.
	sendCh chan outboundEvent

	// sendEpoch is the current connection epoch. connect() increments it
	// BEFORE snapshotting the attachment list for the SyncRequest, and
	// enqueue() stamps every outbound event with the epoch current at
	// enqueue time. An event carrying an older epoch was therefore produced
	// from state that predates the Sync snapshot, so the SyncRequest already
	// sent on the new stream supersedes it and sendLoop drops it (with the
	// single exception of a Subscribed whose ack is still pending).
	sendEpoch atomic.Uint64

	// pendingAcks tracks exact subscription handshakes awaiting a
	// SubscribedAck. A put-if-absent registration prevents duplicate effective
	// work for one attachment and, unlike the old channel-only map, lets
	// reconnect/detach cleanup remove only the attempt it owns.
	pendingAcksMu sync.Mutex
	pendingAcks   map[string]*pendingSubscription

	// admissionStopped is terminal for this client instance. Quarantine or
	// daemon Stop flips it before canceling the current stream so Run cannot
	// reconnect and an already-received ordinary command cannot mutate state.
	admissionStopped atomic.Bool
}

type outboundEvent struct {
	event   *apiv1.DaemonEvent
	pending *pendingSubscription
	// epoch is the connection epoch current when the event was enqueued
	// (see ControlPlaneClient.sendEpoch). sendLoop drops events from an
	// older epoch: the fresh SyncRequest supersedes them.
	epoch uint64
}

var (
	errSubscriptionAlreadyPending = errors.New("subscription already pending")
	errSubscriptionQueueFull      = errors.New("send channel full")
)

// enqueue stamps the event with the current connection epoch and queues it
// without blocking. It returns false when the channel is full — callers
// treat outbound events as best-effort and drop with a warning rather than
// stalling.
func (c *ControlPlaneClient) enqueue(out outboundEvent) bool {
	out.epoch = c.sendEpoch.Load()
	select {
	case c.sendCh <- out:
		return true
	default:
		return false
	}
}

func NewControlPlaneClient(url string, server *Server, logger zerolog.Logger, metadata map[string]string, subscribeAckTimeout time.Duration, creds *ControlPlaneCreds) *ControlPlaneClient {
	return &ControlPlaneClient{
		url:                 url,
		server:              server,
		logger:              logger.With().Str("component", "controlplane").Logger(),
		metadata:            metadata,
		subscribeAckTimeout: subscribeAckTimeout,
		creds:               creds,
		keepaliveTime:       defaultKeepaliveTime,
		keepaliveTimeout:    defaultKeepaliveTimeout,
		reconnectBackoffMax: defaultReconnectBackoffMax,
		state:               apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED,
		sendCh:              make(chan outboundEvent, 100),
		pendingAcks:         make(map[string]*pendingSubscription),
	}
}

// SetTransportTuning overrides the connection-liveness knobs: the HTTP/2
// keepalive ping interval and timeout (dead-peer detection) and the cap on
// the jittered exponential reconnect backoff. A zero value keeps the
// corresponding default — it never disables keepalive or the backoff cap
// (the same "0 means default, not off" convention as ttl_janitor_interval).
// Must be called before Run.
func (c *ControlPlaneClient) SetTransportTuning(keepaliveTime, keepaliveTimeout, reconnectBackoffMax time.Duration) {
	if keepaliveTime > 0 {
		c.keepaliveTime = keepaliveTime
	}
	if keepaliveTimeout > 0 {
		c.keepaliveTimeout = keepaliveTimeout
	}
	if reconnectBackoffMax > 0 {
		c.reconnectBackoffMax = reconnectBackoffMax
	}
}

func (c *ControlPlaneClient) State() apiv1.ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *ControlPlaneClient) setState(state apiv1.ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
}

func (c *ControlPlaneClient) Run(ctx context.Context) {
	// Reconnect pacing: jittered exponential backoff from the floor up to
	// reconnectBackoffMax, so a flapping or overloaded control plane is not
	// hammered on a fixed cadence. The schedule resets to the floor only
	// after a connection stayed CONNECTED for cpConnectionHealthyAge — an
	// instantly-dying connection keeps escalating instead of thrashing.
	backoff := newReconnectBackoff(reconnectBackoffFloor, c.reconnectBackoffMax, nil)
	for {
		if c.admissionStopped.Load() {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
			connectedAt := c.connect(ctx)
			if c.admissionStopped.Load() {
				return
			}
			backoff.noteOutcome(connectedAt, time.Now())
			delay := backoff.next()
			c.logger.Debug().Dur("delay", delay).Msg("waiting before control plane reconnect")
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

// connect dials the control plane, runs the stream until it dies, and
// returns when it became CONNECTED (the zero time if it never did) so Run
// can distinguish a healthy-then-lost connection from one that failed
// outright when deciding whether to reset the reconnect backoff.
func (c *ControlPlaneClient) connect(ctx context.Context) (connectedAt time.Time) {
	if c.admissionStopped.Load() {
		return time.Time{}
	}
	c.setState(apiv1.ConnectionState_CONNECTION_STATE_CONNECTING)
	c.logger.Info().Str("url", c.url).Msg("connecting to control plane")

	// Fail closed: never fall back to plaintext when credentials are
	// missing. Production wiring always resolves them via
	// BuildControlPlaneCreds before constructing the client.
	if c.creds == nil || c.creds.Transport == nil {
		c.logger.Error().Msg("no transport credentials configured for control plane; refusing to dial")
		c.setState(apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED)
		return
	}

	opts := []grpc.DialOption{grpc.WithTransportCredentials(c.creds.Transport)}
	if c.creds.PerRPC != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(c.creds.PerRPC))
	}
	// HTTP/2 keepalive: without it a silently dead TCP path leaves this
	// connection CONNECTED (and every proxied DNS query eating its timeout)
	// until the kernel's TCP retransmission timeout, which takes minutes.
	// PermitWithoutStream keeps liveness checks running even between
	// streams. The control plane must permit this cadence via its keepalive
	// enforcement policy (see README) or it will GOAWAY with
	// ENHANCE_YOUR_CALM ("too_many_pings").
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                c.keepaliveTime,
		Timeout:             c.keepaliveTimeout,
		PermitWithoutStream: true,
	}))

	conn, err := grpc.NewClient(c.url, opts...)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to create grpc client")
		c.setState(apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED)
		return
	}
	defer func() {
		conn.Close()
		c.mu.Lock()
		c.conn = nil
		c.client = nil
		c.mu.Unlock()
	}()

	client := apiv1.NewControlPlaneClient(conn)

	streamCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.conn = conn
	c.client = client
	c.cancel = cancel
	c.mu.Unlock()
	defer cancel()

	stream, err := client.Connect(streamCtx)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to connect stream")
		c.setState(apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED)
		return
	}

	c.mu.Lock()
	c.stream = stream
	c.mu.Unlock()

	// New connection epoch. Bumping BEFORE snapshotting the attachment list
	// below guarantees that any event still queued with an older epoch was
	// produced from state the snapshot already reflects, so the SyncRequest
	// supersedes it and sendLoop can safely drop it. Events enqueued after
	// this point may race the snapshot in either direction — the CP handles
	// that via the idempotency contract documented in control.proto.
	epoch := c.sendEpoch.Add(1)

	syncReq := &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Sync{
			Sync: &apiv1.SyncRequest{
				DaemonId:    c.server.DaemonID(),
				Hostname:    c.server.Hostname(),
				Attachments: c.server.GetSyncAttachments(),
				Metadata:    c.metadata,
			},
		},
	}
	if err := stream.Send(syncReq); err != nil {
		c.logger.Error().Err(err).Msg("failed to send sync request")
		c.setState(apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED)
		return
	}

	c.setState(apiv1.ConnectionState_CONNECTION_STATE_CONNECTED)
	connectedAt = time.Now()
	c.logger.Info().Msg("connected to control plane")

	if err := c.runStreamEpoch(streamCtx, cancel, stream, epoch); err != nil {
		c.logger.Error().Err(err).Msg("stream error")
	}

	c.setState(apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED)
	c.logger.Info().Msg("disconnected from control plane")
	return connectedAt
}

// runStreamEpoch owns every worker that touches one exact gRPC stream after
// its SyncRequest has been sent. Cancellation is the only stream shutdown
// primitive used here: grpc-go permits one concurrent sender and receiver,
// but CloseSend must not race SendMsg. Canceling the stream context unblocks
// both directions; joining all workers before returning ensures the next
// connection epoch is the sole sendCh consumer and recv-loop owner.
func (c *ControlPlaneClient) runStreamEpoch(
	ctx context.Context,
	cancel context.CancelFunc,
	stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand],
	epoch uint64,
) error {
	errCh := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(4)
	go func() {
		defer workers.Done()
		c.sendLoop(ctx, stream, epoch, errCh)
	}()
	go func() {
		defer workers.Done()
		c.recvLoop(stream, epoch, errCh)
	}()
	go func() {
		defer workers.Done()
		c.heartbeatLoop(ctx)
	}()
	// Restored subscriptions are scheduled only after the fresh SyncRequest
	// above has been sent, and they run outside the liveness select. send/recv
	// loops are already active, so a slow/missing ack never blocks ordinary
	// commands/events or stream error detection.
	go func() {
		defer workers.Done()
		c.startRestoreResyncs(ctx, epoch)
	}()

	var streamErr error
	select {
	case <-ctx.Done():
	case streamErr = <-errCh:
	}

	// End restore attempts owned by this connection before returning. Their
	// needsResync flags deliberately remain set; the next connection registers
	// fresh exact attempts after its own SyncRequest. Cancel first so blocked
	// Send/Recv calls unwind and a concurrently-starting scheduler cannot leave
	// a dead-epoch entry behind. Do not CloseSend concurrently with sendLoop.
	cancel()
	c.cancelRestoreSubscriptions(epoch, fmt.Errorf("control plane disconnected"))
	workers.Wait()
	return streamErr
}

// sendLoop drains sendCh onto one connection's stream. epoch is that
// connection's epoch: events stamped with an older one were queued before
// this connection's SyncRequest snapshot (i.e. during or before a previous
// connection) and are dropped — the Sync already conveyed the authoritative
// attachment state, so replaying stale Heartbeats, Unsubscribeds, or
// CommandResults after it would only hand the CP superseded interleavings.
// The one exception is a Subscribed whose ack is STILL pending: a caller
// blocked in SubscribeAndWait across the reconnect needs the CP to see the
// Subscribed on the new stream, because the CP replies SubscribedAck to
// Subscribed, not to Sync. It is re-sent after the SyncRequest (which
// connect() sends directly before starting this loop, so ordering holds by
// construction) and the CP handles the possible re-delivery idempotently
// (see control.proto).
func (c *ControlPlaneClient) sendLoop(ctx context.Context, stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand], epoch uint64, errCh chan<- error) {
	// Re-drive every exact pending subscription after this connection's Sync.
	// This closes the case where the previous sendLoop dequeued Subscribed but
	// stream.Send failed: the pending entry retains the full payload even though
	// its old queue item is gone. Queue duplicates are suppressed by sentEpoch.
	for _, pending := range c.snapshotPendingSubscriptions() {
		if !c.beginPendingSend(pending, epoch) {
			continue
		}
		if err := stream.Send(&apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: pending.sub},
		}); err != nil {
			c.resetPendingSend(pending, epoch)
			errCh <- err
			return
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case outbound := <-c.sendCh:
			if outbound.pending != nil {
				if !c.beginPendingSend(outbound.pending, epoch) {
					c.logger.Debug().Str("id", outbound.pending.sub.Id).Msg("dropping stale or duplicate subscribed event")
					continue
				}
			} else if outbound.epoch < epoch {
				c.logger.Debug().Msg("dropping stale queued event superseded by sync")
				continue
			}
			if err := stream.Send(outbound.event); err != nil {
				if outbound.pending != nil {
					c.resetPendingSend(outbound.pending, epoch)
				}
				errCh <- err
				return
			}
		}
	}
}

func (c *ControlPlaneClient) snapshotPendingSubscriptions() []*pendingSubscription {
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	pending := make([]*pendingSubscription, 0, len(c.pendingAcks))
	for _, subscription := range c.pendingAcks {
		pending = append(pending, subscription)
	}
	return pending
}

// beginPendingSend both validates exact ownership and reserves this connection
// epoch before stream.Send. Reserving first permits an immediate CP response to
// claim the ack; resetPendingSend makes a failed Send eligible for redrive.
func (c *ControlPlaneClient) beginPendingSend(expected *pendingSubscription, epoch uint64) bool {
	if expected == nil || expected.sub == nil {
		return false
	}
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	if c.pendingAcks[expected.sub.Id] != expected {
		return false
	}
	if expected.purpose == subscriptionPurposeRestore && expected.restoreEpoch != epoch {
		return false
	}
	if expected.sentEpoch == epoch {
		return false
	}
	expected.sentEpoch = epoch
	return true
}

func (c *ControlPlaneClient) resetPendingSend(expected *pendingSubscription, epoch uint64) {
	if expected == nil || expected.sub == nil {
		return
	}
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	if c.pendingAcks[expected.sub.Id] == expected && expected.sentEpoch == epoch {
		expected.sentEpoch = 0
	}
}

func (c *ControlPlaneClient) hasPendingAck(id string) bool {
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	_, ok := c.pendingAcks[id]
	return ok
}

// publishPendingSubscription makes the pending-map entry and its initial queue
// item visible atomically with respect to sendLoop snapshots/beginPendingSend.
// Holding pendingAcksMu across the non-blocking enqueue means sendLoop can
// dequeue the item, but cannot validate/send it until publication either fully
// succeeds or is fully rolled back. No ack can therefore be sent and then
// invalidated by a late queue-full branch.
func (c *ControlPlaneClient) publishPendingSubscription(pending *pendingSubscription) error {
	if pending == nil || pending.sub == nil || pending.sub.Id == "" {
		return fmt.Errorf("invalid pending subscription")
	}
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	if _, exists := c.pendingAcks[pending.sub.Id]; exists {
		return errSubscriptionAlreadyPending
	}
	c.pendingAcks[pending.sub.Id] = pending
	outbound := outboundEvent{
		event: &apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: pending.sub},
		},
		pending: pending,
		epoch:   c.sendEpoch.Load(),
	}
	select {
	case c.sendCh <- outbound:
		return nil
	default:
		delete(c.pendingAcks, pending.sub.Id)
		return errSubscriptionQueueFull
	}
}

// takePendingSubscription atomically claims the only ack that may apply to an
// attachment ID. A late/duplicate ack finds no entry and is ignored.
func (c *ControlPlaneClient) takePendingSubscription(id string) *pendingSubscription {
	c.pendingAcksMu.Lock()
	pending := c.pendingAcks[id]
	if pending != nil {
		delete(c.pendingAcks, id)
		if pending.timer != nil {
			pending.timer.Stop()
		}
	}
	c.pendingAcksMu.Unlock()
	return pending
}

func (c *ControlPlaneClient) takePendingSubscriptionForEpoch(id string, epoch uint64) *pendingSubscription {
	c.pendingAcksMu.Lock()
	pending := c.pendingAcks[id]
	// Production connection epochs start at one. Rejecting zero also makes it
	// impossible for an undispatched pending entry (sentEpoch == 0) to accept a
	// synthetic/default-epoch ack.
	if epoch == 0 || pending == nil || pending.sentEpoch != epoch {
		c.pendingAcksMu.Unlock()
		return nil
	}
	delete(c.pendingAcks, id)
	if pending.timer != nil {
		pending.timer.Stop()
	}
	c.pendingAcksMu.Unlock()
	return pending
}

// removePendingSubscription removes only the exact attempt supplied, so an
// old timeout/disconnect cannot erase a newer retry that reused the ID.
func (c *ControlPlaneClient) removePendingSubscription(expected *pendingSubscription) bool {
	if expected == nil || expected.sub == nil {
		return false
	}
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	if c.pendingAcks[expected.sub.Id] != expected {
		return false
	}
	delete(c.pendingAcks, expected.sub.Id)
	if expected.timer != nil {
		expected.timer.Stop()
	}
	return true
}

func (c *ControlPlaneClient) deliverSubscriptionResult(pending *pendingSubscription, result SubscribedAckResult) {
	if pending == nil || pending.resultCh == nil {
		return
	}
	select {
	case pending.resultCh <- result:
	default:
	}
}

// cancelSubscription is called by attachment teardown after the exact server
// state has been unregistered. It unblocks a waiting Attach and invalidates any
// queued Subscribed event; restore attempts retain needsResync automatically.
func (c *ControlPlaneClient) cancelSubscription(id string, err error) {
	pending := c.takePendingSubscription(id)
	if pending == nil {
		return
	}
	c.deliverSubscriptionResult(pending, SubscribedAckResult{Err: err})
}

func (c *ControlPlaneClient) cancelRestoreSubscriptions(epoch uint64, err error) {
	var canceled []*pendingSubscription
	c.pendingAcksMu.Lock()
	for id, pending := range c.pendingAcks {
		if pending.purpose != subscriptionPurposeRestore || pending.restoreEpoch != epoch {
			continue
		}
		delete(c.pendingAcks, id)
		if pending.timer != nil {
			pending.timer.Stop()
		}
		canceled = append(canceled, pending)
	}
	c.pendingAcksMu.Unlock()
	for _, pending := range canceled {
		c.deliverSubscriptionResult(pending, SubscribedAckResult{Err: err})
	}
}

// stopAdmission permanently shuts down this client's command stream. It is
// used for daemon terminal/quarantine state as well as graceful Stop: cancel
// the exact live stream, unblock every pending Attach, and prevent Run from
// reconnecting with the same client instance.
func (c *ControlPlaneClient) stopAdmission(err error) {
	c.admissionStopped.Store(true)
	c.mu.RLock()
	cancel := c.cancel
	c.mu.RUnlock()
	if cancel != nil {
		cancel()
	}

	var pending []*pendingSubscription
	c.pendingAcksMu.Lock()
	for id, subscription := range c.pendingAcks {
		delete(c.pendingAcks, id)
		if subscription.timer != nil {
			subscription.timer.Stop()
		}
		pending = append(pending, subscription)
	}
	c.pendingAcksMu.Unlock()
	for _, subscription := range pending {
		c.deliverSubscriptionResult(subscription, SubscribedAckResult{Err: err})
	}
}

func (c *ControlPlaneClient) restoreSubscribeAckTimeout() time.Duration {
	if c.subscribeAckTimeout > 0 {
		return c.subscribeAckTimeout
	}
	return defaultRestoreSubscribeAckTimeout
}

// startRestoreResyncs registers one bounded background handshake for each
// exact restored attachment still flagged. It never waits for acks itself;
// recvLoop applies them, while timers/disconnect merely invalidate attempts
// and leave needsResync set for a later connection.
func (c *ControlPlaneClient) startRestoreResyncs(ctx context.Context, epoch uint64) {
	timeout := c.restoreSubscribeAckTimeout()
	for _, candidate := range c.server.GetRestoreResyncSubscriptions() {
		if ctx.Err() != nil {
			return
		}
		if candidate.sub == nil || !c.server.restoreResyncStillNeeded(candidate.sub.Id, candidate.state) {
			continue
		}

		pending := &pendingSubscription{
			sub:          candidate.sub,
			purpose:      subscriptionPurposeRestore,
			state:        candidate.state,
			restoreEpoch: epoch,
		}
		if err := c.publishPendingSubscription(pending); err != nil {
			if errors.Is(err, errSubscriptionAlreadyPending) {
				c.logger.Debug().Str("id", candidate.sub.Id).Msg("restore resync already pending; skipping duplicate")
			} else {
				c.logger.Warn().Err(err).Str("id", candidate.sub.Id).
					Msg("could not queue restored attachment resync; will retry after reconnect")
			}
			continue
		}
		if ctx.Err() != nil {
			c.removePendingSubscription(pending)
			return
		}

		// Arm the background timeout only while this exact entry is current.
		timer := time.AfterFunc(timeout, func() {
			if c.removePendingSubscription(pending) {
				c.logger.Warn().Str("id", pending.sub.Id).Dur("timeout", timeout).
					Msg("timeout waiting for restored attachment subscribed ack; will retry after reconnect")
			}
		})
		c.pendingAcksMu.Lock()
		if c.pendingAcks[pending.sub.Id] == pending {
			pending.timer = timer
		} else {
			timer.Stop()
		}
		c.pendingAcksMu.Unlock()

	}
}

func (c *ControlPlaneClient) recvLoop(stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand], epoch uint64, errCh chan<- error) {
	for {
		cmd, err := stream.Recv()
		if err != nil {
			errCh <- err
			return
		}

		c.handleCommandForEpoch(cmd, epoch)
	}
}

func (c *ControlPlaneClient) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			event := outboundEvent{
				event: &apiv1.DaemonEvent{
					Event: &apiv1.DaemonEvent_Heartbeat{
						Heartbeat: &apiv1.Heartbeat{
							Stats: c.server.GetAttachmentStats(),
						},
					},
				},
			}
			if !c.enqueue(event) {
				c.logger.Warn().Msg("send channel full, dropping heartbeat")
			}
		}
	}
}

// handleCommand applies one control-plane command. Every applying case
// yields an outcome (nil = fully applied); when the command carried a
// non-empty command_id, that outcome is reported back as a CommandResult
// event so the control plane can converge on truth instead of assuming
// success. SyncAck and SubscribedAck are pure acks of daemon events and
// never produce results (SubscribedAck already has its own handshake via
// SubscribeAndWait).
func (c *ControlPlaneClient) handleCommand(cmd *apiv1.ControlCommand) {
	c.handleCommandForEpoch(cmd, c.sendEpoch.Load())
}

// handleCommandForEpoch applies a command received on one exact stream epoch.
// Only SubscribedAck uses the epoch: a delayed ack from an older recvLoop must
// not claim a newer restore retry for the same attachment ID.
func (c *ControlPlaneClient) handleCommandForEpoch(cmd *apiv1.ControlCommand, epoch uint64) {
	var err error
	reportResult := true
	if c.admissionStopped.Load() {
		switch cmd.Command.(type) {
		case *apiv1.ControlCommand_SyncAck, *apiv1.ControlCommand_SubscribedAck:
			return
		default:
			c.sendCommandResult(cmd.CommandId, cmd.Id, fmt.Errorf("control-plane command admission is stopped"))
			return
		}
	}
	if c.server != nil {
		done, ok := c.server.beginControlCommand(cmd.Id)
		if !ok {
			switch cmd.Command.(type) {
			case *apiv1.ControlCommand_SyncAck, *apiv1.ControlCommand_SubscribedAck:
				return
			default:
				c.sendCommandResult(cmd.CommandId, cmd.Id, fmt.Errorf("daemon is stopping"))
				return
			}
		}
		defer done()
	}

	switch v := cmd.Command.(type) {
	case *apiv1.ControlCommand_SyncAck:
		c.logger.Debug().Msg("received sync ack")
		reportResult = false

	case *apiv1.ControlCommand_SetMode:
		c.logger.Debug().Str("id", cmd.Id).Str("mode", v.SetMode.Mode.String()).Msg("received set mode")
		if err = c.server.SetFilterMode(cmd.Id, v.SetMode.Mode); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to set filter mode")
			err = fmt.Errorf("setting filter mode: %w", err)
		}

	case *apiv1.ControlCommand_AllowCidr:
		c.logger.Debug().Str("id", cmd.Id).Str("cidr", v.AllowCidr.Cidr).Msg("received allow cidr")
		cidr, parseErr := filter.ParseCIDR(v.AllowCidr.Cidr)
		if parseErr != nil {
			c.logger.Error().Err(parseErr).Str("id", cmd.Id).Str("cidr", v.AllowCidr.Cidr).Msg("failed to parse CIDR")
			err = fmt.Errorf("parsing CIDR %q: %w", v.AllowCidr.Cidr, parseErr)
		} else if err = c.server.AllowCIDR(cmd.Id, cidr, v.AllowCidr.GetTtl().AsDuration()); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to allow CIDR")
			err = fmt.Errorf("allowing CIDR %q: %w", v.AllowCidr.Cidr, err)
		}

	case *apiv1.ControlCommand_DenyCidr:
		c.logger.Debug().Str("id", cmd.Id).Str("cidr", v.DenyCidr.Cidr).Msg("received deny cidr")
		cidr, parseErr := filter.ParseCIDR(v.DenyCidr.Cidr)
		if parseErr != nil {
			c.logger.Error().Err(parseErr).Str("id", cmd.Id).Str("cidr", v.DenyCidr.Cidr).Msg("failed to parse CIDR")
			err = fmt.Errorf("parsing CIDR %q: %w", v.DenyCidr.Cidr, parseErr)
		} else if err = c.server.DenyCIDR(cmd.Id, cidr, v.DenyCidr.GetTtl().AsDuration()); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to deny CIDR")
			err = fmt.Errorf("denying CIDR %q: %w", v.DenyCidr.Cidr, err)
		}

	case *apiv1.ControlCommand_RemoveCidr:
		c.logger.Debug().Str("id", cmd.Id).Str("cidr", v.RemoveCidr).Msg("received remove cidr")
		cidr, parseErr := filter.ParseCIDR(v.RemoveCidr)
		if parseErr != nil {
			c.logger.Error().Err(parseErr).Str("id", cmd.Id).Str("cidr", v.RemoveCidr).Msg("failed to parse CIDR")
			err = fmt.Errorf("parsing CIDR %q: %w", v.RemoveCidr, parseErr)
			break
		}
		var allowErr, denyErr error
		if allowErr = c.server.RemoveAllowedCIDR(cmd.Id, cidr); allowErr != nil {
			c.logger.Warn().Err(allowErr).Str("id", cmd.Id).Msg("failed to remove CIDR from allowlist")
			allowErr = fmt.Errorf("removing from allowlist: %w", allowErr)
		}
		if denyErr = c.server.RemoveDeniedCIDR(cmd.Id, cidr); denyErr != nil {
			c.logger.Warn().Err(denyErr).Str("id", cmd.Id).Msg("failed to remove CIDR from denylist")
			denyErr = fmt.Errorf("removing from denylist: %w", denyErr)
		}
		err = errors.Join(allowErr, denyErr)

	case *apiv1.ControlCommand_BulkUpdate:
		c.logger.Debug().Str("id", cmd.Id).Msg("received bulk update")
		err = c.applyBulkUpdate(cmd.Id, v.BulkUpdate)

	case *apiv1.ControlCommand_SetDnsMode:
		c.logger.Debug().Str("id", cmd.Id).Str("mode", v.SetDnsMode.Mode.String()).Msg("received set dns mode")
		if err = c.server.SetDnsMode(cmd.Id, v.SetDnsMode.Mode); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to set dns mode")
			err = fmt.Errorf("setting DNS mode: %w", err)
		}

	case *apiv1.ControlCommand_AllowDomain:
		c.logger.Debug().Str("id", cmd.Id).Str("domain", v.AllowDomain.Domain).Msg("received allow domain")
		if err = c.server.AllowDomain(cmd.Id, v.AllowDomain.Domain, v.AllowDomain.IncludeSubdomains); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to allow domain")
			err = fmt.Errorf("allowing domain %q: %w", v.AllowDomain.Domain, err)
		}

	case *apiv1.ControlCommand_DenyDomain:
		c.logger.Debug().Str("id", cmd.Id).Str("domain", v.DenyDomain.Domain).Msg("received deny domain")
		if err = c.server.DenyDomain(cmd.Id, v.DenyDomain.Domain, v.DenyDomain.IncludeSubdomains); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to deny domain")
			err = fmt.Errorf("denying domain %q: %w", v.DenyDomain.Domain, err)
		}

	case *apiv1.ControlCommand_RemoveDomain:
		c.logger.Debug().Str("id", cmd.Id).Str("domain", v.RemoveDomain).Msg("received remove domain")
		if err = c.server.RemoveDomain(cmd.Id, v.RemoveDomain); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to remove domain")
			err = fmt.Errorf("removing domain %q: %w", v.RemoveDomain, err)
		}

	case *apiv1.ControlCommand_SubscribedAck:
		c.logger.Debug().Str("id", cmd.Id).Msg("received subscribed ack")
		reportResult = false
		pending := c.takePendingSubscriptionForEpoch(cmd.Id, epoch)
		if pending == nil {
			// The attempt timed out, disconnected, detached, or already consumed
			// this ack. Applying it now could mutate removed/replaced state.
			c.logger.Debug().Str("id", cmd.Id).Msg("ignoring subscribed ack with no exact pending subscription")
			break
		}

		err = c.applyPendingSubscribedAck(cmd.Id, pending, v.SubscribedAck)
		if err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to apply subscribed ack")
		}
		c.deliverSubscriptionResult(pending, SubscribedAckResult{Ack: v.SubscribedAck, Err: err})
		if pending.purpose == subscriptionPurposeAttach && pending.callerApplies && pending.resultCh != nil && pending.state != nil {
			// Preserve control-stream order across the bounded Attach handoff. The
			// ack has been claimed and delivered, but Attach owns apply+commit; do
			// not let recvLoop process the following command until Attach either
			// applies/quarantines successfully or rolls setup back.
			if pending.state.setupDone != nil {
				<-pending.state.setupDone
			}
		}

	default:
		c.logger.Warn().Str("id", cmd.Id).Msg("received unknown command")
		err = fmt.Errorf("unknown command type")
	}

	if reportResult {
		c.sendCommandResult(cmd.CommandId, cmd.Id, err)
	}
}

// sendCommandResult reports a command outcome back to the control plane,
// echoing its correlation id. Commands without a command_id (the default)
// produce no result — opt-in, backward compatible. The send is
// non-blocking: a saturated event channel drops the result with a warning
// rather than stalling the receive loop (results are best-effort by
// contract; the CP treats a missing result as unknown).
func (c *ControlPlaneClient) sendCommandResult(commandID, attachmentID string, cmdErr error) {
	if commandID == "" {
		return
	}
	result := &apiv1.CommandResult{
		CommandId: commandID,
		Id:        attachmentID,
		Success:   cmdErr == nil,
	}
	if cmdErr != nil {
		result.Error = cmdErr.Error()
	}
	if !c.enqueue(outboundEvent{event: &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_CommandResult{CommandResult: result},
	}}) {
		c.logger.Warn().Str("command_id", commandID).Str("id", attachmentID).Msg("send channel full, dropping command result")
	}
}

// SubscribeAndWait sends a Subscribed event and waits for the control plane to
// acknowledge it with initial configuration. Returns the ack, or an error if
// the timeout is reached or the connection is lost.
//
// If subscribeAckTimeout is 0, this returns immediately without waiting, but
// keeps an exact fire-and-forget pending entry so a later ack is still applied
// safely. (Restored-attachment handshakes use a separate bounded background
// timeout and are always ack-driven.)
func (c *ControlPlaneClient) SubscribeAndWait(ctx context.Context, sub *apiv1.Subscribed) (*apiv1.SubscribedAck, error) {
	return c.subscribeAndWait(ctx, sub, false)
}

func (c *ControlPlaneClient) subscribeForAttachAndWait(ctx context.Context, sub *apiv1.Subscribed) (*apiv1.SubscribedAck, error) {
	return c.subscribeAndWait(ctx, sub, true)
}

func (c *ControlPlaneClient) subscribeAndWait(ctx context.Context, sub *apiv1.Subscribed, callerApplies bool) (*apiv1.SubscribedAck, error) {
	if sub == nil || sub.Id == "" {
		return nil, fmt.Errorf("subscribed attachment id is required")
	}

	pending := &pendingSubscription{
		sub:           sub,
		purpose:       subscriptionPurposeAttach,
		callerApplies: callerApplies,
	}
	if c.server != nil {
		pending.state = c.server.getAttachmentState(sub.Id)
	}
	if c.subscribeAckTimeout != 0 {
		pending.resultCh = make(chan SubscribedAckResult, 1)
	}
	if err := c.publishPendingSubscription(pending); err != nil {
		if errors.Is(err, errSubscriptionAlreadyPending) {
			return nil, fmt.Errorf("subscription already pending for attachment %s", sub.Id)
		}
		return nil, err
	}
	if c.subscribeAckTimeout == 0 {
		return nil, nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, c.subscribeAckTimeout)
	defer cancel()

	select {
	case result := <-pending.resultCh:
		return result.Ack, result.Err
	case <-timeoutCtx.Done():
		if c.removePendingSubscription(pending) {
			return nil, fmt.Errorf("waiting for subscribed ack from control plane: %w", timeoutCtx.Err())
		}
		// The receive loop already claimed this exact ack. It will deliver the
		// result and, for Attach-owned apply, wait on setupDone before processing
		// the next stream command. Consume the claimed result even though the
		// timer fired so Attach can finish that handoff and release the barrier.
		result := <-pending.resultCh
		return result.Ack, result.Err
	}
}

func (c *ControlPlaneClient) SendUnsubscribed(unsub *apiv1.Unsubscribed) {
	if !c.enqueue(outboundEvent{event: &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Unsubscribed{Unsubscribed: unsub},
	}}) {
		c.logger.Warn().Str("id", unsub.Id).Msg("send channel full, dropping unsubscribed event")
	}
}

func (c *ControlPlaneClient) MakeProxyFunc(attachmentID string) DnsProxyFunc {
	return func(ctx context.Context, domain, queryType string) (DnsProxyDecision, error) {
		c.mu.RLock()
		client := c.client
		state := c.state
		c.mu.RUnlock()

		if client == nil || state != apiv1.ConnectionState_CONNECTION_STATE_CONNECTED {
			return DnsProxyDecision{}, errDNSProxyUnavailable
		}

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		resp, err := client.QueryDns(ctx, &apiv1.DnsQueryRequest{
			Id:        attachmentID,
			Domain:    domain,
			QueryType: queryType,
		})
		if err != nil {
			return DnsProxyDecision{}, err
		}

		return DnsProxyDecision{
			Allow:       resp.GetAllow(),
			AddToFilter: resp.GetAddToFilter(),
			IPs:         resp.GetIps(),
			TTLSeconds:  resp.GetTtlSeconds(),
		}, nil
	}
}

func (c *ControlPlaneClient) applyPendingSubscribedAck(id string, pending *pendingSubscription, ack *apiv1.SubscribedAck) error {
	if pending == nil {
		return fmt.Errorf("subscription is nil")
	}
	if pending.state == nil {
		if pending.purpose == subscriptionPurposeRestore {
			return fmt.Errorf("restored subscription has no live attachment state")
		}
		// SubscribeAndWait predates server-owned attachment reconciliation and is
		// also used directly to verify/control the stream transport. Preserve that
		// handshake mode when no corresponding server state exists: the ack is
		// delivered to the caller but there is intentionally nothing to apply.
		return nil
	}
	zeroTimeoutAttach := pending.purpose == subscriptionPurposeAttach && pending.callerApplies && pending.resultCh == nil
	var attachValidationErr error
	if pending.purpose == subscriptionPurposeAttach && pending.callerApplies {
		attachValidationErr = c.validateSubscribedAck(id, ack)
		if pending.resultCh != nil {
			// The Attach goroutine owns the apply+commit boundary. Delivering a
			// validated immutable ack cannot change the staged BLOCK_ALL filter.
			return attachValidationErr
		}
		// Zero-timeout fire-and-forget: an ack may beat Attach's final commit.
		// Wait without reconcileMu; Attach needs that lock to finish setup.
		if pending.state.setupDone == nil {
			return fmt.Errorf("attach subscription has no setup barrier")
		}
		<-pending.state.setupDone
		if !pending.state.setupCommitted.Load() {
			return fmt.Errorf("attachment setup did not commit")
		}
	}

	// Teardown never waits for reconcileMu while holding Server.mu. Whichever
	// side wins this exact-state lock completes atomically with respect to the
	// other: ack-first fully applies before teardown; teardown-first unregisters
	// the state, causing the exact-live check below to reject the stale ack.
	pending.state.reconcileMu.Lock()
	defer pending.state.reconcileMu.Unlock()
	if !c.server.attachmentStateStillLive(id, pending.state) {
		return fmt.Errorf("attachment is no longer live")
	}
	if pending.purpose == subscriptionPurposeRestore &&
		!c.server.restoreResyncStillNeeded(id, pending.state) {
		return fmt.Errorf("restored attachment no longer needs resync")
	}
	if attachValidationErr != nil {
		quarantineErr := c.server.quarantineAttachment(id, pending.state)
		c.SendUnsubscribed(&apiv1.Unsubscribed{
			Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR,
			Error: "initial control-plane policy failed validation",
		})
		return errors.Join(attachValidationErr, quarantineErr)
	}

	if err := c.applySubscribedAck(id, ack); err != nil {
		if zeroTimeoutAttach {
			quarantineErr := c.server.quarantineAttachment(id, pending.state)
			c.SendUnsubscribed(&apiv1.Unsubscribed{
				Id: id, Reason: apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR,
				Error: "initial control-plane policy failed to apply",
			})
			return errors.Join(err, quarantineErr)
		}
		return err
	}
	if pending.purpose == subscriptionPurposeRestore {
		if !c.server.clearRestoreResync(id, pending.state) {
			return fmt.Errorf("restored attachment changed while applying subscribed ack")
		}
		c.logger.Info().Str("id", id).Msg("restored attachment converged to fresh control-plane state")
	}
	return nil
}

func (c *ControlPlaneClient) validateSubscribedAck(id string, ack *apiv1.SubscribedAck) error {
	if ack == nil {
		return fmt.Errorf("subscribed ack is nil")
	}
	if err := validateFullDesiredModes(ack.Mode, ack.Dns); err != nil {
		return err
	}
	var requestedUpstreams []string
	if ack.Dns != nil {
		requestedUpstreams = ack.Dns.UpstreamServers
	}
	if _, err := normalizeUpstreamServers(requestedUpstreams, c.server.defaultDNSUpstream); err != nil {
		return fmt.Errorf("validating DNS upstreams: %w", err)
	}
	_, _, err := c.parseBulkCIDRs(id, &apiv1.BulkUpdate{
		Mode:       ack.Mode,
		AllowCidrs: ack.AllowCidrs,
		DenyCidrs:  ack.DenyCidrs,
		Dns:        ack.Dns,
	})
	return err
}

func (c *ControlPlaneClient) applySubscribedAck(id string, ack *apiv1.SubscribedAck) error {
	if ack == nil {
		return fmt.Errorf("subscribed ack is nil")
	}
	// SubscribedAck declares the complete desired state, just like a
	// BulkUpdate. Routing it through the same parse-first, window-free delta
	// reconcile removes stale restored rules without ever removing survivors;
	// nil DNS is authoritative disabled/empty state too.
	return c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       ack.Mode,
		AllowCidrs: ack.AllowCidrs,
		DenyCidrs:  ack.DenyCidrs,
		Dns:        ack.Dns,
	})
}

// applyBulkUpdate reconciles the attachment to the declared state with
// add/remove deltas instead of the old wipe-then-rebuild: a rule present in
// both the old and new state is never removed from the kernel map, so a
// control-plane resync opens no transient allow/block window, and
// DNS-populated filter IPs survive (they age out via their own DNS TTLs,
// Phase 2B). Any validation/parse error aborts BEFORE any mutation. The
// returned error aggregates every failed step — a partially-applied bulk
// update is a failure, never reported as success.
func (c *ControlPlaneClient) applyBulkUpdate(id string, update *apiv1.BulkUpdate) error {
	if update == nil {
		return fmt.Errorf("bulk update is nil")
	}
	if err := validateFullDesiredModes(update.Mode, update.Dns); err != nil {
		return err
	}
	var requestedUpstreams []string
	if update.Dns != nil {
		requestedUpstreams = update.Dns.UpstreamServers
	}
	normalizedUpstreams, err := normalizeUpstreamServers(requestedUpstreams, c.server.defaultDNSUpstream)
	if err != nil {
		return fmt.Errorf("validating DNS upstreams: %w", err)
	}
	allowCIDRs, denyCIDRs, parseErr := c.parseBulkCIDRs(id, update)
	if parseErr != nil {
		return parseErr
	}
	state, done, admissionErr := c.server.beginAttachmentMutation(id)
	if admissionErr != nil {
		return admissionErr
	}
	defer done()

	// ReconcileCIDRs owns the mode write too, sandwiching it between the
	// two list reconciles (new mode's list first) so no mode pair opens a
	// transient allow/block window — see its doc comment.
	reconcileErr := c.server.reconcileCIDRsAdmitted(id, state, update.Mode, allowCIDRs, denyCIDRs)
	if reconcileErr != nil {
		c.logger.Error().Err(reconcileErr).Str("id", id).Msg("failed to reconcile CIDRs in bulk update")
		reconcileErr = fmt.Errorf("reconciling CIDRs: %w", reconcileErr)
	}

	// Domain rules are replaced wholesale as before; DNS-populated filter
	// IPs are deliberately NOT wiped (clients still hold them in resolver
	// caches) — the janitor expires them by their DNS TTLs.
	var dnsErr error
	if update.Dns == nil {
		if dnsErr = c.server.replaceDNSRulesAdmitted(id, state, apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil, normalizedUpstreams); dnsErr != nil {
			c.logger.Error().Err(dnsErr).Str("id", id).Msg("failed to clear DNS rules in bulk update")
			dnsErr = fmt.Errorf("clearing DNS rules: %w", dnsErr)
		}
	} else if dnsErr = c.server.replaceDNSRulesAdmitted(id, state, update.Dns.Mode, update.Dns.AllowDomains, update.Dns.DenyDomains, normalizedUpstreams); dnsErr != nil {
		c.logger.Error().Err(dnsErr).Str("id", id).Msg("failed to replace DNS rules in bulk update")
		dnsErr = fmt.Errorf("replacing DNS rules: %w", dnsErr)
	}

	return errors.Join(reconcileErr, dnsErr)
}

// validateFullDesiredModes rejects unknown/UNSPECIFIED enum values before an
// authoritative update reaches any filter, DNS, TTL, or store mutation. In
// particular, the API-to-filter conversion defaults unknown values to
// DISABLED; allowing that fallback here would turn malformed full desired
// state into a successful fail-open mode change.
func validateFullDesiredModes(mode apiv1.PolicyMode, dns *apiv1.DnsConfig) error {
	switch mode {
	case apiv1.PolicyMode_POLICY_MODE_DISABLED,
		apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL,
		apiv1.PolicyMode_POLICY_MODE_DENYLIST:
	default:
		return fmt.Errorf("invalid policy mode in full desired state: %d", mode)
	}
	if dns == nil {
		return nil
	}
	switch dns.Mode {
	case apiv1.DnsMode_DNS_MODE_DISABLED,
		apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		apiv1.DnsMode_DNS_MODE_DENYLIST,
		apiv1.DnsMode_DNS_MODE_PROXY:
		return nil
	default:
		return fmt.Errorf("invalid DNS mode in full desired state: %d", dns.Mode)
	}
}

// parsedCIDR is a parsed CIDREntry: the network plus its TTL (0 = permanent).
type parsedCIDR struct {
	cidr *net.IPNet
	ttl  time.Duration
}

// parseBulkCIDRs parses both CIDR lists up front; any invalid entry fails
// the whole bulk update before anything is mutated.
func (c *ControlPlaneClient) parseBulkCIDRs(id string, update *apiv1.BulkUpdate) (allowCIDRs, denyCIDRs []parsedCIDR, err error) {
	allowCIDRs, err = c.parseDesiredCIDRs(id, "allow", update.AllowCidrs)
	if err != nil {
		return nil, nil, err
	}
	denyCIDRs, err = c.parseDesiredCIDRs(id, "deny", update.DenyCidrs)
	if err != nil {
		return nil, nil, err
	}
	return allowCIDRs, denyCIDRs, nil
}

func (c *ControlPlaneClient) parseDesiredCIDRs(id, list string, entries []*apiv1.CIDREntry) ([]parsedCIDR, error) {
	parsed := make([]parsedCIDR, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		if entry == nil {
			return nil, fmt.Errorf("%s CIDR entry %d is nil", list, i)
		}
		cidr, err := filter.ParseCIDR(entry.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).
				Msg("failed to parse CIDR in full desired state")
			return nil, fmt.Errorf("parsing %s CIDR %q: %w", list, entry.Cidr, err)
		}
		canonical := cidr.String()
		if _, duplicate := seen[canonical]; duplicate {
			return nil, fmt.Errorf("duplicate %s CIDR %q (canonical %s)", list, entry.Cidr, canonical)
		}
		seen[canonical] = struct{}{}

		ttl, err := exactNonNegativeDuration(entry.Ttl)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL for %s CIDR %q: %w", list, entry.Cidr, err)
		}
		parsed = append(parsed, parsedCIDR{cidr: cidr, ttl: ttl})
	}
	return parsed, nil
}

// exactNonNegativeDuration rejects protobuf durations that the generated
// AsDuration helper would normalize or clamp. In a full desired state, silently
// turning a negative/clamped TTL into a permanent or different lifetime is an
// over-allow and must fail before any mutation. Nil/zero means permanent.
func exactNonNegativeDuration(value *durationpb.Duration) (time.Duration, error) {
	if value == nil {
		return 0, nil
	}
	if err := value.CheckValid(); err != nil {
		return 0, err
	}
	duration := value.AsDuration()
	if duration < 0 {
		return 0, fmt.Errorf("negative duration")
	}
	roundTrip := durationpb.New(duration)
	if roundTrip.Seconds != value.Seconds || roundTrip.Nanos != value.Nanos {
		return 0, fmt.Errorf("duration is outside time.Duration range")
	}
	return duration, nil
}
