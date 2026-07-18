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
)

// SubscribedAckResult contains the result of waiting for a SubscribedAck.
type SubscribedAckResult struct {
	Ack *apiv1.SubscribedAck
	Err error
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

	// pendingAcks tracks subscriptions waiting for SubscribedAck responses.
	// Key is attachment ID, value is the channel to send the result on.
	pendingAcksMu sync.Mutex
	pendingAcks   map[string]chan SubscribedAckResult
}

type outboundEvent struct {
	event             *apiv1.DaemonEvent
	subscribedID      string
	requirePendingAck bool
	// epoch is the connection epoch current when the event was enqueued
	// (see ControlPlaneClient.sendEpoch). sendLoop drops events from an
	// older epoch: the fresh SyncRequest supersedes them.
	epoch uint64
}

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
		pendingAcks:         make(map[string]chan SubscribedAckResult),
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
		select {
		case <-ctx.Done():
			return
		default:
			connectedAt := c.connect(ctx)
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

	errCh := make(chan error, 2)

	go c.sendLoop(streamCtx, stream, epoch, errCh)
	go c.recvLoop(stream, errCh)
	go c.heartbeatLoop(streamCtx)

	select {
	case <-streamCtx.Done():
	case err := <-errCh:
		if err != nil {
			c.logger.Error().Err(err).Msg("stream error")
		}
	}

	c.setState(apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED)
	c.logger.Info().Msg("disconnected from control plane")
	return connectedAt
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
	for {
		select {
		case <-ctx.Done():
			return
		case outbound := <-c.sendCh:
			if outbound.requirePendingAck && !c.hasPendingAck(outbound.subscribedID) {
				c.logger.Debug().Str("id", outbound.subscribedID).Msg("dropping stale subscribed event")
				continue
			}
			if outbound.epoch < epoch && !outbound.requirePendingAck {
				c.logger.Debug().Msg("dropping stale queued event superseded by sync")
				continue
			}
			if err := stream.Send(outbound.event); err != nil {
				errCh <- err
				return
			}
		}
	}
}

func (c *ControlPlaneClient) hasPendingAck(id string) bool {
	c.pendingAcksMu.Lock()
	defer c.pendingAcksMu.Unlock()
	_, ok := c.pendingAcks[id]
	return ok
}

func (c *ControlPlaneClient) recvLoop(stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand], errCh chan<- error) {
	for {
		cmd, err := stream.Recv()
		if err != nil {
			errCh <- err
			return
		}

		c.handleCommand(cmd)
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
	var err error
	reportResult := true

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
		c.applySubscribedAck(cmd.Id, v.SubscribedAck)
		c.pendingAcksMu.Lock()
		if ch, ok := c.pendingAcks[cmd.Id]; ok {
			select {
			case ch <- SubscribedAckResult{Ack: v.SubscribedAck}:
			default:
			}
			delete(c.pendingAcks, cmd.Id)
		}
		c.pendingAcksMu.Unlock()
		reportResult = false

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
// If subscribeAckTimeout is 0, this returns immediately without waiting.
func (c *ControlPlaneClient) SubscribeAndWait(ctx context.Context, sub *apiv1.Subscribed) (*apiv1.SubscribedAck, error) {
	if c.subscribeAckTimeout == 0 {
		if !c.enqueue(outboundEvent{event: &apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: sub},
		}}) {
			return nil, fmt.Errorf("send channel full")
		}
		return nil, nil
	}

	resultCh := make(chan SubscribedAckResult, 1)

	c.pendingAcksMu.Lock()
	c.pendingAcks[sub.Id] = resultCh
	c.pendingAcksMu.Unlock()

	if !c.enqueue(outboundEvent{
		event: &apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: sub},
		},
		subscribedID:      sub.Id,
		requirePendingAck: true,
	}) {
		c.pendingAcksMu.Lock()
		delete(c.pendingAcks, sub.Id)
		c.pendingAcksMu.Unlock()
		return nil, fmt.Errorf("send channel full")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, c.subscribeAckTimeout)
	defer cancel()

	select {
	case result := <-resultCh:
		return result.Ack, result.Err
	case <-timeoutCtx.Done():
		c.pendingAcksMu.Lock()
		delete(c.pendingAcks, sub.Id)
		c.pendingAcksMu.Unlock()
		return nil, fmt.Errorf("timeout waiting for subscribed ack from control plane")
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
	return func(domain, queryType string) (DnsProxyDecision, error) {
		c.mu.RLock()
		client := c.client
		state := c.state
		c.mu.RUnlock()

		if client == nil || state != apiv1.ConnectionState_CONNECTION_STATE_CONNECTED {
			return DnsProxyDecision{}, errDNSProxyUnavailable
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

func (c *ControlPlaneClient) applySubscribedAck(id string, ack *apiv1.SubscribedAck) {
	if ack == nil {
		return
	}
	if err := c.server.SetFilterMode(id, ack.Mode); err != nil {
		c.logger.Error().Err(err).Str("id", id).Msg("failed to set filter mode from subscribed ack")
	}

	for _, entry := range ack.AllowCidrs {
		cidr, err := filter.ParseCIDR(entry.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse allow CIDR in subscribed ack")
			continue
		}
		if err := c.server.AllowCIDR(id, cidr, entry.GetTtl().AsDuration()); err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to allow CIDR in subscribed ack")
		}
	}

	for _, entry := range ack.DenyCidrs {
		cidr, err := filter.ParseCIDR(entry.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse deny CIDR in subscribed ack")
			continue
		}
		if err := c.server.DenyCIDR(id, cidr, entry.GetTtl().AsDuration()); err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to deny CIDR in subscribed ack")
		}
	}

	if ack.Dns != nil {
		if err := c.server.ReplaceDNSRules(id, ack.Dns.Mode, ack.Dns.AllowDomains, ack.Dns.DenyDomains); err != nil {
			c.logger.Error().Err(err).Str("id", id).Msg("failed to replace DNS rules in subscribed ack")
		}
	}
}

// applyBulkUpdate reconciles the attachment to the declared state with
// add/remove deltas instead of the old wipe-then-rebuild: a rule present in
// both the old and new state is never removed from the kernel map, so a
// control-plane resync opens no transient allow/block window, and
// DNS-populated filter IPs survive (they age out via their own DNS TTLs,
// Phase 2B). Any parse error aborts BEFORE any mutation. The returned
// error aggregates every failed step — a partially-applied bulk update is
// a failure, never reported as success.
func (c *ControlPlaneClient) applyBulkUpdate(id string, update *apiv1.BulkUpdate) error {
	if update == nil {
		return nil
	}
	allowCIDRs, denyCIDRs, parseErr := c.parseBulkCIDRs(id, update)
	if parseErr != nil {
		return parseErr
	}

	// ReconcileCIDRs owns the mode write too, sandwiching it between the
	// two list reconciles (new mode's list first) so no mode pair opens a
	// transient allow/block window — see its doc comment.
	reconcileErr := c.server.ReconcileCIDRs(id, update.Mode, allowCIDRs, denyCIDRs)
	if reconcileErr != nil {
		c.logger.Error().Err(reconcileErr).Str("id", id).Msg("failed to reconcile CIDRs in bulk update")
		reconcileErr = fmt.Errorf("reconciling CIDRs: %w", reconcileErr)
	}

	// Domain rules are replaced wholesale as before; DNS-populated filter
	// IPs are deliberately NOT wiped (clients still hold them in resolver
	// caches) — the janitor expires them by their DNS TTLs.
	var dnsErr error
	if update.Dns == nil {
		if dnsErr = c.server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DISABLED, nil, nil); dnsErr != nil {
			c.logger.Error().Err(dnsErr).Str("id", id).Msg("failed to clear DNS rules in bulk update")
			dnsErr = fmt.Errorf("clearing DNS rules: %w", dnsErr)
		}
	} else if dnsErr = c.server.ReplaceDNSRules(id, update.Dns.Mode, update.Dns.AllowDomains, update.Dns.DenyDomains); dnsErr != nil {
		c.logger.Error().Err(dnsErr).Str("id", id).Msg("failed to replace DNS rules in bulk update")
		dnsErr = fmt.Errorf("replacing DNS rules: %w", dnsErr)
	}

	return errors.Join(reconcileErr, dnsErr)
}

// parsedCIDR is a parsed CIDREntry: the network plus its TTL (0 = permanent).
type parsedCIDR struct {
	cidr *net.IPNet
	ttl  time.Duration
}

// parseBulkCIDRs parses both CIDR lists up front; any invalid entry fails
// the whole bulk update before anything is mutated.
func (c *ControlPlaneClient) parseBulkCIDRs(id string, update *apiv1.BulkUpdate) (allowCIDRs, denyCIDRs []parsedCIDR, err error) {
	for _, entry := range update.AllowCidrs {
		cidr, parseErr := filter.ParseCIDR(entry.Cidr)
		if parseErr != nil {
			c.logger.Error().Err(parseErr).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse allow CIDR in bulk update")
			return nil, nil, fmt.Errorf("parsing allow CIDR %q: %w", entry.Cidr, parseErr)
		}
		allowCIDRs = append(allowCIDRs, parsedCIDR{cidr: cidr, ttl: entry.GetTtl().AsDuration()})
	}

	for _, entry := range update.DenyCidrs {
		cidr, parseErr := filter.ParseCIDR(entry.Cidr)
		if parseErr != nil {
			c.logger.Error().Err(parseErr).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse deny CIDR in bulk update")
			return nil, nil, fmt.Errorf("parsing deny CIDR %q: %w", entry.Cidr, parseErr)
		}
		denyCIDRs = append(denyCIDRs, parsedCIDR{cidr: cidr, ttl: entry.GetTtl().AsDuration()})
	}

	return allowCIDRs, denyCIDRs, nil
}
