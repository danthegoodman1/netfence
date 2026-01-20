package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
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

	mu     sync.RWMutex
	state  apiv1.ConnectionState
	conn   *grpc.ClientConn
	client apiv1.ControlPlaneClient
	stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand]
	cancel context.CancelFunc

	sendCh chan *apiv1.DaemonEvent

	// pendingAcks tracks subscriptions waiting for SubscribedAck responses.
	// Key is attachment ID, value is the channel to send the result on.
	pendingAcksMu sync.Mutex
	pendingAcks   map[string]chan SubscribedAckResult
}

func NewControlPlaneClient(url string, server *Server, logger zerolog.Logger, metadata map[string]string, subscribeAckTimeout time.Duration) *ControlPlaneClient {
	return &ControlPlaneClient{
		url:                 url,
		server:              server,
		logger:              logger.With().Str("component", "controlplane").Logger(),
		metadata:            metadata,
		subscribeAckTimeout: subscribeAckTimeout,
		state:               apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED,
		sendCh:              make(chan *apiv1.DaemonEvent, 100),
		pendingAcks:         make(map[string]chan SubscribedAckResult),
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.connect(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				// Reconnection backoff to avoid hammering the control plane
			}
		}
	}
}

func (c *ControlPlaneClient) connect(ctx context.Context) {
	c.setState(apiv1.ConnectionState_CONNECTION_STATE_CONNECTING)
	c.logger.Info().Str("url", c.url).Msg("connecting to control plane")

	conn, err := grpc.NewClient(c.url, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	c.logger.Info().Msg("connected to control plane")

	errCh := make(chan error, 2)

	go c.sendLoop(streamCtx, stream, errCh)
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
}

func (c *ControlPlaneClient) sendLoop(ctx context.Context, stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand], errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-c.sendCh:
			if err := stream.Send(event); err != nil {
				errCh <- err
				return
			}
		}
	}
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
			c.sendCh <- &apiv1.DaemonEvent{
				Event: &apiv1.DaemonEvent_Heartbeat{
					Heartbeat: &apiv1.Heartbeat{
						Stats: c.server.GetAttachmentStats(),
					},
				},
			}
		}
	}
}

func (c *ControlPlaneClient) handleCommand(cmd *apiv1.ControlCommand) {
	switch v := cmd.Command.(type) {
	case *apiv1.ControlCommand_SyncAck:
		c.logger.Debug().Msg("received sync ack")

	case *apiv1.ControlCommand_SetMode:
		c.logger.Debug().Str("id", cmd.Id).Str("mode", v.SetMode.Mode.String()).Msg("received set mode")
		if err := c.server.SetFilterMode(cmd.Id, v.SetMode.Mode); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to set filter mode")
		}

	case *apiv1.ControlCommand_AllowCidr:
		c.logger.Debug().Str("id", cmd.Id).Str("cidr", v.AllowCidr.Cidr).Msg("received allow cidr")
		cidr, err := filter.ParseCIDR(v.AllowCidr.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Str("cidr", v.AllowCidr.Cidr).Msg("failed to parse CIDR")
			return
		}
		if err := c.server.AllowCIDR(cmd.Id, cidr); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to allow CIDR")
		}

	case *apiv1.ControlCommand_DenyCidr:
		c.logger.Debug().Str("id", cmd.Id).Str("cidr", v.DenyCidr.Cidr).Msg("received deny cidr")
		cidr, err := filter.ParseCIDR(v.DenyCidr.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Str("cidr", v.DenyCidr.Cidr).Msg("failed to parse CIDR")
			return
		}
		if err := c.server.DenyCIDR(cmd.Id, cidr); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to deny CIDR")
		}

	case *apiv1.ControlCommand_RemoveCidr:
		c.logger.Debug().Str("id", cmd.Id).Str("cidr", v.RemoveCidr).Msg("received remove cidr")
		cidr, err := filter.ParseCIDR(v.RemoveCidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Str("cidr", v.RemoveCidr).Msg("failed to parse CIDR")
			return
		}
		if err := c.server.RemoveAllowedCIDR(cmd.Id, cidr); err != nil {
			c.logger.Warn().Err(err).Str("id", cmd.Id).Msg("failed to remove CIDR from allowlist")
		}
		if err := c.server.RemoveDeniedCIDR(cmd.Id, cidr); err != nil {
			c.logger.Warn().Err(err).Str("id", cmd.Id).Msg("failed to remove CIDR from denylist")
		}

	case *apiv1.ControlCommand_BulkUpdate:
		c.logger.Debug().Str("id", cmd.Id).Msg("received bulk update")
		c.applyBulkUpdate(cmd.Id, v.BulkUpdate)

	case *apiv1.ControlCommand_SetDnsMode:
		c.logger.Debug().Str("id", cmd.Id).Str("mode", v.SetDnsMode.Mode.String()).Msg("received set dns mode")
		if err := c.server.SetDnsMode(cmd.Id, v.SetDnsMode.Mode); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to set dns mode")
		}

	case *apiv1.ControlCommand_AllowDomain:
		c.logger.Debug().Str("id", cmd.Id).Str("domain", v.AllowDomain.Domain).Msg("received allow domain")
		if err := c.server.AllowDomain(cmd.Id, v.AllowDomain.Domain, v.AllowDomain.IncludeSubdomains); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to allow domain")
		}

	case *apiv1.ControlCommand_DenyDomain:
		c.logger.Debug().Str("id", cmd.Id).Str("domain", v.DenyDomain.Domain).Msg("received deny domain")
		if err := c.server.DenyDomain(cmd.Id, v.DenyDomain.Domain, v.DenyDomain.IncludeSubdomains); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to deny domain")
		}

	case *apiv1.ControlCommand_RemoveDomain:
		c.logger.Debug().Str("id", cmd.Id).Str("domain", v.RemoveDomain).Msg("received remove domain")
		if err := c.server.RemoveDomain(cmd.Id, v.RemoveDomain); err != nil {
			c.logger.Error().Err(err).Str("id", cmd.Id).Msg("failed to remove domain")
		}

	case *apiv1.ControlCommand_SubscribedAck:
		c.logger.Debug().Str("id", cmd.Id).Msg("received subscribed ack")
		// Apply configuration before unblocking the waiter to ensure the
		// attachment is fully configured when Attach returns to the caller.
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

	default:
		c.logger.Warn().Str("id", cmd.Id).Msg("received unknown command")
	}
}

// SubscribeAndWait sends a Subscribed event and waits for the control plane to
// acknowledge it with initial configuration. Returns the ack, or an error if
// the timeout is reached or the connection is lost.
//
// If subscribeAckTimeout is 0, this returns immediately without waiting.
func (c *ControlPlaneClient) SubscribeAndWait(ctx context.Context, sub *apiv1.Subscribed) (*apiv1.SubscribedAck, error) {
	if c.subscribeAckTimeout == 0 {
		select {
		case c.sendCh <- &apiv1.DaemonEvent{
			Event: &apiv1.DaemonEvent_Subscribed{Subscribed: sub},
		}:
			return nil, nil
		default:
			return nil, fmt.Errorf("send channel full")
		}
	}

	resultCh := make(chan SubscribedAckResult, 1)

	c.pendingAcksMu.Lock()
	c.pendingAcks[sub.Id] = resultCh
	c.pendingAcksMu.Unlock()

	select {
	case c.sendCh <- &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Subscribed{Subscribed: sub},
	}:
	default:
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
	select {
	case c.sendCh <- &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Unsubscribed{Unsubscribed: unsub},
	}:
	default:
		c.logger.Warn().Str("id", unsub.Id).Msg("send channel full, dropping unsubscribed event")
	}
}

func (c *ControlPlaneClient) MakeProxyFunc(attachmentID string) DnsProxyFunc {
	return func(domain, queryType string) (allow, addToFilter bool, ips []string, err error) {
		c.mu.RLock()
		client := c.client
		c.mu.RUnlock()

		if client == nil {
			return true, false, nil, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.QueryDns(ctx, &apiv1.DnsQueryRequest{
			Id:        attachmentID,
			Domain:    domain,
			QueryType: queryType,
		})
		if err != nil {
			return false, false, nil, err
		}

		return resp.Allow, resp.AddToFilter, resp.Ips, nil
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
		if err := c.server.AllowCIDR(id, cidr); err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to allow CIDR in subscribed ack")
		}
	}

	for _, entry := range ack.DenyCidrs {
		cidr, err := filter.ParseCIDR(entry.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse deny CIDR in subscribed ack")
			continue
		}
		if err := c.server.DenyCIDR(id, cidr); err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to deny CIDR in subscribed ack")
		}
	}

	if ack.Dns != nil {
		if err := c.server.SetDnsMode(id, ack.Dns.Mode); err != nil {
			c.logger.Error().Err(err).Str("id", id).Msg("failed to set DNS mode in subscribed ack")
		}
		for _, entry := range ack.Dns.AllowDomains {
			if err := c.server.AllowDomain(id, entry.Domain, entry.IncludeSubdomains); err != nil {
				c.logger.Error().Err(err).Str("id", id).Str("domain", entry.Domain).Msg("failed to allow domain in subscribed ack")
			}
		}
		for _, entry := range ack.Dns.DenyDomains {
			if err := c.server.DenyDomain(id, entry.Domain, entry.IncludeSubdomains); err != nil {
				c.logger.Error().Err(err).Str("id", id).Str("domain", entry.Domain).Msg("failed to deny domain in subscribed ack")
			}
		}
	}
}

func (c *ControlPlaneClient) applyBulkUpdate(id string, update *apiv1.BulkUpdate) {
	if err := c.server.SetFilterMode(id, update.Mode); err != nil {
		c.logger.Error().Err(err).Str("id", id).Msg("failed to set filter mode in bulk update")
	}

	for _, entry := range update.AllowCidrs {
		cidr, err := filter.ParseCIDR(entry.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse allow CIDR in bulk update")
			continue
		}
		if err := c.server.AllowCIDR(id, cidr); err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to allow CIDR in bulk update")
		}
	}

	for _, entry := range update.DenyCidrs {
		cidr, err := filter.ParseCIDR(entry.Cidr)
		if err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to parse deny CIDR in bulk update")
			continue
		}
		if err := c.server.DenyCIDR(id, cidr); err != nil {
			c.logger.Error().Err(err).Str("id", id).Str("cidr", entry.Cidr).Msg("failed to deny CIDR in bulk update")
		}
	}

	if update.Dns != nil {
		if err := c.server.SetDnsMode(id, update.Dns.Mode); err != nil {
			c.logger.Error().Err(err).Str("id", id).Msg("failed to set DNS mode in bulk update")
		}
		for _, entry := range update.Dns.AllowDomains {
			if err := c.server.AllowDomain(id, entry.Domain, entry.IncludeSubdomains); err != nil {
				c.logger.Error().Err(err).Str("id", id).Str("domain", entry.Domain).Msg("failed to allow domain in bulk update")
			}
		}
		for _, entry := range update.Dns.DenyDomains {
			if err := c.server.DenyDomain(id, entry.Domain, entry.IncludeSubdomains); err != nil {
				c.logger.Error().Err(err).Str("id", id).Str("domain", entry.Domain).Msg("failed to deny domain in bulk update")
			}
		}
	}
}
