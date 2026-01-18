package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type ControlPlaneClient struct {
	url      string
	server   *Server
	logger   zerolog.Logger
	metadata map[string]string

	mu     sync.RWMutex
	state  apiv1.ConnectionState
	stream grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand]
	cancel context.CancelFunc

	sendCh chan *apiv1.DaemonEvent
}

func NewControlPlaneClient(url string, server *Server, logger zerolog.Logger, metadata map[string]string) *ControlPlaneClient {
	return &ControlPlaneClient{
		url:      url,
		server:   server,
		logger:   logger.With().Str("component", "controlplane").Logger(),
		metadata: metadata,
		state:    apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED,
		sendCh:   make(chan *apiv1.DaemonEvent, 100),
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
	defer conn.Close()

	client := apiv1.NewControlPlaneClient(conn)

	streamCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
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

// TODO: Implement actual command handling - integrate with pkg/filter to modify eBPF maps
func (c *ControlPlaneClient) handleCommand(cmd *apiv1.ControlCommand) {
	switch cmd.Command.(type) {
	case *apiv1.ControlCommand_SyncAck:
		c.logger.Debug().Msg("received sync ack")
	case *apiv1.ControlCommand_SetMode:
		c.logger.Debug().Str("id", cmd.Id).Msg("received set mode")
	case *apiv1.ControlCommand_AllowCidr:
		c.logger.Debug().Str("id", cmd.Id).Msg("received allow cidr")
	case *apiv1.ControlCommand_DenyCidr:
		c.logger.Debug().Str("id", cmd.Id).Msg("received deny cidr")
	case *apiv1.ControlCommand_RemoveCidr:
		c.logger.Debug().Str("id", cmd.Id).Msg("received remove cidr")
	case *apiv1.ControlCommand_BulkUpdate:
		c.logger.Debug().Str("id", cmd.Id).Msg("received bulk update")
	case *apiv1.ControlCommand_SetDnsMode:
		c.logger.Debug().Str("id", cmd.Id).Msg("received set dns mode")
	case *apiv1.ControlCommand_AllowDomain:
		c.logger.Debug().Str("id", cmd.Id).Msg("received allow domain")
	case *apiv1.ControlCommand_DenyDomain:
		c.logger.Debug().Str("id", cmd.Id).Msg("received deny domain")
	case *apiv1.ControlCommand_RemoveDomain:
		c.logger.Debug().Str("id", cmd.Id).Msg("received remove domain")
	default:
		c.logger.Warn().Str("id", cmd.Id).Msg("received unknown command")
	}
}

func (c *ControlPlaneClient) SendSubscribed(sub *apiv1.Subscribed) {
	select {
	case c.sendCh <- &apiv1.DaemonEvent{
		Event: &apiv1.DaemonEvent_Subscribed{Subscribed: sub},
	}:
	default:
		c.logger.Warn().Str("id", sub.Id).Msg("send channel full, dropping subscribed event")
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
