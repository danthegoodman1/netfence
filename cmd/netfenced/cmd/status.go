package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get daemon status",
	Long: `Get the current status of the netfence daemon.

Example:
  netfenced status`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	client, conn, err := newDaemonClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, err := client.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("get status failed: %w", err)
	}

	fmt.Printf("Netfence Daemon Status\n")
	fmt.Printf("  Version:           %s\n", status.Version)
	fmt.Printf("  Daemon ID:         %s\n", status.DaemonId)
	fmt.Printf("  Hostname:          %s\n", status.Hostname)
	fmt.Printf("  Attachments:       %d\n", status.AttachmentCount)
	fmt.Printf("  Control Plane:     %s\n", formatConnectionState(status.ControlPlaneState))
	if status.ControlPlaneAddress != "" {
		fmt.Printf("  Control Plane URL: %s\n", status.ControlPlaneAddress)
	}

	return nil
}

func formatConnectionState(s apiv1.ConnectionState) string {
	switch s {
	case apiv1.ConnectionState_CONNECTION_STATE_CONNECTED:
		return "connected"
	case apiv1.ConnectionState_CONNECTION_STATE_CONNECTING:
		return "connecting"
	case apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED:
		return "disconnected"
	default:
		return "unknown"
	}
}
