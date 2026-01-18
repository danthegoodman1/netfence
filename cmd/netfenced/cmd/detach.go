package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

var detachID string

var detachCmd = &cobra.Command{
	Use:   "detach",
	Short: "Detach an eBPF filter",
	Long: `Detach an eBPF filter by its attachment ID.

Example:
  netfenced detach --id 01234567-89ab-cdef-0123-456789abcdef`,
	RunE: runDetach,
}

func init() {
	detachCmd.Flags().StringVar(&detachID, "id", "", "attachment ID to detach")
	detachCmd.MarkFlagRequired("id")
	rootCmd.AddCommand(detachCmd)
}

func runDetach(cmd *cobra.Command, args []string) error {
	client, conn, err := newDaemonClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Detach(ctx, &apiv1.DetachRequest{Id: detachID})
	if err != nil {
		return fmt.Errorf("detach failed: %w", err)
	}

	fmt.Printf("Detached %s\n", detachID)
	return nil
}
