package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	socketPath string
)

var rootCmd = &cobra.Command{
	Use:   "netfenced",
	Short: "Netfence daemon - eBPF network filter control plane",
	Long: `Netfence daemon manages eBPF network filters for containers and VMs.

Run 'netfenced start' to start the daemon, then use other commands to
attach/detach filters and query status.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&socketPath, "socket", "s", "/var/run/netfence.sock", "daemon socket path")
}
