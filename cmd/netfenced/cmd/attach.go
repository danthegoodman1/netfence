package cmd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

var (
	interfaceName string
	cgroupPath    string
	policyMode    string
	metadata      []string
)

var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "Attach an eBPF filter to an interface or cgroup",
	Long: `Attach an eBPF filter to a network interface (TC) or cgroup.

Examples:
  netfenced attach --interface eth0
  netfenced attach --cgroup /sys/fs/cgroup/user.slice/... --metadata vm_id=abc123
  netfenced attach --interface veth123 --mode allowlist --metadata tenant=acme,env=prod`,
	RunE: runAttach,
}

func init() {
	attachCmd.Flags().StringVarP(&interfaceName, "interface", "i", "", "network interface name (TC attachment)")
	attachCmd.Flags().StringVarP(&cgroupPath, "cgroup", "g", "", "cgroup path (cgroup attachment)")
	attachCmd.Flags().StringVarP(&policyMode, "mode", "m", "disabled", "policy mode: disabled, allowlist, denylist, block-all")
	attachCmd.Flags().StringSliceVar(&metadata, "metadata", nil, "metadata key=value pairs")
	rootCmd.AddCommand(attachCmd)
}

func runAttach(cmd *cobra.Command, args []string) error {
	if interfaceName == "" && cgroupPath == "" {
		return fmt.Errorf("must specify --interface or --cgroup")
	}
	if interfaceName != "" && cgroupPath != "" {
		return fmt.Errorf("cannot specify both --interface and --cgroup")
	}

	client, conn, err := newDaemonClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	req := &apiv1.AttachRequest{
		Mode:     parsePolicyModeFlag(policyMode),
		Metadata: parseMetadata(metadata),
	}

	if interfaceName != "" {
		req.Target = &apiv1.AttachRequest_InterfaceName{InterfaceName: interfaceName}
	} else {
		req.Target = &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Attach(ctx, req)
	if err != nil {
		return fmt.Errorf("attach failed: %w", err)
	}

	fmt.Printf("Attached successfully\n")
	fmt.Printf("  ID:          %s\n", resp.Id)
	fmt.Printf("  DNS Address: %s\n", resp.DnsAddress)

	return nil
}

func newDaemonClient() (apiv1.DaemonServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 5*time.Second)
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to daemon: %w", err)
	}
	return apiv1.NewDaemonServiceClient(conn), conn, nil
}

func parseMetadata(pairs []string) map[string]string {
	m := make(map[string]string)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m
}

func parsePolicyModeFlag(s string) apiv1.PolicyMode {
	switch strings.ToLower(s) {
	case "disabled":
		return apiv1.PolicyMode_POLICY_MODE_DISABLED
	case "allowlist":
		return apiv1.PolicyMode_POLICY_MODE_ALLOWLIST
	case "denylist":
		return apiv1.PolicyMode_POLICY_MODE_DENYLIST
	case "block-all", "blockall":
		return apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL
	default:
		return apiv1.PolicyMode_POLICY_MODE_DISABLED
	}
}
