package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

var (
	listPageSize int
	listAll      bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List attached filters",
	Long: `List all attached eBPF filters with their status.

Example:
  netfenced list
  netfenced list --all
  netfenced list --page-size 50`,
	RunE: runList,
}

func init() {
	listCmd.Flags().IntVar(&listPageSize, "page-size", 100, "number of results per page")
	listCmd.Flags().BoolVar(&listAll, "all", false, "fetch all pages")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	client, conn, err := newDaemonClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTARGET\tTYPE\tMODE\tDNS MODE\tDNS ADDR\tPKTS OK\tPKTS BLOCK")

	var pageToken string
	total := 0

	for {
		resp, err := client.List(ctx, &apiv1.ListRequest{
			PageSize:  int32(listPageSize),
			PageToken: pageToken,
		})
		if err != nil {
			return fmt.Errorf("list failed: %w", err)
		}

		for _, a := range resp.Attachments {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
				a.Id,
				a.Target,
				formatAttachmentType(a.Type),
				formatPolicyMode(a.Mode),
				formatDnsMode(a.DnsMode),
				a.DnsAddress,
				a.PacketsAllowed,
				a.PacketsBlocked,
			)
		}

		total = int(resp.TotalCount)

		if !listAll || resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	w.Flush()
	fmt.Printf("\nTotal: %d attachments\n", total)

	return nil
}

func formatAttachmentType(t apiv1.AttachmentType) string {
	switch t {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		return "tc"
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		return "cgroup"
	default:
		return "unknown"
	}
}

func formatPolicyMode(m apiv1.PolicyMode) string {
	switch m {
	case apiv1.PolicyMode_POLICY_MODE_DISABLED:
		return "disabled"
	case apiv1.PolicyMode_POLICY_MODE_ALLOWLIST:
		return "allowlist"
	case apiv1.PolicyMode_POLICY_MODE_DENYLIST:
		return "denylist"
	case apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL:
		return "block-all"
	default:
		return "unknown"
	}
}

func formatDnsMode(m apiv1.DnsMode) string {
	switch m {
	case apiv1.DnsMode_DNS_MODE_DISABLED:
		return "disabled"
	case apiv1.DnsMode_DNS_MODE_ALLOWLIST:
		return "allowlist"
	case apiv1.DnsMode_DNS_MODE_DENYLIST:
		return "denylist"
	case apiv1.DnsMode_DNS_MODE_PROXY:
		return "proxy"
	default:
		return "unknown"
	}
}
