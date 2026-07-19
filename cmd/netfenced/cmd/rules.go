package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func mutationCommand(use, short string, args int, build func([]string) (*apiv1.ControlCommand, error)) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: cobra.ExactArgs(args), RunE: func(_ *cobra.Command, values []string) error {
		command, err := build(values)
		if err != nil {
			return err
		}
		client, conn, err := newDaemonClient()
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := client.ApplyCommand(ctx, command); err != nil {
			return fmt.Errorf("policy command failed: %w", err)
		}
		return nil
	}}
}

func parsePolicyModeCLI(value string) (apiv1.PolicyMode, error) {
	switch strings.ReplaceAll(strings.ToLower(value), "_", "-") {
	case "disabled":
		return apiv1.PolicyMode_POLICY_MODE_DISABLED, nil
	case "allowlist":
		return apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, nil
	case "denylist":
		return apiv1.PolicyMode_POLICY_MODE_DENYLIST, nil
	case "block-all":
		return apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL, nil
	default:
		return 0, fmt.Errorf("invalid policy mode %q", value)
	}
}

func parseDNSModeCLI(value string) (apiv1.DnsMode, error) {
	switch strings.ToLower(value) {
	case "disabled":
		return apiv1.DnsMode_DNS_MODE_DISABLED, nil
	case "allowlist":
		return apiv1.DnsMode_DNS_MODE_ALLOWLIST, nil
	case "denylist":
		return apiv1.DnsMode_DNS_MODE_DENYLIST, nil
	case "proxy":
		return apiv1.DnsMode_DNS_MODE_PROXY, nil
	default:
		return 0, fmt.Errorf("invalid DNS mode %q", value)
	}
}

func newCIDRCommand(allow bool) *cobra.Command {
	verb := "deny-cidr"
	short := "Add a CIDR to the deny list"
	if allow {
		verb, short = "allow-cidr", "Add a CIDR to the allow list"
	}
	var ttlText string
	command := mutationCommand(verb+" <id> <cidr>", short, 2, func(args []string) (*apiv1.ControlCommand, error) {
		entry := &apiv1.CIDREntry{Cidr: args[1]}
		if ttlText != "" {
			ttl, err := time.ParseDuration(ttlText)
			if err != nil || ttl < 0 {
				return nil, fmt.Errorf("invalid non-negative --ttl %q", ttlText)
			}
			entry.Ttl = durationpb.New(ttl)
		}
		result := &apiv1.ControlCommand{Id: args[0]}
		if allow {
			result.Command = &apiv1.ControlCommand_AllowCidr{AllowCidr: entry}
		} else {
			result.Command = &apiv1.ControlCommand_DenyCidr{DenyCidr: entry}
		}
		return result, nil
	})
	command.Flags().StringVar(&ttlText, "ttl", "", "optional rule lifetime (for example 5m)")
	return command
}

func newDomainCommand(allow bool) *cobra.Command {
	verb := "deny-domain"
	short := "Add a DNS deny rule"
	if allow {
		verb, short = "allow-domain", "Add a DNS allow rule"
	}
	var subdomains bool
	command := mutationCommand(verb+" <id> <domain>", short, 2, func(args []string) (*apiv1.ControlCommand, error) {
		entry := &apiv1.DomainEntry{Domain: args[1], IncludeSubdomains: subdomains}
		result := &apiv1.ControlCommand{Id: args[0]}
		if allow {
			result.Command = &apiv1.ControlCommand_AllowDomain{AllowDomain: entry}
		} else {
			result.Command = &apiv1.ControlCommand_DenyDomain{DenyDomain: entry}
		}
		return result, nil
	})
	command.Flags().BoolVar(&subdomains, "subdomains", false, "include all subdomains")
	return command
}

func init() {
	rootCmd.AddCommand(
		mutationCommand("set-mode <id> <mode>", "Set packet policy mode", 2, func(args []string) (*apiv1.ControlCommand, error) {
			mode, err := parsePolicyModeCLI(args[1])
			return &apiv1.ControlCommand{Id: args[0], Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: mode}}}, err
		}),
		newCIDRCommand(true), newCIDRCommand(false), newRemoveCIDRCommand(),
		mutationCommand("set-dns-mode <id> <mode>", "Set DNS policy mode", 2, func(args []string) (*apiv1.ControlCommand, error) {
			mode, err := parseDNSModeCLI(args[1])
			return &apiv1.ControlCommand{Id: args[0], Command: &apiv1.ControlCommand_SetDnsMode{SetDnsMode: &apiv1.SetDnsMode{Mode: mode}}}, err
		}),
		newDomainCommand(true), newDomainCommand(false),
		mutationCommand("remove-domain <id> <domain>", "Remove a domain from both DNS lists", 2, func(args []string) (*apiv1.ControlCommand, error) {
			return &apiv1.ControlCommand{Id: args[0], Command: &apiv1.ControlCommand_RemoveDomain{RemoveDomain: args[1]}}, nil
		}),
		newApplyRulesCommand(), rulesCmd,
	)
}

func newRemoveCIDRCommand() *cobra.Command {
	var listText string
	command := mutationCommand("remove-cidr <id> <cidr>", "Remove a CIDR policy rule", 2, func(args []string) (*apiv1.ControlCommand, error) {
		lists := map[string]apiv1.RuleList{"allow": apiv1.RuleList_RULE_LIST_ALLOW, "deny": apiv1.RuleList_RULE_LIST_DENY, "both": apiv1.RuleList_RULE_LIST_BOTH}
		list, ok := lists[strings.ToLower(listText)]
		if !ok {
			return nil, fmt.Errorf("invalid --list %q: use allow, deny, or both", listText)
		}
		return &apiv1.ControlCommand{Id: args[0], RemoveCidrList: list, Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: args[1]}}, nil
	})
	command.Flags().StringVar(&listText, "list", "both", "list to remove from: allow, deny, or both")
	return command
}

func newApplyRulesCommand() *cobra.Command {
	var file string
	command := mutationCommand("apply-rules <id>", "Apply complete policy from protobuf JSON", 1, func(args []string) (*apiv1.ControlCommand, error) {
		var payload []byte
		var err error
		if file == "-" {
			payload, err = io.ReadAll(os.Stdin)
		} else {
			payload, err = os.ReadFile(file)
		}
		if err != nil {
			return nil, fmt.Errorf("reading rules: %w", err)
		}
		update := new(apiv1.BulkUpdate)
		if err := protojson.Unmarshal(payload, update); err != nil {
			return nil, fmt.Errorf("parsing rules protobuf JSON: %w", err)
		}
		return &apiv1.ControlCommand{Id: args[0], Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: update}}, nil
	})
	command.Flags().StringVarP(&file, "file", "f", "-", "BulkUpdate protobuf JSON file ('-' for stdin)")
	return command
}

var rulesCmd = &cobra.Command{Use: "rules <id>", Short: "Inspect current rules", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
	client, conn, err := newDaemonClient()
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rules, err := client.GetRules(ctx, &apiv1.GetRulesRequest{Id: args[0]})
	if err != nil {
		return fmt.Errorf("get rules failed: %w", err)
	}
	payload, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(rules)
	if err != nil {
		return err
	}
	fmt.Println(string(payload))
	return nil
}}
