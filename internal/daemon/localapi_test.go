package daemon

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func TestSharedPolicyCommandValidationAndVariants(t *testing.T) {
	valid := []struct {
		name    string
		command func(string) *apiv1.ControlCommand
	}{
		{"set_mode", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST}}}
		}},
		{"allow_cidr", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.7/24", Ttl: durationpb.New(time.Minute)}}}
		}},
		{"deny_cidr", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "198.51.100.0/24"}}}
		}},
		{"remove_cidr", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, RemoveCidrList: apiv1.RuleList_RULE_LIST_BOTH, Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "203.0.113.0/24"}}
		}},
		{"bulk_update", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST, Dns: &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_DISABLED}}}}
		}},
		{"set_dns_mode", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetDnsMode{SetDnsMode: &apiv1.SetDnsMode{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST}}}
		}},
		{"allow_domain", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowDomain{AllowDomain: &apiv1.DomainEntry{Domain: "Allow.Example", IncludeSubdomains: true}}}
		}},
		{"deny_domain", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_DenyDomain{DenyDomain: &apiv1.DomainEntry{Domain: "deny.example"}}}
		}},
		{"remove_domain", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_RemoveDomain{RemoveDomain: "remove.example"}}
		}},
	}
	for _, test := range valid {
		t.Run("valid/"+test.name, func(t *testing.T) {
			server, _, id, _, _ := newTestServerWithAttachment(t)
			require.NoError(t, server.ApplyPolicyCommand(test.command(id)))
		})
	}

	invalid := []struct {
		name    string
		command func(string) *apiv1.ControlCommand
	}{
		{"nil", func(string) *apiv1.ControlCommand { return nil }},
		{"missing_id", func(string) *apiv1.ControlCommand { return &apiv1.ControlCommand{} }},
		{"missing_variant", func(id string) *apiv1.ControlCommand { return &apiv1.ControlCommand{Id: id} }},
		{"sync_ack", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SyncAck{SyncAck: &apiv1.SyncAck{}}}
		}},
		{"subscribed_ack", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{}}}
		}},
		{"nil_set_mode", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetMode{}}
		}},
		{"unspecified_mode", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{}}}
		}},
		{"nil_cidr", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowCidr{}}
		}},
		{"malformed_cidr", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "bad"}}}
		}},
		{"negative_ttl", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.0/24", Ttl: durationpb.New(-time.Second)}}}
		}},
		{"invalid_duration", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.0/24", Ttl: &durationpb.Duration{Nanos: 1_000_000_000}}}}
		}},
		{"invalid_selector", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, RemoveCidrList: apiv1.RuleList(99), Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "192.0.2.0/24"}}
		}},
		{"nil_dns_mode", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetDnsMode{}}
		}},
		{"unspecified_dns_mode", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetDnsMode{SetDnsMode: &apiv1.SetDnsMode{}}}
		}},
		{"nil_domain", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowDomain{}}
		}},
		{"invalid_domain", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_DenyDomain{DenyDomain: &apiv1.DomainEntry{Domain: "bad..example"}}}
		}},
		{"nil_bulk", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_BulkUpdate{}}
		}},
		{"invalid_bulk_ttl", func(id string) *apiv1.ControlCommand {
			return &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24", Ttl: durationpb.New(-time.Second)}}}}}
		}},
	}
	for _, test := range invalid {
		t.Run("invalid/"+test.name, func(t *testing.T) {
			server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
			beforeEvents := ff.eventLog()
			beforeRules := server.attachments[id].ttls.snapshotRules()
			dnsServer.mu.RLock()
			beforeDNS := dnsServer.currentConfigLocked()
			dnsServer.mu.RUnlock()
			err := server.ApplyPolicyCommand(test.command(id))
			require.Error(t, err)
			assert.Equal(t, beforeEvents, ff.eventLog(), "invalid command must not reach the filter")
			assert.Equal(t, beforeRules, server.attachments[id].ttls.snapshotRules())
			dnsServer.mu.RLock()
			assert.Equal(t, beforeDNS, dnsServer.currentConfigLocked())
			dnsServer.mu.RUnlock()
		})
	}
}

func TestLocalCIDRCanonicalTTLSelectorAndInspection(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	apply := func(command *apiv1.ControlCommand) {
		t.Helper()
		command.Id = id
		_, err := server.ApplyCommand(context.Background(), command)
		require.NoError(t, err)
	}
	apply(&apiv1.ControlCommand{Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.99/24", Ttl: durationpb.New(time.Minute)}}})
	apply(&apiv1.ControlCommand{Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.7/24", Ttl: durationpb.New(2 * time.Minute)}}})
	apply(&apiv1.ControlCommand{Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.1/24", Ttl: durationpb.New(30 * time.Second)}}})
	apply(&apiv1.ControlCommand{Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "192.0.2.0/24"}}})
	assert.Equal(t, 1, ff.allowCallCount(), "canonical alias and TTL extension are bookkeeping-only")

	rules, err := server.GetRules(context.Background(), &apiv1.GetRulesRequest{Id: id})
	require.NoError(t, err)
	require.Len(t, rules.Cidrs, 2)
	assert.Equal(t, apiv1.RuleList_RULE_LIST_ALLOW, rules.Cidrs[0].List)
	assert.Equal(t, "192.0.2.0/24", rules.Cidrs[0].Cidr)
	assert.Equal(t, now.Add(2*time.Minute), rules.Cidrs[0].ExpiresAt.AsTime())
	assert.Equal(t, apiv1.RuleList_RULE_LIST_DENY, rules.Cidrs[1].List)

	_, err = server.ApplyCommand(context.Background(), &apiv1.ControlCommand{Id: id, RemoveCidrList: apiv1.RuleList_RULE_LIST_ALLOW, Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "192.0.2.77/24"}})
	require.NoError(t, err)
	_, allowed, denied, _ := ff.snapshot()
	assert.NotContains(t, allowed, "192.0.2.0/24")
	assert.Contains(t, denied, "192.0.2.0/24")
	_, err = server.ApplyCommand(context.Background(), &apiv1.ControlCommand{Id: id, RemoveCidrList: apiv1.RuleList_RULE_LIST_BOTH, Command: &apiv1.ControlCommand_RemoveCidr{RemoveCidr: "192.0.2.0/24"}})
	require.NoError(t, err)
	_, _, denied, _ = ff.snapshot()
	assert.NotContains(t, denied, "192.0.2.0/24")
}

func TestLocalBulkUpdateUsesStableDegradationRecoveryPath(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	ff.setDenyErr(syscall.EIO)
	_, err := server.ApplyCommand(context.Background(), &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_DenyCidr{DenyCidr: &apiv1.CIDREntry{Cidr: "198.51.100.0/24"}}})
	require.Error(t, err)
	ff.setDenyErr(nil)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), server.attachments[id].info.Mode)
	assert.NotEmpty(t, server.attachments[id].info.PolicyDegradedReason)

	_, err = server.ApplyCommand(context.Background(), &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "192.0.2.0/24"}}})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = server.ApplyCommand(context.Background(), &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.0/24"}},
		Dns: &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains: []*apiv1.DomainEntry{{Domain: "allowed.example", IncludeSubdomains: true}}},
	}}})
	require.NoError(t, err)
	assert.Empty(t, server.attachments[id].info.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), server.attachments[id].info.Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"allowed.example": true}, dnsServer.allowedDomains)
}

func TestLocalRPCRejectsUncommittedAttachAndCommandID(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	state := server.attachments[id]
	state.setupDone = make(chan struct{})
	command := &apiv1.ControlCommand{Id: id, Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST}}}
	_, err := server.ApplyCommand(context.Background(), command)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Empty(t, ff.eventLog())
	state.finishSetup(true)
	_, err = server.ApplyCommand(context.Background(), command)
	require.NoError(t, err)
	afterApply := ff.eventLog()
	command.CommandId = "local-has-unary-status"
	_, err = server.ApplyCommand(context.Background(), command)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, afterApply, ff.eventLog())
}

func TestGetRulesMarksSystemAliasesProvisionalAndRemovalRetry(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	reg := server.attachments[id].ttls
	alias := mustCIDR(t, "127.0.0.1/32")
	require.NoError(t, reg.seedAdopted([]*net.IPNet{alias}, nil))
	require.NoError(t, reg.addSystem(ff, alias, listAllow))
	retry := mustCIDR(t, "192.0.2.0/24")
	reg.mu.Lock()
	reg.entries[ttlKey{cidr: retry.String(), list: listAllow}] = ttlEntry{cidr: retry, inFilter: true}
	reg.mu.Unlock()
	rules, err := server.GetRules(context.Background(), &apiv1.GetRulesRequest{Id: id})
	require.NoError(t, err)
	require.Len(t, rules.Cidrs, 2)
	assert.True(t, rules.Cidrs[0].PolicyOwned)
	assert.True(t, rules.Cidrs[0].SystemOwned)
	assert.True(t, rules.Cidrs[0].Provisional)
	assert.True(t, rules.Cidrs[1].Installed)
	assert.False(t, rules.Cidrs[1].PolicyOwned)
	assert.False(t, rules.Cidrs[1].SystemOwned)
}
