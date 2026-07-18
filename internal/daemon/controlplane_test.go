package daemon

import (
	"context"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type fakeControlPlaneClient struct {
	queries int
}

func (f *fakeControlPlaneClient) Connect(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[apiv1.DaemonEvent, apiv1.ControlCommand], error) {
	return nil, nil
}

func (f *fakeControlPlaneClient) QueryDns(context.Context, *apiv1.DnsQueryRequest, ...grpc.CallOption) (*apiv1.DnsQueryResponse, error) {
	f.queries++
	return &apiv1.DnsQueryResponse{Allow: true, AddToFilter: true, Ips: []string{"198.51.100.10"}, TtlSeconds: 30}, nil
}

func TestApplyBulkUpdateReplacesExistingState(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

	oldAllow, err := filter.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	oldDeny, err := filter.ParseCIDR("192.0.2.0/24")
	require.NoError(t, err)
	require.NoError(t, server.AllowCIDR(id, oldAllow, 0))
	require.NoError(t, server.DenyCIDR(id, oldDeny, 0))
	require.NoError(t, server.ReplaceDNSRules(
		id,
		apiv1.DnsMode_DNS_MODE_DENYLIST,
		[]*apiv1.DomainEntry{{Domain: "old-allow.test"}},
		[]*apiv1.DomainEntry{{Domain: "old-deny.test"}},
	))
	dnsServer.addIPToFilter("cached.test", netIP(t, "203.0.113.200"), 32, 60)
	_, allowedBefore, _, _ := ff.snapshot()
	require.Contains(t, allowedBefore, "203.0.113.200/32")

	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}},
		DenyCidrs:  []*apiv1.CIDREntry{{Cidr: "2001:db8::/32"}},
		Dns: &apiv1.DnsConfig{
			Mode:         apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains: []*apiv1.DomainEntry{{Domain: "new-allow.test", IncludeSubdomains: true}},
			DenyDomains:  []*apiv1.DomainEntry{{Domain: "new-deny.test"}},
		},
	})

	mode, allowed, denied, clearCalls := ff.snapshot()
	assert.Equal(t, filter.ModeDenylist, mode)
	assert.Zero(t, clearCalls, "bulk update must reconcile deltas, never wipe the filter")
	// The stale CP rule is removed, the new one added — and the
	// DNS-populated IP SURVIVES the resync (it ages out via its own DNS
	// TTL; clients still hold it in resolver caches).
	assert.ElementsMatch(t, []string{"198.51.100.0/24", "203.0.113.200/32"}, allowed)
	assert.Equal(t, []string{"2001:db8::/32"}, denied)
	removedAllowed, removedDenied := ff.removeCalls()
	assert.Equal(t, []string{"10.0.0.0/8"}, removedAllowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, removedDenied)

	// Exactly one entry is pending expiry afterwards: the surviving
	// DNS-populated IP. The bulk's permanent entries are pinned.
	server.mu.RLock()
	reg := server.attachments[id].ttls
	server.mu.RUnlock()
	assert.Equal(t, 1, reg.pendingLen())

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"new-allow.test": true}, dnsServer.allowedDomains)
	assert.Equal(t, map[string]bool{"new-deny.test": false}, dnsServer.deniedDomains)
}

func TestApplyBulkUpdateWithNilDNSClearsExistingDNSRules(t *testing.T) {
	server, _, id, _, dnsServer := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

	require.NoError(t, server.ReplaceDNSRules(
		id,
		apiv1.DnsMode_DNS_MODE_DENYLIST,
		[]*apiv1.DomainEntry{{Domain: "old-allow.test"}},
		[]*apiv1.DomainEntry{{Domain: "old-deny.test"}},
	))

	c.applyBulkUpdate(id, &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED})

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DISABLED, dnsServer.mode)
	assert.Empty(t, dnsServer.allowedDomains)
	assert.Empty(t, dnsServer.deniedDomains)
}

func TestApplyBulkUpdateRejectsInvalidCIDRBeforeClearingExistingState(t *testing.T) {
	server, _, id, ff, dnsServer := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

	oldAllow, err := filter.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	require.NoError(t, server.AllowCIDR(id, oldAllow, 0))
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST, nil, []*apiv1.DomainEntry{{Domain: "old-deny.test"}}))

	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "not-a-cidr"}},
		Dns: &apiv1.DnsConfig{
			Mode:         apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains: []*apiv1.DomainEntry{{Domain: "new-allow.test"}},
		},
	})

	mode, allowed, denied, clearCalls := ff.snapshot()
	assert.Equal(t, filter.ModeDisabled, mode)
	assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
	assert.Empty(t, denied)
	assert.Zero(t, clearCalls)

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"old-deny.test": false}, dnsServer.deniedDomains)
}

func TestSubscribeAndWaitTimeoutCleansPendingAckAndMarksOutboundStale(t *testing.T) {
	c := NewControlPlaneClient("", nil, zerolog.Nop(), nil, 10*time.Millisecond)

	_, err := c.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: "att-timeout"})
	require.Error(t, err)

	c.pendingAcksMu.Lock()
	_, exists := c.pendingAcks["att-timeout"]
	c.pendingAcksMu.Unlock()
	assert.False(t, exists)

	select {
	case outbound := <-c.sendCh:
		assert.True(t, outbound.requirePendingAck)
		assert.Equal(t, "att-timeout", outbound.subscribedID)
		assert.False(t, c.hasPendingAck("att-timeout"))
	default:
		t.Fatal("expected queued subscribed event")
	}
}

func TestMakeProxyFuncRequiresConnectedState(t *testing.T) {
	c := NewControlPlaneClient("", nil, zerolog.Nop(), nil, 0)
	fakeClient := &fakeControlPlaneClient{}

	c.mu.Lock()
	c.client = fakeClient
	c.state = apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED
	c.mu.Unlock()

	proxy := c.MakeProxyFunc("att-1")
	_, err := proxy("example.com.", "A")
	require.ErrorIs(t, err, errDNSProxyUnavailable)
	assert.Zero(t, fakeClient.queries)

	c.mu.Lock()
	c.state = apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	c.mu.Unlock()

	decision, err := proxy("example.com.", "A")
	require.NoError(t, err)
	assert.True(t, decision.Allow)
	assert.Equal(t, uint32(30), decision.TTLSeconds)
	assert.Equal(t, 1, fakeClient.queries)
}

// drainCommandResults empties sendCh and returns any CommandResult events.
func drainCommandResults(t *testing.T, c *ControlPlaneClient) []*apiv1.CommandResult {
	t.Helper()
	var results []*apiv1.CommandResult
	for {
		select {
		case out := <-c.sendCh:
			if r, ok := out.event.Event.(*apiv1.DaemonEvent_CommandResult); ok {
				results = append(results, r.CommandResult)
			}
		default:
			return results
		}
	}
}

// TestHandleCommandEmitsCommandResults covers 2D: commands carrying a
// command_id get a CommandResult echoing it (success only when the command
// fully applied); commands without one produce no result at all.
func TestHandleCommandEmitsCommandResults(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0)

	t.Run("valid_command_reports_success", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-ok",
			Command:   &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "10.0.0.0/8"}},
		})
		results := drainCommandResults(t, c)
		require.Len(t, results, 1)
		assert.Equal(t, "cmd-ok", results[0].CommandId)
		assert.Equal(t, id, results[0].Id)
		assert.True(t, results[0].Success)
		assert.Empty(t, results[0].Error)
	})

	t.Run("bad_cidr_reports_failure", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-bad-cidr",
			Command:   &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "not-a-cidr"}},
		})
		results := drainCommandResults(t, c)
		require.Len(t, results, 1)
		assert.Equal(t, "cmd-bad-cidr", results[0].CommandId)
		assert.Equal(t, id, results[0].Id)
		assert.False(t, results[0].Success)
		assert.Contains(t, results[0].Error, "parsing CIDR")
	})

	t.Run("no_command_id_no_result", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:      id,
			Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "10.1.0.0/16"}},
		})
		// Failing command without a command_id must be silent too.
		c.handleCommand(&apiv1.ControlCommand{
			Id:      id,
			Command: &apiv1.ControlCommand_AllowCidr{AllowCidr: &apiv1.CIDREntry{Cidr: "also-not-a-cidr"}},
		})
		assert.Empty(t, drainCommandResults(t, c))
	})

	t.Run("bulk_update_parse_failure_reports_failure", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-bulk-bad",
			Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}, {Cidr: "bogus"}},
			}},
		})
		results := drainCommandResults(t, c)
		require.Len(t, results, 1)
		assert.False(t, results[0].Success)
		assert.Contains(t, results[0].Error, "parsing allow CIDR")
	})

	t.Run("bulk_update_success", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-bulk-ok",
			Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}},
			}},
		})
		results := drainCommandResults(t, c)
		require.Len(t, results, 1)
		assert.Equal(t, "cmd-bulk-ok", results[0].CommandId)
		assert.True(t, results[0].Success)
	})

	t.Run("partially_applied_bulk_reports_failure", func(t *testing.T) {
		// A filter-level failure mid-bulk (map full) must yield failure even
		// though the rest of the update applied.
		ff.setAllowErr(fmt.Errorf("updating allowed_ipv4: %w", syscall.ENOSPC))
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-bulk-partial",
			Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.0/24"}},
			}},
		})
		ff.setAllowErr(nil)
		results := drainCommandResults(t, c)
		require.Len(t, results, 1)
		assert.False(t, results[0].Success)
		assert.Contains(t, results[0].Error, "reconciling CIDRs")
	})

	t.Run("unknown_attachment_reports_failure", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:        "no-such-attachment",
			CommandId: "cmd-missing",
			Command:   &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST}},
		})
		results := drainCommandResults(t, c)
		require.Len(t, results, 1)
		assert.Equal(t, "cmd-missing", results[0].CommandId)
		assert.Equal(t, "no-such-attachment", results[0].Id)
		assert.False(t, results[0].Success)
		assert.Contains(t, results[0].Error, "attachment not found")
	})

	t.Run("acks_never_produce_results", func(t *testing.T) {
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-sync-ack",
			Command:   &apiv1.ControlCommand_SyncAck{SyncAck: &apiv1.SyncAck{}},
		})
		c.handleCommand(&apiv1.ControlCommand{
			Id:        id,
			CommandId: "cmd-subscribed-ack",
			Command:   &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED}},
		})
		assert.Empty(t, drainCommandResults(t, c))
	})
}
