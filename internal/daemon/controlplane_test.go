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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

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
	dnsBefore, _ := ff.dnsSnapshot()
	require.Contains(t, dnsBefore, "203.0.113.200")

	c.applyBulkUpdate(id, &apiv1.BulkUpdate{
		Mode:       apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}},
		DenyCidrs:  []*apiv1.CIDREntry{{Cidr: "2001:db8::/32"}},
		Dns: &apiv1.DnsConfig{
			Mode:            apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains:    []*apiv1.DomainEntry{{Domain: "new-allow.test", IncludeSubdomains: true}},
			DenyDomains:     []*apiv1.DomainEntry{{Domain: "new-deny.test"}},
			UpstreamServers: []string{"[2001:db8::53]:0053", "dns.example.:53"},
		},
	})

	mode, allowed, denied, clearCalls := ff.snapshot()
	assert.Equal(t, filter.ModeDenylist, mode)
	assert.Zero(t, clearCalls, "bulk update must reconcile deltas, never wipe the filter")
	// The stale CP rule is removed and the new one added. cached.test loses
	// ownership because the authoritative DNS allowlist no longer permits it.
	assert.ElementsMatch(t, []string{"198.51.100.0/24"}, allowed)
	dnsAfter, _ := ff.dnsSnapshot()
	assert.Empty(t, dnsAfter)
	assert.Equal(t, []string{"2001:db8::/32"}, denied)
	removedAllowed, removedDenied := ff.removeCalls()
	assert.Equal(t, []string{"10.0.0.0/8"}, removedAllowed)
	assert.Equal(t, []string{"192.0.2.0/24"}, removedDenied)

	// DNS ownership is independent of the authoritative LPM TTL registry, and
	// the bulk's remaining CP entries are permanent.
	server.mu.RLock()
	reg := server.attachments[id].ttls
	server.mu.RUnlock()
	assert.Zero(t, reg.pendingLen())

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"new-allow.test": true}, dnsServer.allowedDomains)
	assert.Equal(t, map[string]bool{"new-deny.test": false}, dnsServer.deniedDomains)
	assert.Equal(t, []string{"[2001:db8::53]:53", "dns.example:53"}, dnsServer.upstreams)
}

func TestIncrementalModesRejectUnspecifiedAndUnknownWithoutMutation(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	rowBefore, err := st.GetAttachment(id)
	require.NoError(t, err)
	filterEvents := ff.eventLog()

	for _, mode := range []apiv1.PolicyMode{
		apiv1.PolicyMode_POLICY_MODE_UNSPECIFIED,
		apiv1.PolicyMode(99),
	} {
		require.Error(t, server.SetFilterMode(id, mode))
	}
	assert.Equal(t, filterEvents, ff.eventLog())
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, rowBefore.Mode, row.Mode)

	dnsServer.mu.RLock()
	dnsModeBefore := dnsServer.mode
	dnsServer.mu.RUnlock()
	for _, mode := range []apiv1.DnsMode{
		apiv1.DnsMode_DNS_MODE_UNSPECIFIED,
		apiv1.DnsMode(99),
	} {
		require.Error(t, server.SetDnsMode(id, mode))
	}
	dnsServer.mu.RLock()
	assert.Equal(t, dnsModeBefore, dnsServer.mode)
	dnsServer.mu.RUnlock()
	row, err = st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, rowBefore.DnsMode, row.DnsMode)
}

func TestApplyBulkUpdateWithNilDNSClearsExistingDNSRules(t *testing.T) {
	server, _, id, _, dnsServer := newTestServerWithAttachment(t)
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

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

func TestApplyBulkUpdateRejectsInvalidUpstreamBeforeAnyMutation(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST,
		nil, []*apiv1.DomainEntry{{Domain: "old-deny.test"}}, []string{"1.1.1.1:53"}))
	beforeEvents := ff.eventLog()
	beforeStored, err := st.GetAttachment(id)
	require.NoError(t, err)
	server.mu.Lock()
	server.attachments[id].needsResync = true
	server.mu.Unlock()

	client.handleCommand(&apiv1.ControlCommand{
		Id:        id,
		CommandId: "invalid-upstream",
		Command: &apiv1.ControlCommand_BulkUpdate{BulkUpdate: &apiv1.BulkUpdate{
			Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
			Dns: &apiv1.DnsConfig{
				Mode:            apiv1.DnsMode_DNS_MODE_ALLOWLIST,
				AllowDomains:    []*apiv1.DomainEntry{{Domain: "new.test"}},
				UpstreamServers: []string{"2001:db8::53:53"},
			},
		}},
	})
	results := drainCommandResults(t, client)
	require.Len(t, results, 1)
	assert.False(t, results[0].Success)
	assert.Contains(t, results[0].Error, "validating DNS configuration")
	assert.Equal(t, beforeEvents, ff.eventLog())
	afterStored, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, beforeStored, afterStored, "validation failure must not persist desired state")
	server.mu.RLock()
	assert.True(t, server.attachments[id].needsResync, "failed authoritative state must remain pending")
	server.mu.RUnlock()
	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"old-deny.test": false}, dnsServer.deniedDomains)
	assert.Equal(t, []string{"1.1.1.1:53"}, dnsServer.upstreams)
}

func TestBulkUpdateRejectsInvalidModesBeforeAnyMutation(t *testing.T) {
	tests := []struct {
		name      string
		update    *apiv1.BulkUpdate
		errorText string
	}{
		{
			name: "unspecified_policy",
			update: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_UNSPECIFIED,
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
				Dns:        &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST},
			},
			errorText: "invalid policy mode",
		},
		{
			name: "unknown_policy",
			update: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode(99),
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
				Dns:        &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST},
			},
			errorText: "invalid policy mode",
		},
		{
			name: "unspecified_dns",
			update: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
				Dns:        &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_UNSPECIFIED},
			},
			errorText: "invalid DNS mode",
		},
		{
			name: "unknown_dns",
			update: &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
				AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.0/24"}},
				Dns:        &apiv1.DnsConfig{Mode: apiv1.DnsMode(99)},
			},
			errorText: "invalid DNS mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
			client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)
			oldAllow, err := filter.ParseCIDR("10.0.0.0/8")
			require.NoError(t, err)
			require.NoError(t, server.AllowCIDR(id, oldAllow, 0))
			require.NoError(t, server.ReplaceDNSRules(
				id,
				apiv1.DnsMode_DNS_MODE_DENYLIST,
				nil,
				[]*apiv1.DomainEntry{{Domain: "old-deny.test"}},
			))
			beforeEvents := ff.eventLog()
			beforeStored, err := st.GetAttachment(id)
			require.NoError(t, err)

			client.handleCommand(&apiv1.ControlCommand{
				Id:        id,
				CommandId: "invalid-mode-" + tt.name,
				Command:   &apiv1.ControlCommand_BulkUpdate{BulkUpdate: tt.update},
			})

			results := drainCommandResults(t, client)
			require.Len(t, results, 1)
			assert.False(t, results[0].Success)
			assert.Contains(t, results[0].Error, tt.errorText)
			assert.Equal(t, beforeEvents, ff.eventLog(), "invalid full state must make no filter calls")
			mode, allowed, denied, clearCalls := ff.snapshot()
			assert.Equal(t, filter.ModeDisabled, mode)
			assert.Equal(t, []string{"10.0.0.0/8"}, allowed)
			assert.Empty(t, denied)
			assert.Zero(t, clearCalls)

			afterStored, err := st.GetAttachment(id)
			require.NoError(t, err)
			assert.Equal(t, beforeStored, afterStored, "invalid full state must not persist anything")
			dnsServer.mu.RLock()
			assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, dnsServer.mode)
			assert.Empty(t, dnsServer.allowedDomains)
			assert.Equal(t, map[string]bool{"old-deny.test": false}, dnsServer.deniedDomains)
			dnsServer.mu.RUnlock()
		})
	}
}

func TestSubscribeAndWaitTimeoutCleansPendingAckAndMarksOutboundStale(t *testing.T) {
	c := NewControlPlaneClient("", nil, zerolog.Nop(), nil, 10*time.Millisecond, nil)

	_, err := c.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: "att-timeout"})
	require.Error(t, err)

	c.pendingAcksMu.Lock()
	_, exists := c.pendingAcks["att-timeout"]
	c.pendingAcksMu.Unlock()
	assert.False(t, exists)

	select {
	case outbound := <-c.sendCh:
		require.NotNil(t, outbound.pending)
		assert.Equal(t, "att-timeout", outbound.pending.sub.Id)
		assert.False(t, c.hasPendingAck("att-timeout"))
	default:
		t.Fatal("expected queued subscribed event")
	}
}

func TestSubscribedAckApplySerializesWithDetach(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 5*time.Second, nil)
	server.SetControlPlaneClient(client)

	waitResult := make(chan error, 1)
	go func() {
		_, err := client.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: id})
		waitResult <- err
	}()
	require.Eventually(t, func() bool { return client.hasPendingAck(id) }, time.Second, time.Millisecond)
	pending := pendingSubscriptionFor(t, client, id)
	require.True(t, client.beginPendingSend(pending, 1))

	entered := make(chan struct{})
	release := make(chan struct{})
	ff.blockSetMode(entered, release)
	ackDone := make(chan struct{})
	go func() {
		defer close(ackDone)
		client.handleCommandForEpoch(&apiv1.ControlCommand{
			Id: id,
			Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
				Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			}},
		}, 1)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("ack did not reach the gated filter mutation")
	}

	detachDone := make(chan error, 1)
	go func() {
		_, err := server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
		detachDone <- err
	}()
	select {
	case err := <-detachDone:
		t.Fatalf("Detach interleaved with claimed ack apply: %v", err)
	case <-time.After(25 * time.Millisecond):
		// Expected: Detach waits on the exact state's reconcileMu without
		// holding Server.mu, while the ack remains free to finish.
	}
	_, err := st.GetAttachment(id)
	require.NoError(t, err, "row must remain owned by the in-flight ack until teardown wins the state lock")

	close(release)
	select {
	case <-ackDone:
	case <-time.After(time.Second):
		t.Fatal("ack did not finish after releasing the gate")
	}
	require.NoError(t, <-waitResult)
	select {
	case err := <-detachDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Detach did not finish after the ack released state ownership")
	}

	rows, err := st.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows, "ack's delayed SaveAttachment must not resurrect the detached row")
	assert.Equal(t, 1, ff.detachCallCount())
	assert.Zero(t, ff.mutationAfterCloseCount())
	server.mu.RLock()
	_, live := server.attachments[id]
	server.mu.RUnlock()
	assert.False(t, live)
}

func TestSubscribedAckApplySerializesWithStop(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 5*time.Second, nil)
	server.SetControlPlaneClient(client)

	waitResult := make(chan error, 1)
	go func() {
		_, err := client.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: id})
		waitResult <- err
	}()
	require.Eventually(t, func() bool { return client.hasPendingAck(id) }, time.Second, time.Millisecond)
	pending := pendingSubscriptionFor(t, client, id)
	require.True(t, client.beginPendingSend(pending, 1))

	entered := make(chan struct{})
	release := make(chan struct{})
	ff.blockSetMode(entered, release)
	ackDone := make(chan struct{})
	go func() {
		defer close(ackDone)
		client.handleCommandForEpoch(&apiv1.ControlCommand{
			Id: id,
			Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
				Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			}},
		}, 1)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("ack did not reach the gated filter mutation")
	}

	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		server.Stop()
	}()
	require.Eventually(t, func() bool {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return server.stopping
	}, time.Second, time.Millisecond)
	allowCallsBefore := ff.allowCallCount()
	cidr, err := filter.ParseCIDR("198.51.100.0/24")
	require.NoError(t, err)
	require.Error(t, server.AllowCIDR(id, cidr, 0))
	require.Error(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DISABLED))
	assert.Equal(t, allowCallsBefore, ff.allowCallCount(), "post-Stop mutation is not admitted behind active command")
	select {
	case <-stopDone:
		t.Fatal("Stop closed resources while a claimed ack owned reconcileMu")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case <-ackDone:
	case <-time.After(time.Second):
		t.Fatal("ack did not finish after gate release")
	}
	require.NoError(t, <-waitResult)
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after ack released reconcileMu")
	}

	row, err := st.GetAttachment(id)
	require.NoError(t, err, "Stop preserves the attachment row for restart")
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), row.Mode)
	assert.Equal(t, 1, ff.closeCallCount())
	assert.Zero(t, ff.mutationAfterCloseCount())
}

func TestPendingSubscriptionPublicationIsAtomicOnQueueFull(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, time.Second, nil)
	for i := 0; i < cap(client.sendCh); i++ {
		require.True(t, client.enqueue(staleHeartbeat()))
	}

	_, err := client.SubscribeAndWait(context.Background(), &apiv1.Subscribed{Id: id})
	require.ErrorIs(t, err, errSubscriptionQueueFull)
	assert.False(t, client.hasPendingAck(id))
	assert.Empty(t, client.snapshotPendingSubscriptions(),
		"sendLoop redrive snapshots must never observe a publication whose initial enqueue failed")
}

func TestMakeProxyFuncRequiresConnectedState(t *testing.T) {
	c := NewControlPlaneClient("", nil, zerolog.Nop(), nil, 0, nil)
	fakeClient := &fakeControlPlaneClient{}

	c.mu.Lock()
	c.client = fakeClient
	c.state = apiv1.ConnectionState_CONNECTION_STATE_DISCONNECTED
	c.mu.Unlock()

	proxy := c.MakeProxyFunc("att-1")
	_, err := proxy(context.Background(), "example.com.", "A")
	require.ErrorIs(t, err, errDNSProxyUnavailable)
	assert.Zero(t, fakeClient.queries)

	c.mu.Lock()
	c.state = apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	c.mu.Unlock()

	decision, err := proxy(context.Background(), "example.com.", "A")
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
	c := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)

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
