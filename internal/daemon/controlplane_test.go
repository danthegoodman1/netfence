package daemon

import (
	"context"
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
	require.NoError(t, server.AllowCIDR(id, oldAllow))
	require.NoError(t, server.DenyCIDR(id, oldDeny))
	require.NoError(t, server.ReplaceDNSRules(
		id,
		apiv1.DnsMode_DNS_MODE_DENYLIST,
		[]*apiv1.DomainEntry{{Domain: "old-allow.test"}},
		[]*apiv1.DomainEntry{{Domain: "old-deny.test"}},
	))
	dnsServer.addIPToFilter("cached.test", netIP(t, "203.0.113.200"), 32, 60)
	require.NotEmpty(t, dnsServer.ipCache)

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
	assert.Equal(t, 1, clearCalls)
	assert.Equal(t, []string{"198.51.100.0/24"}, allowed)
	assert.Equal(t, []string{"2001:db8::/32"}, denied)

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
	assert.Empty(t, dnsServer.ipCache)
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
	require.NoError(t, server.AllowCIDR(id, oldAllow))
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
