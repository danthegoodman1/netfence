package daemon

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func attachmentNeedsResync(t *testing.T, server *Server, id string) bool {
	t.Helper()
	server.mu.RLock()
	defer server.mu.RUnlock()
	state := server.attachments[id]
	require.NotNil(t, state)
	return state.needsResync
}

func pendingSubscriptionFor(t *testing.T, client *ControlPlaneClient, id string) *pendingSubscription {
	t.Helper()
	client.pendingAcksMu.Lock()
	defer client.pendingAcksMu.Unlock()
	pending := client.pendingAcks[id]
	require.NotNil(t, pending)
	return pending
}

// dispatchRestoreAck drives the production ownership gates for a restore
// handshake: publish the exact attempt, consume its queued Subscribed as the
// send loop would, reserve the explicit connection epoch, then deliver the ack
// through that same epoch's receive path. Restore tests must not use epoch zero,
// because sentEpoch == 0 means "not dispatched".
func dispatchRestoreAck(t *testing.T, client *ControlPlaneClient, id string, epoch uint64, ack *apiv1.SubscribedAck) {
	t.Helper()
	require.NotZero(t, epoch)
	client.startRestoreResyncs(context.Background(), epoch)
	pending := pendingSubscriptionFor(t, client, id)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case outbound := <-client.sendCh:
			// A disconnected prior attempt can leave an exact-but-canceled
			// queue item behind. sendLoop discards those by identity; emulate
			// that behavior until this attempt's item is reached.
			if outbound.pending != pending {
				continue
			}
			require.Same(t, pending.sub, outbound.event.GetSubscribed())
		case <-deadline.C:
			t.Fatal("restore Subscribed was not queued")
		}
		break
	}
	require.True(t, client.beginPendingSend(pending, epoch))
	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id:      id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: ack},
	}, epoch)
}

func prepareCompleteRestoreInfo(t *testing.T, env *restoreEnv) {
	t.Helper()
	env.server.mu.Lock()
	state := env.server.attachments[env.id]
	require.NotNil(t, state)
	state.info.DnsMode = apiv1.DnsMode_DNS_MODE_ALLOWLIST.String()
	state.info.Direction = apiv1.TcDirection_TC_DIRECTION_INGRESS.String()
	state.info.Metadata = map[string]string{"tenant": "acme", "workload": "sandbox-7"}
	row := cloneAttachment(state.info)
	env.server.mu.Unlock()
	require.NoError(t, env.st.SaveAttachment(row))
}

// Both successful Start restore paths need the same complete re-subscription:
// a pin adoption and a recreate-empty fallback differ only in their current
// data-plane contents, never in whether the control plane must re-declare full
// desired state.
func TestRestoreMarksNeedsResyncAndBuildsCompleteSubscribed(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		adopted bool
	}{
		{name: "adopted_from_pins", port: 12307, adopted: true},
		{name: "recreated_empty", port: 12308, adopted: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			prepareCompleteRestoreInfo(t, env)
			if tt.adopted {
				env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
				env.mkPinDir(t)
			}

			require.NoError(t, env.server.Start())
			t.Cleanup(env.server.Stop)

			assert.True(t, attachmentNeedsResync(t, env.server, env.id))
			resyncs := env.server.GetRestoreResyncSubscriptions()
			require.Len(t, resyncs, 1)
			sub := resyncs[0].sub
			require.NotNil(t, sub)
			assert.Equal(t, env.id, sub.Id)
			assert.Equal(t, "lo", sub.Target)
			assert.Equal(t, apiv1.AttachmentType_ATTACHMENT_TYPE_TC, sub.Type)
			assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, sub.Mode)
			assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, sub.DnsMode)
			env.server.mu.RLock()
			expectedDNSAddress := env.server.attachments[env.id].info.DnsAddress
			env.server.mu.RUnlock()
			assert.Equal(t, expectedDNSAddress, sub.DnsAddress)
			assert.Equal(t, map[string]string{"tenant": "acme", "workload": "sandbox-7"}, sub.Metadata)
			assert.Equal(t, apiv1.TcDirection_TC_DIRECTION_INGRESS, sub.TcDirection)

			// The snapshot owns its metadata copy; CP-side/test mutation cannot
			// race or alter the live attachment record.
			sub.Metadata["tenant"] = "mutated"
			env.server.mu.RLock()
			assert.Equal(t, "acme", env.server.attachments[env.id].info.Metadata["tenant"])
			env.server.mu.RUnlock()

			loadPinned, newFilter := env.counts()
			if tt.adopted {
				assert.Equal(t, 1, loadPinned)
				assert.Zero(t, newFilter)
			} else {
				assert.Zero(t, loadPinned)
				assert.Equal(t, 1, newFilter)
			}
		})
	}
}

// With no CP configured, Start must do nothing beyond faithful restoration and
// bookkeeping. The last-known map contents stay enforced and the flag remains
// for a future daemon life/connection.
func TestRestoreWithoutControlPlaneKeepsRulesAndNeedsResync(t *testing.T) {
	env := newRestoreEnv(t, 12309, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	env.adopted = &fakeFilter{
		mode:    filter.ModeAllowlist,
		allowed: []string{"198.51.100.1/32", "203.0.113.5/32"},
	}
	env.mkPinDir(t)

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	mode, allowed, denied, clearCalls := env.adopted.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)
	assert.ElementsMatch(t, []string{"198.51.100.1/32", "203.0.113.5/32", testDNSBootstrapCIDR}, allowed)
	assert.Empty(t, denied)
	assert.Zero(t, clearCalls)
	for _, event := range env.adopted.eventLog() {
		assert.False(t, strings.HasPrefix(event, "remove-"), "restore without an ack must not remove rules: %v", env.adopted.eventLog())
	}
	assert.True(t, attachmentNeedsResync(t, env.server, env.id))
}

// A restored SubscribedAck is authoritative full desired state. It uses the
// same reconcile as BulkUpdate: stale leaves, new arrives, and the survivor is
// never removed. DNS rules are replaced as part of the same success decision.
func TestRestoreSubscribedAckAuthoritativeReconcileClearsExactFlag(t *testing.T) {
	env := newRestoreEnv(t, 12310, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	survivor := "198.51.100.1/32"
	stale := "203.0.113.5/32"
	added := "192.0.2.7/32"
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{survivor, stale}}
	env.mkPinDir(t)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	require.NoError(t, env.server.ReplaceDNSRules(env.id, apiv1.DnsMode_DNS_MODE_DENYLIST,
		nil, []*apiv1.DomainEntry{{Domain: "old.test"}}))

	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	dispatchRestoreAck(t, client, env.id, 1, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: survivor},
			{Cidr: added},
		},
		Dns: &apiv1.DnsConfig{
			Mode:         apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains: []*apiv1.DomainEntry{{Domain: "new.test", IncludeSubdomains: true}},
		},
	})

	mode, allowed, denied, clearCalls := env.adopted.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)
	assert.ElementsMatch(t, []string{survivor, added, testDNSBootstrapCIDR}, allowed)
	assert.Empty(t, denied)
	assert.Zero(t, clearCalls)
	removedAllowed, _ := env.adopted.removeCalls()
	assert.Equal(t, []string{stale}, removedAllowed)
	assert.NotContains(t, removedAllowed, survivor, "surviving traffic must never lose its map entry")

	env.server.mu.RLock()
	dns := env.server.attachments[env.id].dns
	env.server.mu.RUnlock()
	require.NotNil(t, dns)
	dns.mu.RLock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dns.mode)
	assert.Equal(t, map[string]bool{"new.test": true}, dns.allowedDomains)
	assert.Empty(t, dns.deniedDomains)
	dns.mu.RUnlock()
	assert.False(t, attachmentNeedsResync(t, env.server, env.id))
	assert.False(t, client.hasPendingAck(env.id))
}

func TestRestoreRecreatedEmptySubscribedAckConverges(t *testing.T) {
	env := newRestoreEnv(t, 12323, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	require.Len(t, env.created, 1, "missing pins must use the recreate-empty restore path")
	_, beforeAllowed, beforeDenied, _ := env.created[0].snapshot()
	assert.Equal(t, []string{testDNSBootstrapCIDR}, beforeAllowed)
	assert.Empty(t, beforeDenied)
	assert.True(t, attachmentNeedsResync(t, env.server, env.id))

	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	desired := "192.0.2.44/32"
	dispatchRestoreAck(t, client, env.id, 1, &apiv1.SubscribedAck{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: desired}},
	})

	mode, allowed, denied, _ := env.created[0].snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)
	assert.ElementsMatch(t, []string{testDNSBootstrapCIDR, desired}, allowed)
	assert.Empty(t, denied)
	assert.False(t, attachmentNeedsResync(t, env.server, env.id))
	assert.False(t, client.hasPendingAck(env.id))
}

func TestRestoreResyncFailureRetainsFlagAndLaterRetryConverges(t *testing.T) {
	t.Run("invalid_cidr_is_parse_first_and_static", func(t *testing.T) {
		env := newRestoreEnv(t, 12311, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
		env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{"198.51.100.1/32"}}
		env.mkPinDir(t)
		require.NoError(t, env.server.Start())
		t.Cleanup(env.server.Stop)

		client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
		before := env.adopted.eventLog()
		dispatchRestoreAck(t, client, env.id, 1, &apiv1.SubscribedAck{
			Mode:       apiv1.PolicyMode_POLICY_MODE_DENYLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "not-a-cidr"}},
		})
		assert.Equal(t, before, env.adopted.eventLog(), "invalid authoritative state must mutate nothing")
		assert.True(t, attachmentNeedsResync(t, env.server, env.id))

		// A later connection/attempt can retry and is the only one allowed to
		// clear the exact flag.
		dispatchRestoreAck(t, client, env.id, 2, &apiv1.SubscribedAck{
			Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.1/32"}},
		})
		assert.False(t, attachmentNeedsResync(t, env.server, env.id))
	})

	t.Run("filter_apply_failure", func(t *testing.T) {
		env := newRestoreEnv(t, 12312, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
		env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{"198.51.100.1/32"}}
		env.mkPinDir(t)
		require.NoError(t, env.server.Start())
		t.Cleanup(env.server.Stop)

		client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
		env.adopted.setAllowErr(syscall.ENOSPC)
		dispatchRestoreAck(t, client, env.id, 1, &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{
				{Cidr: "198.51.100.1/32"},
				{Cidr: "192.0.2.7/32"},
			},
		})
		assert.True(t, attachmentNeedsResync(t, env.server, env.id))

		env.adopted.setAllowErr(nil)
		dispatchRestoreAck(t, client, env.id, 2, &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{
				{Cidr: "198.51.100.1/32"},
				{Cidr: "192.0.2.7/32"},
			},
		})
		assert.False(t, attachmentNeedsResync(t, env.server, env.id))
	})
}

func TestRestoreInvalidAuthoritativeAckIsStaticAndRetainsFlag(t *testing.T) {
	env := newRestoreEnv(t, 12319, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	survivor := "198.51.100.1/32"
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{survivor}}
	env.mkPinDir(t)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)

	tests := []struct {
		name string
		ack  *apiv1.SubscribedAck
	}{
		{name: "unspecified_policy", ack: &apiv1.SubscribedAck{}},
		{name: "unknown_policy", ack: &apiv1.SubscribedAck{Mode: apiv1.PolicyMode(99)}},
		{name: "unspecified_dns", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			Dns:  &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_UNSPECIFIED},
		}},
		{name: "unknown_dns", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			Dns:  &apiv1.DnsConfig{Mode: apiv1.DnsMode(99)},
		}},
		{name: "nil_cidr_entry", ack: &apiv1.SubscribedAck{
			Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{nil},
		}},
		{name: "negative_ttl", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{
				Cidr: survivor,
				Ttl:  durationpb.New(-time.Second),
			}},
		}},
		{name: "malformed_ttl", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{
				Cidr: survivor,
				Ttl:  &durationpb.Duration{Seconds: 1, Nanos: -1},
			}},
		}},
		{name: "duration_clamp", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{
				Cidr: survivor,
				Ttl:  &durationpb.Duration{Seconds: 10_000_000_000},
			}},
		}},
		{name: "duplicate_canonical_cidr", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{
				{Cidr: "10.0.0.1/8"},
				{Cidr: "10.0.0.0/8", Ttl: durationpb.New(time.Minute)},
			},
		}},
		{name: "malformed_dns_upstream", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			Dns: &apiv1.DnsConfig{
				Mode:            apiv1.DnsMode_DNS_MODE_ALLOWLIST,
				AllowDomains:    []*apiv1.DomainEntry{{Domain: "must-not-apply.test"}},
				UpstreamServers: []string{"2001:db8::53:53"},
			},
		}},
		{name: "too_many_unique_dns_upstreams", ack: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			Dns: &apiv1.DnsConfig{
				Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST,
				UpstreamServers: []string{
					"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53",
					"192.0.2.4:53", "192.0.2.5:53", "192.0.2.6:53",
					"192.0.2.7:53", "192.0.2.8:53", "192.0.2.9:53",
				},
			},
		}},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := env.adopted.eventLog()
			dispatchRestoreAck(t, client, env.id, uint64(i+1), tt.ack)
			assert.Equal(t, before, env.adopted.eventLog())
			mode, allowed, _, clearCalls := env.adopted.snapshot()
			assert.Equal(t, filter.ModeAllowlist, mode)
			assert.ElementsMatch(t, []string{survivor, testDNSBootstrapCIDR}, allowed)
			assert.Zero(t, clearCalls)
			assert.True(t, attachmentNeedsResync(t, env.server, env.id))
			assert.False(t, client.hasPendingAck(env.id))
			env.server.mu.RLock()
			dnsServer := env.server.attachments[env.id].dns
			env.server.mu.RUnlock()
			dnsServer.mu.RLock()
			assert.Equal(t, apiv1.DnsMode_DNS_MODE_DISABLED, dnsServer.mode)
			assert.Empty(t, dnsServer.allowedDomains)
			assert.Empty(t, dnsServer.deniedDomains)
			assert.Equal(t, []string{"127.0.0.1:1"}, dnsServer.upstreams)
			dnsServer.mu.RUnlock()
		})
	}

	dispatchRestoreAck(t, client, env.id, uint64(len(tests)+1), &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		Dns: &apiv1.DnsConfig{
			Mode:            apiv1.DnsMode_DNS_MODE_ALLOWLIST,
			AllowDomains:    []*apiv1.DomainEntry{{Domain: "retry.test", IncludeSubdomains: true}},
			UpstreamServers: []string{"192.0.2.53:53"},
		},
	})
	assert.False(t, attachmentNeedsResync(t, env.server, env.id), "a later valid full state must clear the exact restore marker")
	env.server.mu.RLock()
	dnsServer := env.server.attachments[env.id].dns
	env.server.mu.RUnlock()
	dnsServer.mu.RLock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"retry.test": true}, dnsServer.allowedDomains)
	assert.Equal(t, []string{"192.0.2.53:53"}, dnsServer.upstreams)
	dnsServer.mu.RUnlock()
}

func TestRestoreAckReplacesPermanentSurvivorWithFiniteTTLWithoutRemove(t *testing.T) {
	env := newRestoreEnv(t, 12320, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	survivor := "198.51.100.1/32"
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{survivor}}
	env.mkPinDir(t)
	clock := newFakeClock()
	env.server.now = clock.Now
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	dispatchRestoreAck(t, client, env.id, 1, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{
			Cidr: survivor,
			Ttl:  durationpb.New(2 * time.Second),
		}},
	})

	removed, _ := env.adopted.removeCalls()
	assert.Empty(t, removed, "authoritative TTL correction must not remove/re-add the survivor")
	assert.False(t, attachmentNeedsResync(t, env.server, env.id))
	env.server.mu.RLock()
	registry := env.server.attachments[env.id].ttls
	env.server.mu.RUnlock()
	assert.Equal(t, 1, registry.pendingLen())

	clock.Advance(2 * time.Second)
	env.server.sweepExpiredTTLs(clock.Now())
	_, allowed, _, _ := env.adopted.snapshot()
	assert.Equal(t, []string{testDNSBootstrapCIDR}, allowed, "restored permanent seed must expire at the fresh ack TTL while bootstrap remains")
	removed, _ = env.adopted.removeCalls()
	assert.Equal(t, []string{survivor}, removed)
}

func TestRestoreResyncRetriesFailedStaleRemovalBeforeClearingFlag(t *testing.T) {
	env := newRestoreEnv(t, 12321, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	survivor := "198.51.100.1/32"
	stale := "203.0.113.5/32"
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{survivor, stale}}
	env.mkPinDir(t)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	ack := &apiv1.SubscribedAck{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: survivor}},
	}

	env.adopted.setRemoveAllowedErr(syscall.EIO)
	for epoch := uint64(1); epoch <= 2; epoch++ {
		dispatchRestoreAck(t, client, env.id, epoch, ack)
		assert.True(t, attachmentNeedsResync(t, env.server, env.id),
			"failed stale removal on attempt %d must retain the flag", epoch)
		_, allowed, _, _ := env.adopted.snapshot()
		assert.Contains(t, allowed, stale, "failed kernel removal must remain visible for retry")
	}
	removed, _ := env.adopted.removeCalls()
	assert.Equal(t, []string{stale, stale}, removed, "the source-less stale entry must be retried on every authoritative ack")
	assert.NotContains(t, removed, survivor)

	env.adopted.setRemoveAllowedErr(nil)
	dispatchRestoreAck(t, client, env.id, 3, ack)
	assert.False(t, attachmentNeedsResync(t, env.server, env.id))
	_, allowed, _, _ := env.adopted.snapshot()
	assert.ElementsMatch(t, []string{survivor, testDNSBootstrapCIDR}, allowed)
	removed, _ = env.adopted.removeCalls()
	assert.Equal(t, []string{stale, stale, stale}, removed)
	assert.NotContains(t, removed, survivor)
}

func TestRestoreResyncTimeoutZeroStillRequiresAck(t *testing.T) {
	env := newRestoreEnv(t, 12313, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 0, nil)
	assert.Equal(t, defaultRestoreSubscribeAckTimeout, client.restoreSubscribeAckTimeout())
	client.startRestoreResyncs(context.Background(), 1)
	pending := pendingSubscriptionFor(t, client, env.id)
	assert.Equal(t, subscriptionPurposeRestore, pending.purpose)
	assert.True(t, attachmentNeedsResync(t, env.server, env.id), "scheduling alone can never clear the flag")

	// Disconnect/no ack retains the flag, then the next connection retries.
	client.cancelRestoreSubscriptions(1, errors.New("test disconnect"))
	assert.False(t, client.hasPendingAck(env.id))
	assert.True(t, attachmentNeedsResync(t, env.server, env.id))
	dispatchRestoreAck(t, client, env.id, 2, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
	})
	assert.False(t, attachmentNeedsResync(t, env.server, env.id))
}

func TestRestoreResyncNoAckAndQueuePressureRetainFlag(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		env := newRestoreEnv(t, 12314, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
		require.NoError(t, env.server.Start())
		t.Cleanup(env.server.Stop)
		client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 10*time.Millisecond, nil)
		client.startRestoreResyncs(context.Background(), 1)
		require.Eventually(t, func() bool { return !client.hasPendingAck(env.id) }, time.Second, time.Millisecond)
		assert.True(t, attachmentNeedsResync(t, env.server, env.id))
	})

	t.Run("enqueue_pressure_and_no_duplicate", func(t *testing.T) {
		env := newRestoreEnv(t, 12315, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
		require.NoError(t, env.server.Start())
		t.Cleanup(env.server.Stop)
		client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
		for i := 0; i < cap(client.sendCh); i++ {
			require.True(t, client.enqueue(staleHeartbeat()))
		}
		client.startRestoreResyncs(context.Background(), 1)
		assert.False(t, client.hasPendingAck(env.id))
		assert.True(t, attachmentNeedsResync(t, env.server, env.id))

		for len(client.sendCh) > 0 {
			<-client.sendCh
		}
		client.startRestoreResyncs(context.Background(), 2)
		client.startRestoreResyncs(context.Background(), 2)
		assert.True(t, client.hasPendingAck(env.id))
		subscribed := 0
		for len(client.sendCh) > 0 {
			if (<-client.sendCh).event.GetSubscribed() != nil {
				subscribed++
			}
		}
		assert.Equal(t, 1, subscribed, "duplicate scheduling must produce one effective handshake")
		client.cancelRestoreSubscriptions(2, errors.New("test cleanup"))
	})
}

func TestRestoreUndispatchedAttemptRejectsEpochZeroAck(t *testing.T) {
	env := newRestoreEnv(t, 12322, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	client.startRestoreResyncs(context.Background(), 1)
	pending := pendingSubscriptionFor(t, client, env.id)
	assert.Zero(t, pending.sentEpoch)

	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id: env.id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
			Mode: apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL,
		}},
	}, 0)

	assert.Same(t, pending, pendingSubscriptionFor(t, client, env.id))
	assert.True(t, attachmentNeedsResync(t, env.server, env.id))
	env.server.mu.RLock()
	state := env.server.attachments[env.id]
	env.server.mu.RUnlock()
	mode, err := state.filter.GetMode()
	require.NoError(t, err)
	assert.Equal(t, filter.ModeAllowlist, mode, "an ack for an undispatched Subscribed must not mutate enforcement")
	client.cancelRestoreSubscriptions(1, errors.New("test cleanup"))
}

func TestRestoreLateAckAfterDetachIsIgnored(t *testing.T) {
	env := newRestoreEnv(t, 12316, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	client := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	env.server.SetControlPlaneClient(client)
	client.startRestoreResyncs(context.Background(), 1)
	pending := pendingSubscriptionFor(t, client, env.id)
	require.True(t, client.beginPendingSend(pending, 1))

	_, err := env.server.Detach(context.Background(), &apiv1.DetachRequest{Id: env.id})
	require.NoError(t, err)
	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id: env.id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
			Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			AllowCidrs: []*apiv1.CIDREntry{{Cidr: "192.0.2.7/32"}},
		}},
	}, 1)

	env.server.mu.RLock()
	_, live := env.server.attachments[env.id]
	env.server.mu.RUnlock()
	assert.False(t, live)
	_, allowed, _, _ := env.created[0].snapshot()
	assert.NotContains(t, allowed, "192.0.2.7/32", "late ack must not mutate the detached filter")
}

// Map inventory is mandatory for delta convergence. If Rules or registry
// seeding fails, startup leaves the pins enforcing and aborts before exposing a
// needsResync flag that an incomplete reconcile could falsely clear.
func TestRestoreAdoptedInventoryFailureAbortsWithoutUnpinning(t *testing.T) {
	tests := []struct {
		name string
		port int
		prep func(*fakeFilter)
	}{
		{name: "rules_iteration", port: 12317, prep: func(ff *fakeFilter) { ff.setRulesErr(errors.New("iterate failed")) }},
		{name: "registry_seed", port: 12318, prep: func(ff *fakeFilter) { ff.setAllowErr(syscall.ENOSPC) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			env.adopted = &fakeFilter{mode: filter.ModeAllowlist, allowed: []string{"198.51.100.1/32"}}
			tt.prep(env.adopted)
			env.mkPinDir(t)

			err := env.server.Start()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "inventorying re-adopted attachment")
			assert.Equal(t, 1, env.adopted.closeCallCount(), "adopted handle must close without detaching pins")
			assert.Zero(t, env.adopted.detachCallCount())
			assert.DirExists(t, env.pinRoot+"/"+env.id, "last-known pinned policy must survive startup failure")
			env.server.mu.RLock()
			assert.False(t, env.server.attachments[env.id].needsResync)
			env.server.mu.RUnlock()
		})
	}
}

func TestRestoreAdoptedBootstrapFailureAbortsWithoutUnpinning(t *testing.T) {
	env := newRestoreEnv(t, 12324, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
	env.adopted.setAllowErr(syscall.ENOSPC)
	env.mkPinDir(t)

	err := env.server.Start()
	require.ErrorContains(t, err, "protected DNS bootstrap route")
	assert.Equal(t, 1, env.adopted.closeCallCount())
	assert.Zero(t, env.adopted.detachCallCount(), "bootstrap failure must not destroy live pinned enforcement")
	assert.DirExists(t, env.pinRoot+"/"+env.id)
	assertDNSPortFree(t, env.port)
	env.server.mu.RLock()
	assert.False(t, env.server.attachments[env.id].needsResync)
	env.server.mu.RUnlock()
}

func TestRestoreRecreatedBootstrapFailureAbortsAndRetainsDurableRow(t *testing.T) {
	env := newRestoreEnv(t, 12325, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	before, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	env.server.newFilter = func(string, string, apiv1.AttachmentType, apiv1.PolicyMode, apiv1.TcDirection, uint32) (filter.Filter, error) {
		env.newFilterCalls++
		ff := &fakeFilter{mode: filter.ModeAllowlist, allowErr: syscall.ENOSPC}
		env.created = append(env.created, ff)
		return ff, nil
	}

	err = env.server.Start()
	require.ErrorContains(t, err, "protected DNS bootstrap route")
	require.Len(t, env.created, 1)
	assert.Equal(t, 1, env.created[0].detachCallCount())
	assertRestoreDurableOwnershipRetained(t, env, before)
	assertDNSPortFree(t, env.port)
}

func TestRestoreRollbackDoesNotCompensateBootstrapInsideRecreatedFilter(t *testing.T) {
	env := newRestoreEnv(t, 12326, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	bootstrap := mustCIDR(t, testDNSBootstrapCIDR)

	env.server.mu.RLock()
	recreatedState := env.server.attachments[env.id]
	env.server.mu.RUnlock()
	recreated := &fakeFilter{mode: filter.ModeAllowlist}
	require.NoError(t, recreatedState.ttls.addSystem(recreated, bootstrap, listAllow))
	recreated.setRemoveAllowedErr(errors.New("must not remove a rule from a disposable recreated map"))
	beforeRecreated, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)

	adoptedInfo := cloneAttachment(beforeRecreated)
	adoptedInfo.ID = "att-restore-adopted"
	require.NoError(t, env.st.SaveAttachment(adoptedInfo))
	adoptedState := &attachmentState{info: adoptedInfo, ttls: newTTLRegistry()}
	adopted := &fakeFilter{mode: filter.ModeAllowlist}
	require.NoError(t, adoptedState.ttls.addSystem(adopted, bootstrap, listAllow))
	adopted.setRemoveAllowedErr(syscall.EIO)

	env.server.mu.Lock()
	err = env.server.rollbackRestoreStart([]*restoreStartResource{
		{
			id:                 env.id,
			state:              recreatedState,
			filter:             recreated,
			bootstrap:          bootstrap,
			bootstrapInstalled: true,
			originalDNSAddress: beforeRecreated.DnsAddress,
		},
		{
			id:                 adoptedInfo.ID,
			state:              adoptedState,
			filter:             adopted,
			adopted:            true,
			bootstrap:          bootstrap,
			bootstrapInstalled: true,
			originalDNSAddress: adoptedInfo.DnsAddress,
		},
	})
	env.server.mu.Unlock()
	require.ErrorContains(t, err, "restoring bootstrap for "+adoptedInfo.ID)

	afterRecreated, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	assert.Equal(t, beforeRecreated, afterRecreated, "successful recreated Detach must preserve the original persisted policy")
	assert.Equal(t, 1, recreated.detachCallCount())
	removed, _ := recreated.removeCalls()
	assert.Empty(t, removed, "recreated rollback destroys the map instead of compensating individual rules")
	events := recreated.eventLog()
	assert.Less(t,
		indexOfEvent(t, events, "set-mode "+filter.ModeBlockAll.String()),
		indexOfEvent(t, events, "detach"),
		"recreated map must be staged fail-closed before Detach can close its FDs")

	afterAdopted, err := env.st.GetAttachment(adoptedInfo.ID)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), afterAdopted.Mode)
	assert.Equal(t, 1, adopted.closeCallCount())
	assert.Zero(t, adopted.detachCallCount())
}

func TestRestoreRollbackStagesRecreatedFilterBlockAllBeforeFailedDetach(t *testing.T) {
	for _, tt := range []struct {
		name       string
		setModeErr error
	}{
		{name: "prestage_succeeds"},
		{name: "prestage_failure_is_aggregated", setModeErr: syscall.EPERM},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12327, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			env.server.mu.RLock()
			state := env.server.attachments[env.id]
			env.server.mu.RUnlock()
			ff := &fakeFilter{mode: filter.ModeAllowlist}
			ff.setSetModeErr(tt.setModeErr)
			ff.setDetachErr(syscall.EIO)

			env.server.mu.Lock()
			err := env.server.rollbackRestoreStart([]*restoreStartResource{{
				id:                 env.id,
				state:              state,
				filter:             ff,
				originalDNSAddress: state.info.DnsAddress,
			}})
			env.server.mu.Unlock()
			require.ErrorContains(t, err, "detaching recreated filter")
			if tt.setModeErr != nil {
				assert.ErrorContains(t, err, "forcing "+env.id+" block-all before failed detach")
			}
			events := ff.eventLog()
			assert.Less(t,
				indexOfEvent(t, events, "set-mode "+filter.ModeBlockAll.String()),
				indexOfEvent(t, events, "detach"))
			stored, getErr := env.st.GetAttachment(env.id)
			require.NoError(t, getErr)
			assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), stored.Mode)
		})
	}
}
