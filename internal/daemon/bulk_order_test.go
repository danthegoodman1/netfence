package daemon

import (
	"net"
	"syscall"
	"testing"

	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
	"github.com/stretchr/testify/require"
)

func TestHealthyBulkDNSFailureDoesNotActivateStaleAllows(t *testing.T) {
	s, st, id, ff, resolver := newTestServerWithAttachment(t)
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{
		Mode:      apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		DenyCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.10/32"}},
		Dns:       &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST, AllowDomains: []*apiv1.DomainEntry{{Domain: "old.example"}}},
	}))
	require.NoError(t, resolver.addIPToFilter("old.example", net.ParseIP("203.0.113.10"), 32, 60))
	ff.dnsRemoveErr = syscall.EIO
	err := s.ApplyRules(id, &apiv1.BulkUpdate{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		Dns:  &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST},
	})
	require.ErrorIs(t, err, syscall.EIO)
	mode, allowed, _, _ := ff.snapshot()
	exact, _ := ff.dnsSnapshot()
	require.Equal(t, filter.ModeDenylist, mode)
	require.Empty(t, allowed)
	require.Contains(t, exact, "203.0.113.10")
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	require.Empty(t, row.PolicyDegradedReason)
}

type observeDNSRemoval struct {
	filter.Filter
	t            *testing.T
	exposed      bool
	beforeRemove func()
}

func (f *observeDNSRemoval) RemoveDNSAllowedIPs(ips []net.IP) error {
	if f.beforeRemove != nil {
		f.beforeRemove()
	}
	mode, err := f.GetMode()
	require.NoError(f.t, err)
	existing, err := f.DNSAllowedIPs()
	require.NoError(f.t, err)
	for _, ip := range existing {
		if mode == filter.ModeAllowlist && ip.String() == "203.0.113.10" {
			f.exposed = true
		}
	}
	return f.Filter.RemoveDNSAllowedIPs(ips)
}

func TestHealthyAllowlistInstallsProtectedSurvivorBeforeRevokingDNS(t *testing.T) {
	s, _, id, ff, resolver := newTestServerWithAttachment(t)
	observed := &observeDNSRemoval{Filter: ff, t: t}
	state := s.attachments[id]
	state.filter, state.dnsSink.filter, state.dnsSink.manager.filter = observed, observed, observed
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		Dns: &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST, AllowDomains: []*apiv1.DomainEntry{{Domain: "old.example"}}}}))
	require.NoError(t, resolver.addIPToFilter("old.example", net.ParseIP("203.0.113.10"), 32, 60))
	observed.beforeRemove = func() {
		mode, allowed, _, _ := ff.snapshot()
		require.Equal(t, filter.ModeAllowlist, mode)
		require.Contains(t, allowed, "203.0.113.10/32", "protected survivor must exist before its DNS owner is removed")
	}
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.10/32"}}, Dns: &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST}}))
}

func TestHealthyBulkDNSFirstPersistenceFailureRetainsSafeOldPacketPolicy(t *testing.T) {
	s, st, id, ff, resolver := newTestServerWithAttachment(t)
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		DenyCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.10/32"}},
		Dns:       &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST, AllowDomains: []*apiv1.DomainEntry{{Domain: "old.example"}}}}))
	require.NoError(t, resolver.addIPToFilter("old.example", net.ParseIP("203.0.113.10"), 32, 60))
	s.saveAttachment = func(*store.Attachment) error { return syscall.EIO }
	require.ErrorIs(t, s.ApplyRules(id, &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		Dns: &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST}}), syscall.EIO)
	mode, _, denied, _ := ff.snapshot()
	require.Equal(t, filter.ModeDenylist, mode)
	require.Contains(t, denied, "203.0.113.10/32")
	exact, _ := ff.dnsSnapshot()
	require.Empty(t, exact)
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	require.Equal(t, apiv1.PolicyMode_POLICY_MODE_DENYLIST.String(), row.Mode, "restart retains old deny policy after DNS-first persistence failure")
}

func TestHealthyBulkRevokesDNSBeforeActivatingAllowlist(t *testing.T) {
	s, _, id, ff, resolver := newTestServerWithAttachment(t)
	observed := &observeDNSRemoval{Filter: ff, t: t}
	state := s.attachments[id]
	state.filter, state.dnsSink.filter, state.dnsSink.manager.filter = observed, observed, observed
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{
		Mode:      apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		DenyCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.10/32"}},
		Dns:       &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST, AllowDomains: []*apiv1.DomainEntry{{Domain: "old.example"}}},
	}))
	require.NoError(t, resolver.addIPToFilter("old.example", net.ParseIP("203.0.113.10"), 32, 60))
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{
		Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		Dns:  &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_ALLOWLIST},
	}))
	require.False(t, observed.exposed)
}
