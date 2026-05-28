package daemon

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func TestExtractPortHandlesJoinHostPortAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want int
	}{
		{name: "ipv4", addr: "127.0.0.1:12000", want: 12000},
		{name: "hostname", addr: "localhost:12001", want: 12001},
		{name: "ipv6", addr: "[::1]:12002", want: 12002},
		{name: "invalid missing brackets", addr: "::1:12002", want: 0},
		{name: "invalid port", addr: "127.0.0.1:not-a-port", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractPort(tt.addr))
		})
	}
}

func TestServerModeChangesPersistToStoreAndSyncViews(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)

	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	require.NoError(t, server.SetDnsMode(id, apiv1.DnsMode_DNS_MODE_DENYLIST))

	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)

	stored, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), stored.Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST.String(), stored.DnsMode)

	list, err := server.List(context.Background(), &apiv1.ListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Attachments, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, list.Attachments[0].Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, list.Attachments[0].DnsMode)

	syncAttachments := server.GetSyncAttachments()
	require.Len(t, syncAttachments, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, syncAttachments[0].Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, syncAttachments[0].DnsMode)
}

func TestNewServerRestoresIPv6DNSPortReservation(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = st.Close()
	})

	require.NoError(t, st.SaveAttachment(&store.Attachment{
		ID:         "restored",
		Target:     "target",
		Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(),
		Mode:       apiv1.PolicyMode_POLICY_MODE_DISABLED.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: net.JoinHostPort("::1", "12005"),
		Metadata:   map[string]string{},
		AttachedAt: time.Now().UTC(),
	}))

	server, err := NewServer(&config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "::1",
			PortMin:    12005,
			PortMax:    12005,
			Upstream:   "127.0.0.1:1",
		},
	}, st, zerolog.Nop(), "test")
	require.NoError(t, err)

	server.mu.RLock()
	defer server.mu.RUnlock()
	assert.True(t, server.portPool[12005])
}

func TestServerReplaceDNSRulesPersistsAndClearsDynamicCache(t *testing.T) {
	server, st, id, _, dnsServer := newTestServerWithAttachment(t)
	dnsServer.addIPToFilter("example.com", netIP(t, "203.0.113.20"), 32, 60)
	require.NotEmpty(t, dnsServer.ipCache)

	require.NoError(t, server.ReplaceDNSRules(
		id,
		apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "allowed.test", IncludeSubdomains: true}},
		[]*apiv1.DomainEntry{{Domain: "denied.test"}},
	))

	stored, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST.String(), stored.DnsMode)

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Empty(t, dnsServer.ipCache)
	assert.Equal(t, map[string]bool{"allowed.test": true}, dnsServer.allowedDomains)
	assert.Equal(t, map[string]bool{"denied.test": false}, dnsServer.deniedDomains)
}

func netIP(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	require.NotNil(t, ip)
	return ip
}
