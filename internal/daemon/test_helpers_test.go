package daemon

import (
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

type fakeFilter struct {
	mu           sync.Mutex
	mode         filter.PolicyMode
	allowed      []string
	denied       []string
	clearCalls   int
	stats        filter.Stats
	setModeCalls int
}

func (f *fakeFilter) SetMode(mode filter.PolicyMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
	f.setModeCalls++
	return nil
}

func (f *fakeFilter) AllowIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed = append(f.allowed, cidr.String())
	return nil
}

func (f *fakeFilter) DenyIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied = append(f.denied, cidr.String())
	return nil
}

func (f *fakeFilter) RemoveAllowedIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed = removeString(f.allowed, cidr.String())
	return nil
}

func (f *fakeFilter) RemoveDeniedIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied = removeString(f.denied, cidr.String())
	return nil
}

func (f *fakeFilter) ClearRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed = nil
	f.denied = nil
	f.clearCalls++
	return nil
}

func (f *fakeFilter) GetStats() (filter.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, nil
}

func (f *fakeFilter) Close() error { return nil }

func (f *fakeFilter) snapshot() (filter.PolicyMode, []string, []string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode, append([]string(nil), f.allowed...), append([]string(nil), f.denied...), f.clearCalls
}

func removeString(values []string, target string) []string {
	out := values[:0]
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func newTestServerWithAttachment(t *testing.T) (*Server, *store.Store, string, *fakeFilter, *DNSServer) {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = st.Close()
	})

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    12000,
			PortMax:    12010,
			Upstream:   "127.0.0.1:1",
		},
	}
	server, err := NewServer(cfg, st, zerolog.Nop(), "test")
	require.NoError(t, err)

	id := "att-1"
	attachment := &store.Attachment{
		ID:         id,
		Target:     "target-1",
		Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(),
		Mode:       apiv1.PolicyMode_POLICY_MODE_DISABLED.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: net.JoinHostPort(cfg.DNS.ListenAddr, "12000"),
		Metadata:   map[string]string{"tenant": "test"},
		AttachedAt: time.Now().UTC(),
	}
	require.NoError(t, st.SaveAttachment(attachment))

	ff := &fakeFilter{}
	dnsServer := NewDNSServer(id, attachment.DnsAddress, cfg.DNS.Upstream, zerolog.Nop(), ff, nil)
	server.mu.Lock()
	server.attachments[id] = &attachmentState{info: attachment, dns: dnsServer, filter: ff}
	server.targetIndex[attachment.Target] = id
	server.portPool[12000] = true
	server.mu.Unlock()

	return server, st, id, ff, dnsServer
}
