package daemon

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func BenchmarkServerListWithConcurrentStats(b *testing.B) {
	server := newBenchmarkServer(b, 1000)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := server.List(ctx, &apiv1.ListRequest{PageSize: 1000}); err != nil {
				b.Fatal(err)
			}
			_ = server.GetAttachmentStats()
		}
	})
}

func newBenchmarkServer(b *testing.B, attachmentCount int) *Server {
	b.Helper()

	st, err := store.New(filepath.Join(b.TempDir(), "netfence.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = st.Close()
	})

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    21000,
			PortMax:    22000 + attachmentCount,
			Upstream:   "127.0.0.1:1",
		},
	}
	server, err := NewServer(cfg, st, zerolog.Nop(), "bench")
	if err != nil {
		b.Fatal(err)
	}

	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	for i := 0; i < attachmentCount; i++ {
		id := fmt.Sprintf("att-%06d", i)
		port := 21000 + i
		attachment := &store.Attachment{
			ID:         id,
			Target:     "target-" + id,
			Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(),
			Mode:       apiv1.PolicyMode_POLICY_MODE_DISABLED.String(),
			DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
			DnsAddress: net.JoinHostPort(cfg.DNS.ListenAddr, fmt.Sprintf("%d", port)),
			Metadata:   map[string]string{"bench": "true"},
			AttachedAt: base.Add(time.Duration(i) * time.Nanosecond),
		}
		if err := st.SaveAttachment(attachment); err != nil {
			b.Fatal(err)
		}
		ff := &fakeFilter{stats: filter.Stats{Allowed: uint64(i), Blocked: uint64(i / 2)}}
		server.attachments[id] = &attachmentState{
			info:   attachment,
			filter: ff,
			dns:    NewDNSServer(id, attachment.DnsAddress, cfg.DNS.Upstream, zerolog.Nop(), ff, nil),
		}
	}
	return server
}
