//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// BenchmarkProtectedOccupancyMaxCapacity measures the Linux kernel-map walk
// both directly and through heartbeat stats at the configured production
// maximum: 4 independent protected LPM maps × 4096 entries. Setup is outside
// the timed regions; the benchmark reports allocations so a future accidental
// return to full key snapshots/sorting is immediately visible in bench-docker.
func BenchmarkProtectedOccupancyMaxCapacity(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("benchmark requires root")
	}
	cgroupPath, err := os.MkdirTemp("/sys/fs/cgroup", "netfence-protected-stats-bench-")
	if err != nil {
		b.Skipf("creating benchmark cgroup: %v", err)
	}
	b.Cleanup(func() { _ = os.Remove(cgroupPath) })

	f, err := filter.NewCgroupFilterWithOptions(cgroupPath, filter.ModeDisabled, filter.DefaultCarveouts(), filter.Options{
		MaxRuleEntries: 4096,
	})
	if err != nil {
		b.Skipf("creating cgroup filter: %v", err)
	}
	b.Cleanup(func() { _ = f.Close() })

	allowed := make([]*net.IPNet, 0, 8192)
	denied := make([]*net.IPNet, 0, 8192)
	for i := 0; i < 4096; i++ {
		v4, err := filter.ParseCIDR(fmt.Sprintf("10.%d.%d.1/32", i>>8, i&0xff))
		if err != nil {
			b.Fatal(err)
		}
		v6, err := filter.ParseCIDR(fmt.Sprintf("2001:db8:%x::1/128", i))
		if err != nil {
			b.Fatal(err)
		}
		allowed = append(allowed, v4, v6)
		denied = append(denied, v4, v6)
	}
	if err := f.ReplaceProtectedRules(allowed, denied, filter.ModeDisabled); err != nil {
		b.Fatalf("filling protected maps: %v", err)
	}
	occupancy, err := f.ProtectedRuleOccupancy()
	if err != nil {
		b.Fatal(err)
	}
	for _, usage := range []filter.RuleMapUsage{
		occupancy.AllowedIPv4, occupancy.AllowedIPv6, occupancy.DeniedIPv4, occupancy.DeniedIPv6,
	} {
		if usage.Entries != 4096 || usage.Capacity != 4096 {
			b.Fatalf("benchmark map not full: %+v", occupancy)
		}
	}

	st, err := store.New(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	server, err := NewServer(&config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    21000,
			PortMax:    21000,
			Upstream:   "127.0.0.1:1",
		},
	}, st, zerolog.Nop(), "bench")
	if err != nil {
		b.Fatal(err)
	}
	const id = "protected-max-capacity"
	attachment := &store.Attachment{
		ID:         id,
		Target:     cgroupPath,
		Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP.String(),
		Mode:       apiv1.PolicyMode_POLICY_MODE_DISABLED.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: "127.0.0.1:21000",
		AttachedAt: time.Now().UTC(),
	}
	server.attachments[id] = &attachmentState{info: attachment, filter: f, ttls: newTTLRegistry()}
	if stats := server.GetAttachmentStats(); len(stats) != 1 ||
		stats[0].ProtectedAllowIpv4Entries != 4096 || stats[0].ProtectedAllowIpv6Entries != 4096 ||
		stats[0].ProtectedDenyIpv4Entries != 4096 || stats[0].ProtectedDenyIpv6Entries != 4096 {
		b.Fatalf("end-to-end stats fixture is not full: %+v", stats)
	}

	b.Run("ProtectedRuleOccupancy", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := f.ProtectedRuleOccupancy(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("GetAttachmentStats", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			stats := server.GetAttachmentStats()
			if len(stats) != 1 || stats[0].ProtectedDenyIpv6Entries != 4096 {
				b.Fatalf("invalid stats snapshot: %+v", stats)
			}
		}
	})
}
