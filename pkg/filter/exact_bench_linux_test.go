//go:build linux

package filter

import (
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// BenchmarkDNSExactKernel measures two real kernel transactions per iteration:
// admission followed by removal. Unrelated occupancy stays constant. Unlike a
// fake-backend benchmark this includes map syscalls and inventory costs.
func BenchmarkDNSExactKernel(b *testing.B) {
	for _, batch := range []int{1, 16} {
		for _, entries := range []int{0, 1024, 4096 - batch} {
			b.Run(fmt.Sprintf("batch_%d/entries_%d", batch, entries), func(b *testing.B) {
				newMap := func(size uint32) *ebpf.Map {
					m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: size, ValueSize: 1, MaxEntries: 4096})
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() { m.Close() })
					return m
				}
				c := &ruleMapCore{}
				c.setRuleMaps(ruleMapHandles{exact4: newMap(4), exact6: newMap(16)})
				seed := make([]net.IP, entries)
				for i := range seed {
					seed[i] = net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
				}
				if err := c.AddDNSAllowedIPs(seed); err != nil {
					b.Fatal(err)
				}
				ips := make([]net.IP, batch)
				for i := range ips {
					ips[i] = net.IPv4(192, 0, 2, byte(i+1))
				}
				// Bound sample storage independently of benchmark calibration.
				samples := make([]int64, 0, 65536)
				stride := max(1, b.N/cap(samples))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					start := time.Now()
					if err := c.AddDNSAllowedIPs(ips); err != nil {
						b.Fatal(err)
					}
					if err := c.RemoveDNSAllowedIPs(ips); err != nil {
						b.Fatal(err)
					}
					if i%stride == 0 && len(samples) < cap(samples) {
						samples = append(samples, time.Since(start).Nanoseconds())
					}
				}
				b.StopTimer()
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				for _, p := range []int{50, 95, 99} {
					b.ReportMetric(float64(samples[(len(samples)-1)*p/100]), fmt.Sprintf("p%d-ns/pair", p))
				}
				b.ReportMetric(float64(b.N)*2/b.Elapsed().Seconds(), "transactions/s")
			})
		}
	}
}
