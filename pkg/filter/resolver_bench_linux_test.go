//go:build linux

package filter

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"testing"
)

// BenchmarkTCResolverPacket measures kernel execution time only. The same fixture
// runs on the baseline: its spec has no resolver map. New programs configure the
// guard, so this comparison includes the added packet-path enforcement cost.
func BenchmarkTCResolverPacket(b *testing.B) {
	for _, name := range []string{"own_dns", "ordinary_allow"} {
		b.Run(name, func(b *testing.B) {
			spec, err := loadTc()
			if err != nil {
				b.Fatal(err)
			}
			collection, err := ebpf.NewCollection(spec)
			if err != nil {
				b.Fatal(err)
			}
			defer collection.Close()
			if err := collection.Maps["policy_mode"].Put(uint32(0), uint8(ModeAllowlist)); err != nil {
				b.Fatal(err)
			}
			if guard := collection.Maps["resolver_endpoint"]; guard != nil {
				// Stable BPF ABI; avoid relying on a Go type absent from the baseline.
				config := struct {
					Addr                  [16]byte
					Min, Max, Own, Family uint16
				}{Addr: [16]byte{127, 0, 0, 1}, Min: 11000, Max: 11500, Own: 11001, Family: 4}
				if err := guard.Put(uint32(0), config); err != nil {
					b.Fatal(err)
				}
			}
			packet := resolverTestPacket(false, 17, 11001)
			if name == "ordinary_allow" {
				copy(packet[30:34], []byte{198, 51, 100, 1})
				if err := collection.Maps["allowed_ipv4"].Put(IPv4LPMKey{Prefixlen: 32, Addr: [4]byte{198, 51, 100, 1}}, uint8(1)); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			result, duration, err := collection.Programs["filter_egress"].Benchmark(packet, b.N, b.ResetTimer)
			if err != nil {
				b.Fatal(err)
			}
			if result != 0 {
				b.Fatalf("verdict=%d", result)
			}
			b.ReportMetric(float64(duration.Nanoseconds()), "ns/op")
		})
	}
}

func resolverTestPacket(v6 bool, proto byte, port uint16) []byte {
	size := 20
	if v6 {
		size = 40
	}
	p := make([]byte, 14+size+20)
	if v6 {
		binary.BigEndian.PutUint16(p[12:14], 0x86dd)
		p[14] = 0x60
		p[20] = proto
		p[21] = 64
		binary.BigEndian.PutUint16(p[18:20], 20)
		p[14+23] = 1
		p[14+39] = 1
	} else {
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14] = 0x45
		p[22] = 64
		p[23] = proto
		binary.BigEndian.PutUint16(p[16:18], 40)
		copy(p[26:30], []byte{127, 0, 0, 1})
		copy(p[30:34], []byte{127, 0, 0, 1})
	}
	binary.BigEndian.PutUint16(p[14+size:16+size], 12345)
	binary.BigEndian.PutUint16(p[16+size:18+size], port)
	return p
}
