//go:build linux

package daemon

import (
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
	"github.com/miekg/dns"
)

// BenchmarkDNSKernelQuery includes UDP client/server, policy, upstream, ownership
// admission, and actual BPF exact maps. Cold reset is synchronized and reported
// separately; latency samples cover the query itself. It requires isolated Linux
// networking: a permissive TC filter is attached to the container's loopback.
func BenchmarkDNSKernelQuery(b *testing.B) {
	for _, entries := range []int{0, 4095} {
		for _, cold := range []bool{false, true} {
			b.Run(fmt.Sprintf("entries_%d/cold_%t", entries, cold), func(b *testing.B) {
				dnsServer, _, _ := benchmarkRegistrySink(b)
				sink := dnsServer.sink.(*dnsFilterSink)
				f, err := filter.NewTCFilter("lo", filter.ModeDisabled, filter.DirectionEgress, filter.DefaultCarveouts())
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { f.Detach() })
				sink.filter, sink.manager.filter = f, f
				sink.server.attachments[sink.id].filter = f
				sink.manager.limits = dnsAdmissionLimits{4096, 64, 4096, 1024, 8192}
				sink.server.dnsAdmissionCeilings = sink.manager.limits
				dnsServer.limits, dnsServer.limitCeilings = sink.manager.limits, sink.manager.limits
				if err := dnsServer.ReplaceRules(apiv1.DnsMode_DNS_MODE_ALLOWLIST,
					[]*apiv1.DomainEntry{{Domain: "example.com"}, {Domain: "large.example"}}, nil, []string{startTestUpstream(b)}); err != nil {
					b.Fatal(err)
				}
				seeded := populatedDNSOwnershipManager(b, entries, sink.server.now())
				sink.manager.entries = seeded.entries
				sink.manager.rebuildOwnershipIndexes()
				seed := make([]net.IP, 0, entries)
				for addr := range seeded.entries {
					seed = append(seed, net.IP(addr.AsSlice()))
				}
				if err := f.AddDNSAllowedIPs(seed); err != nil {
					b.Fatal(err)
				}
				startBenchmarkDNSServer(b, dnsServer)
				client := &dns.Client{Timeout: 2 * time.Second}
				request := new(dns.Msg)
				request.SetQuestion("example.com.", dns.TypeA)
				lookup := func() {
					resp, _, err := client.Exchange(request, dnsServer.listenAddr)
					if err != nil {
						b.Fatal(err)
					}
					if resp.Rcode != dns.RcodeSuccess {
						b.Fatalf("rcode=%d", resp.Rcode)
					}
				}
				lookup()
				// The test upstream returns one A record; find its canonical key.
				var incoming net.IP
				// Use the actual response rather than relying on fixture IP constants.
				resp, _, err := client.Exchange(request, dnsServer.listenAddr)
				if err != nil {
					b.Fatal(err)
				}
				for _, rr := range resp.Answer {
					if a, ok := rr.(*dns.A); ok {
						incoming = a.A
					}
				}
				if incoming == nil {
					b.Fatal("upstream returned no A record")
				}
				addr, _ := canonicalDNSAddr(incoming)
				edge := dnsOwnershipKey{query: "example.com", owner: dnsPolicyOwner{kind: dnsOwnerRule, domain: "example.com"}}
				samples := make([]int64, 0, 65536)
				stride := max(1, (b.N+cap(samples)-1)/cap(samples))
				var resets time.Duration
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if cold {
						start := time.Now()
						done, err := sink.BeginAdmission()
						if err != nil {
							b.Fatal(err)
						}
						dnsServer.mu.Lock()
						removeColdDNSOwnershipBenchmarkAdmission(b, sink.manager, addr, edge)
						if err := f.RemoveDNSAllowedIPs([]net.IP{incoming}); err != nil {
							b.Fatal(err)
						}
						dnsServer.mu.Unlock()
						done()
						resets += time.Since(start)
					}
					start := time.Now()
					lookup()
					if i%stride == 0 {
						samples = append(samples, time.Since(start).Nanoseconds())
					}
				}
				b.StopTimer()
				queryElapsed := b.Elapsed() - resets
				b.ReportMetric(float64(queryElapsed.Nanoseconds())/float64(b.N), "ns/op")
				b.ReportMetric(float64(b.N)/queryElapsed.Seconds(), "queries/s")
				b.ReportMetric(float64(resets.Nanoseconds())/float64(b.N), "fixture-reset-ns/op")
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				for _, p := range []int{50, 95, 99} {
					b.ReportMetric(float64(samples[(len(samples)-1)*p/100]), fmt.Sprintf("p%d-ns/query", p))
				}
			})
		}
	}
}
