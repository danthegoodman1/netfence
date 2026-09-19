# Enforcement and DNS performance review

Measured 2026-09-19. Baseline: main at `6c477ae`. Implementation: `41d4cf8`.
The implementation covers all six phases in [REVIEW_PLAN.md](REVIEW_PLAN.md),
followed by a separate simplification pass. The final diagnostic-only change
(`cc21dd3`) clarifies upgrade errors and does not change the measured paths.

## Results

At 4,095 unrelated entries, a cold DNS query fell from **3.21 ms to 37.7 µs
(85.1× faster)**; sampled p99 fell from **5.56 ms to 65.7 µs**. Sustained serial
throughput rose from **312 to 26,524 queries/s**. These results include real
resolver traffic and kernel map work.

### Exact-map add/remove pairs

| Batch / unrelated entries | Before | After | Speedup | Bytes/pair before → after | Allocs/pair before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 / 0 | 28.4 µs | 1.57 µs | 18.1× | 21,344 → 200 | 100 → 17 |
| 1 / 1,024 | 1.45 ms | 1.57 µs | 924.1× | 304,126 → 200 | 169 → 17 |
| 1 / 4,095 | 5.88 ms | 1.57 µs | 3,740.3× | 1,157,392 → 200 | 229 → 17 |
| 16 / 0 | 51.6 µs | 23.3 µs | 2.2× | 25,642 → 3,952 | 196 → 194 |
| 16 / 1,024 | 1.48 ms | 23.6 µs | 62.6× | 306,756 → 3,952 | 254 → 194 |
| 16 / 4,080 | 5.86 ms | 23.6 µs | 248.7× | 1,160,026 → 3,952 | 314 → 194 |

For one-IP pairs at 4,095 entries, sampled p95 is 8.24 ms → 1.89 µs
and p99 is 9.06 ms → 3.68 µs. Throughput is
340 → 1,272,347 transactions/s. A pair contains two transactions.

### Resolver queries with real kernel maps

| Query / unrelated entries | Mean before → after | p50 before → after | p95 before → after | p99 before → after | Queries/s before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| Warm / 0 | 32.7 µs → 32.1 µs | 32.1 µs → 31.2 µs | 39.9 µs → 39.3 µs | 60.3 µs → 62.3 µs | 30,600 → 31,130 |
| Cold / 0 | 56.6 µs → 37.1 µs | 54.1 µs → 35.7 µs | 72.2 µs → 45.3 µs | 123 µs → 66.5 µs | 17,653 → 26,941 |
| Warm / 4,095 | 32.6 µs → 32.3 µs | 31.9 µs → 31.4 µs | 39.3 µs → 39.4 µs | 59.7 µs → 58.7 µs | 30,638 → 30,956 |
| Cold / 4,095 | 3.21 ms → 37.7 µs | 3.06 ms → 36.3 µs | 4.14 ms → 45.7 µs | 5.56 ms → 65.7 µs | 312 → 26,524 |

Cold high-occupancy allocations, **including fixture reset**, are
1,165,288 → 7,470 B/query and
353 → 135 allocations/query. Reset time, excluded from query latency, is
3.19 ms → 1.52 µs.

Real-backend warm means improve slightly; high-occupancy samples overlap baseline:

- 0 entries: baseline 32.3 µs–32.8 µs, implementation 31.9 µs–32.2 µs; median -1.7%.
- 4,095 entries: baseline 32.1 µs–33.3 µs, implementation 32.2 µs–32.5 µs; median -1.0%.

### Costs and remaining slow path

| Diagnostic | Before | After | Change |
| --- | ---: | ---: | ---: |
| Warm allowlist, fake filter | 32 µs | 31.7 µs | -0.9% |
| Warm proxy, fake filter | 17.4 µs | 17.9 µs | +2.7% |
| TC own-resolver UDP packet, kernel only | 7 ns | 17 ns | +142.9% |
| TC ordinary allowed UDP packet, kernel only | 10 ns | 10 ns | +0.0% |
| Full-capacity ownership/LRU planner, fake filter | 3.73 ms | 3.75 ms | +0.4% |

The proxy increase is measurable: 0.463 µs/query, with 56 → 60 allocations
and 3,313 → 3,585 B/query. This is the cost observed with the new admission
accounting and shared deadline. The TC guard adds 10 ns to the own-resolver case (+143% from
a 7 ns baseline). Ordinary allowed traffic remains 10 ns in this fixture;
the kernel reports whole-nanosecond averages.

Full-capacity logical eviction remains about 3.75 ms and 4.23 MB per operation
(+0.4% median; overlapping sample ranges). The physical transaction redesign
does not remove ownership graph projection/LRU planning. Existing work/churn
budgets bound that slow path.

## Method and limits

- Same privileged Linux Docker image and machine: Intel Core Ultra 9 285,
  Linux 7.0.0-30, Go 1.25.5. Both runs use `GOMAXPROCS=4`, CPU affinity 0–3,
  five samples per case, and `-benchtime=1s`. Baseline and implementation run
  sequentially without concurrent test suites. CPU frequency is not locked;
  reported ranges are observed variation, not confidence intervals.
- Tables report medians across five runs. A latency-tail column is the median
  of each run's sampled percentile, rather than a pooled distribution.
- `BenchmarkDNSExactKernel` uses real IPv4/IPv6 BPF HASH maps. One iteration
  is an add transaction followed by a remove transaction; throughput counts
  both transactions. Occupancy denotes unrelated IPv4 entries. Initialization
  and seeding are outside the timed loop; first-use accounting is amortized.
- `BenchmarkDNSKernelQuery` includes a UDP client, resolver, local upstream,
  policy/ownership admission, mutation barrier, and real BPF maps. One client
  issues requests serially without think time. These are sustained serial
  query rates, not maximum concurrent capacity or Internet DNS latency.
  Cold fixture-reset time is reported separately and excluded from query
  timing/throughput; **allocation counts include the reset**. Its loopback
  TC filter is permissive and has no configured endpoint guard.
- `BenchmarkTCResolverPacket` separately measures kernel program execution
  with the new endpoint guard configured. The baseline has no guard. This
  isolates its IPv4 UDP packet cost; it is not a NIC throughput measurement
  or a measurement of every cgroup/IPv6/TCP path.
- Warm allowlist/proxy diagnostics use the existing fake filter backend.
  Full-capacity eviction is also a manager/fake-backend diagnostic: logical
  ownership projection/LRU planning remains a deliberately separate slow path.
  Routine physical transaction gains do not imply constant-time eviction.

Raw evidence: [baseline](docs/perf/2026-09-19/baseline.txt),
[implementation](docs/perf/2026-09-19/after.txt),
[environment](docs/perf/2026-09-19/environment.txt), and
[validation](docs/perf/2026-09-19/validation.txt).

## Correctness and simplification

All required Docker gates pass: `make check-docker`, `make test-docker`,
`make test-docker-cgroup`, `make test-docker-tc`, and `make bench-docker`.
The validation artifact records revisions and expected helper/negative-test
skips. The final test-only quarantine synchronization change also passed
20 race-enabled repetitions. The pinned/migration/resolver race suite passed
again after the final upgrade-diagnostic wording change. No accepted gate skipped BPF or networking
coverage because of missing capabilities.

Permanent regressions cover second-daemon/wrong-store preservation, live
sockets, healthy packet/DNS transitions and surviving permits, real denied
traffic, cgroup/TC resolver isolation across transports/families and port reuse,
pin compatibility, CIDR identity/expiry/adoption, resource ceilings, shared
deadlines, shutdown, and ambiguous syscall rollback. The denied-canary fixture
exercises 80 transitions; the focused run observed 0 allowed / 70,733 blocked.

Operation-count tests prove that, after initial inventory, routine exact-map
transactions perform no full-map scans at 0 or 4,095 unrelated entries. They
retain capacity preflight and verified restoration of touched preimages; an
unproven rollback invalidates accounting and triggers existing quarantine.

The simplification pass (`83e7fbb`) consolidated transaction normalization and
sorting, removed redundant inventory state and obsolete orphan classification,
and collapsed duplicate apply branches. Resource admission uses nonblocking
channel slots. Existing ownership, mutation, and recovery machinery remains
in use. The pass also closed ambiguous VLAN parsing under an active guard.

Pin schema 2 requires controlled recreation of schema-1 attachments; old pins
are preserved rather than silently detached. See the [README](README.md) for
upgrade steps, immutable resolver endpoints/ranges, durable storage, and hook
limitations.

## Reproduce the comparison

Use a Linux host with functional privileged Docker, BPF, bpffs, and writable
cgroups. Archive the baseline and copy only the three added benchmark fixtures:

```sh
mkdir -p /tmp/netfence-baseline
git archive 6c477ae | tar -x -C /tmp/netfence-baseline
for fixture in pkg/filter/exact_bench_linux_test.go \
  pkg/filter/resolver_bench_linux_test.go \
  internal/daemon/dns_kernel_bench_linux_test.go; do
  cp "$fixture" "/tmp/netfence-baseline/$fixture"
done

sudo -n docker -H unix:///var/run/docker.sock compose run --rm \
  -v /tmp/netfence-baseline:/workspace \
  -e BENCH='BenchmarkDNSExactKernel|BenchmarkDNSKernelQuery|BenchmarkDNSAllowlistQueryWarm|BenchmarkDNSProxyQueryWarm|BenchmarkTCResolverPacket|BenchmarkDNSOwnershipPhysicalPressure' \
  -e COUNT=5 -e GOMAXPROCS=4 \
  bench taskset -c 0-3 scripts/bench-linux.sh ./... -benchtime=1s
```

Repeat the command without the baseline volume override for this branch.
The three fixtures were byte-identical in both measured trees. Choose the same
available CPU cores for both runs if CPUs 0–3 are unavailable on another host.
