# Architecture, correctness, and performance review plan

Review date: 2026-09-19. Baseline: `6c477aeac55bedb37c8634477fdaa2b0d23b0883`.
This is a new plan based on the implementation, independent of earlier roadmaps.
Implementation and the simplification pass are complete on
`codex/enforcement-performance-review`. See [PERFORMANCE_REVIEW.md](PERFORMANCE_REVIEW.md)
for measured deltas, retained raw samples, and validation evidence.

## Overarching goal

Make the existing enforcement guarantees hold across process startup, complete
policy transitions, and multiple workloads sharing a daemon. Make routine DNS
admission scale with the changed response, and bound resolver resource use.
Performance is a required outcome, verified with real-backend measurements.

The broad architecture is worth keeping: small shared BPF verdict functions,
separate protected LPM and regenerable DNS exact maps, a common local/control-plane
command parser, explicit ownership, and extensive failure-injection tests. The
highest leverage changes are at boundaries between these components. A wholesale
rewrite, a different database, or an actor framework is not justified by this
review. Extracting files alone would not address the findings.

## Findings and priority

P1 means an enforcement or isolation issue to address before relying on the
affected deployment. P2 means a concrete correctness or scalability improvement.

| ID | Priority | Finding and consequence | Evidence at baseline | Phase |
| --- | --- | --- | --- | --- |
| R1 | P1 | Default restart can remove enforcement. Default configuration enables persistent pins but leaves `data_dir` empty; the fresh in-memory store has no attachment rows, so startup deletes schema-current pins as orphans. Changing or losing the database has the same risk. A valid schema proves structure, not permission to detach. | `internal/config/config.go:162,304`; `internal/daemon/server.go:936`. Diagnostic D1 reproduced the deletion decision with the existing pin-inspection seam. | 1 |
| R2 | P1 | Exclusive daemon ownership is an unchecked assumption. Startup touches storage/pins before publishing the socket, and socket publication removes a live predecessor's socket. Another process using the pin root with a different/empty store can also classify the first process's pins as orphans. Process-local mutexes cannot protect this. | `cmd/netfenced/cmd/start.go:48,215,258`; `internal/daemon/server.go:643`. D2 replaced a still-open daemon endpoint. README already documents the socket limitation; it remains worth fixing. | 1 |
| R3 | P1 | Complete updates can expose a mixed packet policy. Protected rules and packet mode commit before DNS exact ownership is reconciled. An IP denied by the old denylist and absent from the new allowlist becomes temporarily allowed through an old DNS exact entry. If DNS removal fails with a proven rollback, that exposure persists without a degraded marker. | `internal/daemon/controlplane.go:1173`; `internal/daemon/server.go:3207,3230`; `bpf/filter_common.h`. D3/D4 reproduced both failure and success paths. Existing `TestDegradedFullRecoveryHoldsBlockAllAcrossDNSStageFailure` covers already-degraded recovery, not this healthy transition. | 2 |
| R4 | P1 | Per-attachment DNS ports do not establish workload identity. All listeners share one IP, every attachment gets an all-port bootstrap allow for that IP, and the resolver never authenticates the querying attachment. A restricted workload that can reach a more permissive attachment's listener can forward a forbidden name through it, defeating pre-resolution exfiltration filtering. This does not imply that B's DNS response installs an allow in A's map. | `internal/daemon/server.go:1598,1876`; `internal/daemon/dns.go:179,805`; `bpf/filter_common.h`. D5 confirmed UDP/TCP listener behavior. Full filtered-workload traffic proof remains outstanding. The README's broad-IP warning does not provide isolation, and one dedicated daemon-wide IP still shares every resolver port. | 3 |
| R5 | P2 | CIDR identity differs between operations. `::ffff:192.0.2.1/128` is accepted; incremental operations select IPv4 through `To4()` with prefix 128, bulk replacement selects IPv6 through mask width, and `IPNet.String()` reports `192.0.2.1/32` for the registry key. Installation, removal, TTLs, deduplication, and restore can disagree about the same rule. | `pkg/filter/types.go:231`; `pkg/filter/rule_maps_linux.go:78,88`; `pkg/filter/protected.go:71`; `internal/daemon/ttl.go`. D6 confirmed all three representations. `TestProtectedCanonicalUsesMaskWidthForIPv4MappedIPv6` establishes the existing bulk semantics. | 4 |
| R6 | P2 | A one-IP cold DNS admission still scans and sorts both physical exact maps. Removal and replacement also take full snapshots. The ownership manager's response-sized fast path stops at the filter boundary, so current fake-filter DNS benchmarks omit this occupancy-dependent kernel work. | `pkg/filter/exact.go:80,109,149,176`; `pkg/filter/maps_linux.go:252`; `internal/daemon/dns_ownership.go:1100`; `internal/daemon/dns_bench_test.go:120,516`. D7 counted 4,095 existing keys visited for one new insertion. Kernel latency was not measured here. | 5 |
| R7 | P2 | Bounded DNS map state does not bound resolver resource consumption. Queries reach upstream/proxy I/O before ownership budgets, with no daemon/per-attachment in-flight or accepted-TCP-connection limit. Five-second exchange timeouts apply separately across up to eight upstreams and TCP retries, rather than one query deadline. Successful replies also hold the attachment mutation lane during socket writes. | `internal/daemon/dns.go:179,805,917,1084`; `internal/daemon/dns_sink.go:16`; `internal/daemon/server.go:218`; `internal/daemon/controlplane.go:724`. Static finding; no exhaustion or tail-latency measurement was attempted. | 6 |

## Implementation principles

- Preserve invalid-command no-op behavior, protected-rule non-eviction,
  response-wide DNS admission, survivor continuity, exact-state teardown, and
  conservative handling of ambiguous kernel/storage failures.
- Preserve documented distinctions: cgroup hooks do not revoke established
  connections or cover raw-packet bypasses; TC enforces packets. Userspace TTLs
  and provisional restart ownership remain explicit until deliberately changed.
- Use focused redesigns where they simplify ownership, enforce a missing boundary,
  or remove demonstrated scaling costs. Prefer them to accumulating special cases;
  every new abstraction must have a concrete job in the selected fixes.
- Preserve unidentified pins and enforce one daemon per host. New ownership
  metadata, automatic recovery tooling, and multi-instance coordination are outside
  this plan.
- Share CIDR conversion and identity rules without changing the public IP API.
- Remove whole-map work from routine DNS exact mutations and measure latency,
  throughput, and allocations through the real backend. Preserve warm-path
  performance and rollback guarantees; fake-filter timings are insufficient.
- Each phase stops when its concrete regression and gate pass. Broader abstraction,
  API, migration, or scheduling work needs a demonstrated requirement; it is not
  an implicit follow-on task.

## Testing strategy and review evidence

Use the repository's Docker Linux gates: `make check-docker`, `make test-docker`,
`make test-docker-cgroup`, `make test-docker-tc`, and `make bench-docker`. Run focused
work through the compose `test`/`bench` services. Kernel-sensitive tests must execute
on a host with usable BPF, bpffs, writable cgroups, and privileged networking;
skips or permission failures are not acceptance evidence.

All five required Docker gates passed using the system Docker daemon through
`sudo -n env DOCKER_HOST=unix:///var/run/docker.sock make ...`. Retained
[validation evidence](docs/perf/2026-09-19/validation.txt) names tested revisions,
package results, focused regressions, and expected helper/negative-test skips.
No accepted run skipped real BPF/cgroup/TC coverage for missing capabilities.
The initial review's D1–D7 diagnostic observations are now covered by permanent
regressions asserting corrected behavior, as recorded in the phase ledgers.

The requested post-implementation simplification pass (`83e7fbb`) removed duplicate
exact-transaction normalization, redundant inventory state, obsolete orphan
classification, and duplicate bulk-apply branches. Existing recovery mechanisms
and simple nonblocking resource slots remain. Final review also clarified pin
upgrade diagnostics; the focused pinned/migration/resolver race suite passed
again after that text-only change (`cc21dd3`).

## Phase 1: Make startup ownership and persistence safe

Goal: Fix R1/R2 with configuration validation, one process lock, and conservative
orphan handling. Keep the supported model of one daemon per host.

Scope:
- 1A: Default to a durable data directory when pinning is enabled; reject explicitly
  ephemeral storage combined with pinning. Create/validate the data directory
  before use. Ephemeral operation remains available with pinning disabled.
- 1B: Acquire a host-shared, nonblocking lifetime lock before opening/migrating the
  store or touching pins/socket paths. A second daemon fails before side effects.
  Container deployments must share that lock; supporting independent concurrent
  daemons is outside this scope.
- 1C: Abort startup and preserve orphan pin directories, including current-schema
  ones. Keep existing explicit detach and persisted cleanup-tombstone paths. An
  absent database row alone must never cause automatic unpinning.
- 1D: Document the data requirement, lock location, and manual inspection of
  preserved orphans. No new pin-owner format, recovery CLI, or migration framework.

Completion gate: Default restart preserves enforcement and attachment identity;
second startup and missing/wrong stores cannot silently remove existing state.

Testing plan: Regress D1/D2; test lock collision/release, including different socket
paths; run existing real TC/cgroup restart tests with durable defaults and a
missing-store case. Retain existing detach/tombstone coverage.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 1A: Durable default and validation | `internal/config/persistence_test.go` covers durable defaults and explicit ephemeral validation; startup creates the data directory after locking. |
| Complete | Work | 1B: One host-shared process lock | `TestDaemonLockLifetime` uses a child process to verify collision/release; `TestPrepareDaemonSocketPreservesLiveEndpoint` passes with race detection. |
| Complete | Work | 1C: Preserve orphan pins | `TestRestorePreservesOrphanPinDirs` and existing partial/future-schema preservation tests pass. |
| Complete | Doc | 1D: Configuration and manual recovery guidance | README documents durable storage, `/run/netfence.lock`, container sharing, and preserved orphan inspection. |
| Complete | Test | 1T: Focused startup/restart tests | `TestDaemonLockLifetime`, `TestPrepareDaemonSocketPreservesLiveEndpoint`, and privileged `TestCgroupSecondDaemonAndWrongStorePreservePinnedEnforcement` pass. |
| Complete | Gate | 1G: No unintended startup removal | Full Docker check passes restart, detach/tombstone, wrong-store, and second-daemon regressions; real pins remain enforcing after rejected startup. |

## Phase 2: Fix packet/DNS update ordering in the existing apply path

Goal: Eliminate R3 with one understandable packet/DNS update order. The existing
partial-update failure contract does not require atomic old-or-new snapshots.

Scope:
- 2A: Extend `applyPreparedRules`, which already serves both complete-update APIs.
  Before entering ALLOWLIST from another mode, remove obsolete DNS exact allows
  while that tier is still inactive. Add only the projection/order helpers needed
  by this change; keep the existing protected-map transaction.
- 2B: Test the ordering across mode pairs. Same-mode ALLOWLIST updates still need
  protected replacements installed before removing DNS ownership that may cover
  a surviving destination. Do not blindly move all DNS work before all CIDR work.
  A small combined policy plan/apply component is justified if it makes these
  dependencies explicit and replaces scattered orchestration; it need not become
  a reusable transaction framework.
- 2C: Reuse existing degradation and recovery helpers when an apply failure leaves
  an unsafe combination. Verify restart at the affected ordering boundaries.
  Preserve the documented partial-update failure contract where it is safe;
  generalized journaling of all policy state is not required.

Out of scope: versioned policy generations, map-in-map switching, or a general
lifecycle/state-machine rewrite without a demonstrated failing case. Normal
successful updates must retain the existing survivor-continuity guarantee;
blanket BLOCK_ALL is not a substitute for correct ordering.

Completion gate: A destination blocked before and after the complete update never
becomes allowed by stale exact state. Failed updates cannot leave the R3 exposure
active. Existing survivor and degraded-recovery tests still pass.

Testing plan: Make D3/D4 permanent regressions; cover entering/leaving/staying in
ALLOWLIST and ownership transfers between tiers, with DNS/map/store failures at
the changed boundaries. Extend existing real traffic tests with the denied canary.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 2A: Correct ordering in the existing apply path | `applyPreparedRules` revokes obsolete exact keys before entering ALLOWLIST; permanent healthy-transition success/failure regressions pass. |
| Complete | Decision | 2B: Validate ordering and its implementation boundary | `bulk_order_test.go` verifies healthy transitions and same-ALLOWLIST protected survivors; existing continuity tests pass in the full Docker check. |
| Complete | Work | 2C: Failure and restart containment | `TestHealthyBulkDNSFirstPersistenceFailureRetainsSafeOldPacketPolicy` preserves the durable old mode; existing degraded recovery and restart tests pass. |
| Complete | Test | 2T: Focused faults and denied-canary traffic | `bulk_order_test.go` and `TestCgroupBulkTransitionNeverAllowsDeniedCanary` pass; focused traffic run observed 0 allowed / 70,733 blocked over 80 transitions. |
| Complete | Gate | 2G: R3 eliminated with an understandable apply order | Full Docker check passes ordering, fault, survivor, recovery, and denied-canary tests; existing transaction and degraded-state machinery retained. |

## Phase 3: Prevent access to sibling DNS endpoints

Goal: Close R4 for the existing shared-IP/per-attachment-port topology. This remains
the most substantial fix: listener configuration alone cannot enforce isolation.

Scope:
- 3A: Keep the existing topology. Restrict workload access to Netfence's reserved
  resolver endpoints at its cgroup/TC hook so only its assigned endpoint is usable.
  Apply that restriction before broad carve-outs and IP allows. Do not build a
  general layer-4 policy API, identity service, or network-namespace provisioner.
- 3B: Add only the endpoint/address-range information and protocol parsing needed
  for that restriction. Cover UDP/TCP and IPv4/IPv6; unsupported or ambiguous
  packets targeting the reserved endpoints must not bypass the check. Broader
  restrictions on unrelated services at the listener IP are outside this fix.
- 3C: Handle port reuse and restore explicitly. Reuse existing upgrade machinery
  if sufficient; otherwise retain old enforcement and report that controlled
  upgrade/recreation is required before claiming endpoint isolation. Do not add a
  new online migration system or silently detach older pinned programs.

Completion gate: Workload A cannot cause an upstream/proxy query through B's
resolver, including with default localhost carve-outs; its own DNS still works.
Document the existing cgroup raw-packet/established-socket limits accurately.

Testing plan: One focused two-workload fixture with a counting upstream, conflicting
policies, both transports/families, and actual cgroup/TC filters. Exercise relevant
fragment/malformed-packet cases, port reuse, and pinned-state compatibility.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Decision | 3A: Narrow endpoint restriction in the current topology | `resolver_endpoint` map and shared BPF helpers restrict the reserved ports before carve-outs and DISABLED. |
| Complete | Work | 3B: Implement endpoint checks | `TestTCResolverGuardPrecedesCarveoutsAndHandlesAmbiguousPackets` executes actual kernel verdicts for both families/transports and malformed/fragmented input. |
| Complete | Work | 3C: Reuse/restore compatibility | `TestResolverEndpointPinnedRestoreAndSchemaOnePreservation`, `TestRestoreRecreatedFilterStaysBlockedUntilResolverIsReady`, legacy migrations, and live port-reuse tests pass. |
| Complete | Test | 3T: Two-workload endpoint regression | `TestCgroupSiblingResolverIsolation` and `TestTCSiblingResolverIsolation`: both families/transports, conflicting policies, zero forbidden upstream observations, DISABLED, port reuse. |
| Complete | Gate | 3G: No sibling-resolver bypass in the supported model | Both cgroup and TC isolation traffic tests pass; README documents schema-1 controlled recreation, immutable endpoint/range, and hook/fragment limitations. |

## Phase 4: Align CIDR conversion and registry identity

Goal: Fix R5 without replacing the public `net.IPNet` API or rewriting rule storage.

Scope:
- 4A: Share a checked family/key conversion using mask width, consistent with
  `TestProtectedCanonicalUsesMaskWidthForIPv4MappedIPv6`. Use an internal key or
  lossless canonical encoding for registry identity and bulk deduplication instead
  of `IPNet.String()` where it loses address family. Keep the change local.
- 4B: Validate masks before mutation and preserve family/prefix through restore.
  Display formatting must not become an alternate identity.

Completion gate: A CIDR added through bulk or incremental commands can be removed,
expired, and restored consistently; native IPv4 and mapped IPv6 cannot collide.

Testing plan: Focused cases for native v4/v6, mapped v6, masked host bits, and invalid
masks, including bulk-add/incremental-remove, expiry, and restore. Verify the
problematic keys against real LPM maps through the shared adapter.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 4A: Shared conversion and lossless registry identity | `filter.CIDRPrefix` and lossless identity shared by incremental, bulk, and TTL operations; kernel mapped-v6 regression passes. |
| Complete | Work | 4B: Validation and restore consistency | `TestMappedCIDROwnershipSurvivesBulkRemovalExpiryAndAdoption` and invalid-mask tests pass with race detection. |
| Complete | Test | 4T: Cross-operation CIDR regressions | `TestCIDRIdentityPreservesFamilyAndMasksHostBits`, `TestMappedCIDRBulkAndIncrementalUseSameKernelKey`, and ownership expiry/adoption regression pass. |
| Complete | Gate | 4G: Consistent physical identity | Real LPM and registry regressions pass in the full Docker check; public net.IPNet API retained. |

## Phase 5: Make routine DNS exact mutations scale with the batch

Goal: Eliminate R6's occupancy-dependent success-path work and demonstrate the
improvement through real filter/resolver measurements. This phase is required.

Scope:
- 5A: Baseline one-IP cold admission at empty and near-full occupancy, batched
  admission/removal, and real resolver-to-map traffic. Use the existing compose
  benchmark harness and separate fixture work. Include sustained load and warm
  queries so throughput and tail latency are visible alongside per-operation cost.
- 5B: Redesign the physical exact-map transaction locally. Prefer cached capacities
  and counts plus prior state for touched keys over a fresh whole-map snapshot.
  Initialize accounting on create/adopt, update it on committed effects, and
  invalidate it on ambiguity. Retain full inventories for adoption and exceptional
  recovery. A full membership mirror is needed only if touched-key lookups and
  counters cannot satisfy the contract; do not add redundant authoritative caches.
- Preserve response-wide capacity checks, unchanged keys, and verified rollback
  after before/after-effect errors. Reuse the existing sole-writer lock and error
  types. This is a justified transaction redesign, limited to exact-map operations;
  rewriting logical DNS ownership/LRU planning is outside scope.
- 5D: Record before/after latency, throughput, allocations, and backend operation
  counts. Distinguish real-backend results from manager-only diagnostics. Unrelated
  protected-map telemetry optimization is outside scope.

Completion gate: Successful normal fixed-size exact admission/removal performs no
full-map enumeration and has backend operation counts independent of unrelated
occupancy. Real measurements show improved cold performance at high occupancy,
with warm performance within baseline variance and rollback/capacity guarantees
intact. Full-capacity eviction/planning remains a separately measured slow path.

Testing plan: Operation-count tests at multiple occupancies; relevant capacity,
before/after-effect rollback, and adoption regressions. Use repeated compose
`bench` samples and `make bench-docker`; report medians and p95/p99 resolver latency
under a stated load. If measurements do not demonstrate the gain, investigate the
remaining cost rather than completing the phase on microbenchmarks alone.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Test | 5A: Real-backend baseline | Identical real-kernel and UDP resolver fixtures on main/implementation, five samples each with GOMAXPROCS=4 and CPUs 0–3; retained baseline/after logs under `docs/perf/2026-09-19/`. |
| Complete | Work | 5B: Bounded exact-map transaction redesign | `exactDNSState` caches only counts/capacities and transaction preimages. Existing ambiguous syscall rollback tests and operation-count tests pass. |
| Complete | Doc | 5D: Before/after performance evidence | `PERFORMANCE_REVIEW.md` records medians, p50/p95/p99, throughput, allocation deltas, warm/packet overhead, full-capacity planner costs, and measurement boundaries. |
| Complete | Test | 5T: Scaling and safety regressions | `exact_state_test.go`, existing fault/capacity/adoption tests, full Docker gates, and matched warm/cold benchmarks pass; normal mutations perform zero full inventories after adoption. |
| Complete | Gate | 5G: Measured scalable admission with intact guarantees | At 4,095 entries: cold queries 3.21 ms → 37.7 µs (85.1×), one-IP pairs 5.88 ms → 1.57 µs (3,740×); real-resolver warm queries do not regress. Rollback/capacity gates pass. |

## Phase 6: Add simple resolver resource limits

Goal: Address R7 with bounded admission and one total query deadline, keeping the
existing mutation lease, response-write deadlines, and dispatch architecture.

Scope:
- 6A: Use simple per-attachment and daemon ceilings for active upstream/proxy work
  and accepted TCP connections, including idle clients. Admission must not create
  an unbounded waiting queue. Drop overloaded UDP work or close/reject excess TCP
  work promptly; overload responses must not create a new blocking backlog.
- 6B: Apply one query deadline across failover/TCP retries/proxy work, derived from
  the existing shutdown context. Release admission slots on every completion path.
- 6C: Use existing error counters to surface overload; retain the existing
  rate-limited admission diagnostics.
  No new telemetry subsystem, priority scheduler, parallel control-plane dispatcher,
  TTL scheduler rewrite, DNS cache, or connection pool is needed for this phase.

Completion gate: Outstanding upstream work and accepted TCP connections stay within
the selected bounds; timeout, overload, and shutdown release resources. Preserve
existing policy synchronization instead of introducing new fairness guarantees.

Testing plan: Deterministic blocking upstream/proxy and idle-TCP tests, offered load
above the ceilings, total failover deadline, cancellation, and slot recovery.
Use compose `test`; retain the existing policy/reply synchronization regressions.
Compare DNS throughput and latency below saturation to ensure admission accounting
does not introduce a material warm-path regression.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 6A: Simple admission and connection ceilings | Per-attachment/global nonblocking query and accepted-TCP limits; idle connection and cross-attachment tests pass. |
| Complete | Work | 6B: Total deadline and slot cleanup | One context deadline spans proxy and upstream attempts; cancellation/deadline/overload release tests pass. |
| Complete | Work | 6C: Minimal overload diagnostics | `dns.go` increments existing dns_queries_errors on query/connection rejection; resource tests check overload counters and README documents their meaning. |
| Complete | Test | 6T: Bounds, cleanup, and accounting overhead | `dns_resources_test.go` passes query/TCP ceilings, deadline, overload, cancellation, and slot reuse; real-resolver warm means do not regress, proxy diagnostic costs +0.463 µs (+2.7%) as explicitly reported. |
| Complete | Gate | 6G: Bounded retained resolver work | Full Docker check/test gates retain synchronization guarantees; resource tests prove bounded work and cleanup. `PERFORMANCE_REVIEW.md` records accounting overhead. |

## Execution order and stopping rules

Capture the Phase 5 baseline early. Phases 1–4 address concrete correctness/isolation
issues; Phase 4 is a small independent correction. Phase 5's implementation depends
on sole ownership from Phase 1 and must fit Phase 2's final apply order. Phase 6 adds
basic resource bounds and must preserve performance. All six phases remain in scope.

Retain the existing guarantees and test infrastructure. Run the relevant Docker
gates for each change; a permission failure or skip is not kernel evidence. Do not
expand a passing phase into a general architecture cleanup. A focused redesign is
appropriate when it makes the required behavior simpler or faster; justify larger
mechanisms with a specific failing invariant, measured cost, or reduction in
duplicated responsibilities. Preserve the current architecture where it works.
