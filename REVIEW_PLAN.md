# Architecture, correctness, and performance review plan

Review date: 2026-09-19. Baseline: `6c477aeac55bedb37c8634477fdaa2b0d23b0883`.
This is a new plan based on the implementation, independent of earlier roadmaps.
Implementation is in progress on `codex/enforcement-performance-review`.

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

During the initial review, rootless `make check-docker` completed formatting, BPF
generation, and vet, and its race tests passed for `cmd/netfenced/cmd`,
`internal/config`, `internal/daemon`, and `internal/store`. The overall gate
**failed**: BPF map creation returned `operation not permitted`, and creating test
cgroups returned `permission denied`. No production kernel-performance claim or
successful integration gate is made. Log: `/tmp/netfence-review-check.log`.

The system Docker daemon is usable through `sudo -n docker -H
unix:///var/run/docker.sock`. The isolated baseline's full `check` service passed
(including privileged integration tests); `/tmp/netfence-clean-baseline-check.log`.
Implementation evidence below distinguishes focused tests from the final gates.

Seven temporary diagnostic probes passed with `-race` using an external Go
overlay, leaving production and test sources unchanged. They assert the observed
current behavior, not the desired fixed behavior. Files are session-local under
`/tmp/netfence-review-probes`; output is `/tmp/netfence-review-probes.log`.

```sh
docker compose run --rm -v /tmp/netfence-review-probes:/review:ro test \
  go test -race -count=1 -v -overlay=/review/overlay.json \
  -run '^TestReview' ./internal/daemon ./pkg/filter ./cmd/netfenced/cmd
```

| Diagnostic | Reproduction and observed result |
| --- | --- |
| D1: `TestReviewDefaultRestartDeletesCommittedOrphan` | Load default config; use a temporary pin root and a fresh default store; classify an existing attachment directory as current via the test seam; call `Start`. The directory is removed. This proves the cleanup decision, not a real-kernel detach. |
| D2: `TestReviewSocketPublicationReplacesLiveDaemonEndpoint` | Publish two listeners sequentially at the same socket path without closing the first. Both calls succeed; new connections reach the second listener. |
| D3: `TestReviewHealthyBulkCanActivateStaleDNSAllow` | Start with IP denylist containing `203.0.113.10/32` and a DNS owner for that exact IP. Replace with empty packet/DNS allowlists; inject `EIO` on exact removal. Result: error returned, live mode ALLOWLIST, stale exact key present, no degraded marker. |
| D4: `TestReviewSuccessfulBulkHasMixedPacketPolicy` | Same transition without failure; observe the exact-removal call. Packet mode is already ALLOWLIST while the old exact key remains installed. This is a userspace ordering observation; BPF source determines the resulting verdict. |
| D5: `TestReviewResolverEndpointDoesNotAuthenticateAttachment` | Start restricted A and disabled/forwarding B on the same IP. The same client receives REFUSED from A and an upstream answer from B over both UDP and TCP. No real attachment filter was used in this probe. |
| D6: `TestReviewMappedCIDRUsesDifferentPhysicalFamilies` | Parse `::ffff:192.0.2.1/128`; inspect incremental key, bulk key, and registry string: IPv4/prefix 128, IPv6/prefix 128, and `192.0.2.1/32`, respectively. |
| D7: `TestReviewColdExactAddInventoriesWorkingSet` | Seed a counting backend with 4,095 keys; add one unrelated IP. Observe two family inventories visiting 4,095 keys for one put. This is operation-count evidence, not a kernel benchmark. |

For implementation, convert the relevant reproductions into permanent regression
tests asserting the corrected behavior. Add model/interleaving tests at component
boundaries and traffic tests for the actual guarantees. Preserve existing failure
injection, pin migration, DNS ownership, and reconnect tests.

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
| Complete | Work | 1A: Durable default and validation | `config/persistence_test.go`: durable default and explicit ephemeral validation; startup creates the data directory after locking. |
| Complete | Work | 1B: One host-shared process lock | `TestDaemonLockLifetime` uses a child process to verify collision/release; `TestPrepareDaemonSocketPreservesLiveEndpoint` passes with race detection. |
| Complete | Work | 1C: Preserve orphan pins | `TestRestorePreservesOrphanPinDirs` and existing partial/future-schema preservation tests pass. |
| Complete | Doc | 1D: Configuration and manual recovery guidance | README documents durable storage, `/run/netfence.lock`, container sharing, and preserved orphan inspection. |
| Incomplete | Test | 1T: Focused startup/restart tests | Missing: D1/D2 regressions and privileged restart results. |
| Incomplete | Gate | 1G: No unintended startup removal | Missing: passing 1T with detach/tombstone behavior retained. |

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
| In Progress | Decision | 2B: Validate ordering and its implementation boundary | Existing protected-map transaction retained; focused ordering and failure tests pass. Needs final continuity/denied-canary gate. |
| In Progress | Work | 2C: Failure and restart containment | DNS-first failures retain the old inert exact tier; existing degraded recovery tests pass. Needs final restart/traffic evidence. |
| Incomplete | Test | 2T: Focused faults and denied-canary traffic | Missing: permanent D3/D4 regressions and privileged traffic results. |
| Incomplete | Gate | 2G: R3 eliminated with an understandable apply order | Missing: passing 2T and existing continuity/recovery tests. |

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
| In Progress | Work | 3C: Reuse/restore compatibility | Schema 2 pins the guard; schema 1 is preserved with controlled-upgrade error. Port-reuse traffic passes; final pinned regression pending. |
| Complete | Test | 3T: Two-workload endpoint regression | `TestCgroupSiblingResolverIsolation` and `TestTCSiblingResolverIsolation`: both families/transports, conflicting policies, zero forbidden upstream observations, DISABLED, port reuse. |
| Incomplete | Gate | 3G: No sibling-resolver bypass in the supported model | Missing: passing 3T and documented compatibility/limitations. |

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
| Incomplete | Test | 4T: Cross-operation CIDR regressions | Missing: permanent D6 regression and real-map validation. |
| Incomplete | Gate | 4G: Consistent physical identity | Missing: passing 4T without a public API migration. |

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
| In Progress | Test | 5A: Real-backend baseline | Five baseline kernel and resolver samples captured under `/tmp/netfence-baseline*-bench.log`; final controlled before/after report pending. |
| Complete | Work | 5B: Bounded exact-map transaction redesign | `exactDNSState` caches only counts/capacities and transaction preimages. Existing ambiguous syscall rollback tests and operation-count tests pass. |
| Incomplete | Doc | 5D: Before/after performance evidence | Missing: retained real-backend samples, tails, and operation counts. |
| Incomplete | Test | 5T: Scaling and safety regressions | Missing: operation bounds, fault/adoption tests, and warm-path comparison. |
| Incomplete | Gate | 5G: Measured scalable admission with intact guarantees | Missing: successful 5T and demonstrated gains in 5D. |

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
- 6C: Use existing error counters and rate-limited diagnostics to identify overload.
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
| Incomplete | Work | 6C: Minimal overload diagnostics | Missing: existing-counter/log integration without new scheduling infrastructure. |
| Incomplete | Test | 6T: Bounds, cleanup, and accounting overhead | Missing: deterministic Docker tests and below-saturation performance comparison. |
| Incomplete | Gate | 6G: Bounded retained resolver work | Missing: passing 6T and existing synchronization tests. |

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
