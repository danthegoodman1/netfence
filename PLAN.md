# Development Plan

## Overarching Goal

Make netfence's core guarantee actually hold end-to-end: for an attached target in an enforcing mode, egress traffic to destinations outside the configured policy is blocked — for all protocols and topologies the docs claim (cgroup and TC, TCP and UDP, direct-to-IP and DNS-resolved) — and rule changes converge without transient allow/block windows. Secondary goals: the daemon survives restarts/upgrades without dropping enforcement, the control-plane channel is secure, and the codebase sheds duplication and dead weight so the enforcement logic has one source of truth.

Non-goals: L7/protocol-aware filtering, per-port rules, inbound (ingress-to-workload) policy, and multi-daemon coordination. The existing guarantees are kept unless a phase explicitly proposes a better one (Phase 1 does: the hardcoded link-local always-allow is replaced with policy-controlled carve-outs).

## Implementation Principles

- Guarantee-first: any gap that lets policy-violating traffic through (or blocks allowed traffic) outranks all other work.
- Fail-closed by default in enforcing modes; every fail-open path must be an explicit, documented decision.
- Capacity behavior is source-aware and deterministic: control-plane CIDRs and deny rules are never silently evicted; only regenerable DNS-derived allow entries may be reclaimed, expired first and then LRU within a configured per-attachment eviction budget. Memory, ownership metadata, and churn are bounded; once the budget is exhausted, preserve the working set, reject new DNS admissions explicitly, and fail closed.
- Enforcement logic lives in one place: shared BPF header for the two programs, shared Go rule-map core for the two filter types.
- Every enforcement claim gets a traffic-level test in the Docker Linux gate (AGENTS.md); macOS results are never evidence.
- Preserve the measured warm-path numbers (README "Performance snapshot"): connected-socket overhead must stay ~noise; re-run `make bench-docker` after each BPF change.
- API changes are allowed (proto is pre-1.0), but each one ships with README + proto-comment updates in the same commit.

## Testing Strategy

- Docker Linux gate is the only source of truth: `make check-docker`, `make test-docker`, `make test-docker-cgroup`, `make test-docker-tc`, `make bench-docker` (AGENTS.md).
- New traffic-level regression tests accompany every Phase 1–2 fix (unconnected UDP, veth-pair TC direction, VLAN frames, bulk-update windows, TTL expiry).
- Unit tests (`internal/daemon`, `internal/store`) keep covering lock/rollback/pagination logic with fakes; race detector stays on in `check-docker`.
- Benchmarks are a regression gate: warm connected-socket path stays ~0 overhead vs no-eBPF baseline; DNS query path stays within current numbers ±20%.

## Phase 1: Close enforcement bypasses in the eBPF layer

Goal:
No traffic escapes an enforcing-mode attachment through a hook gap, a parsing gap, or a hardcoded carve-out; the TC feature filters the direction the README promises.

Scope:
- 1A — Cgroup UDP bypass: `bpf/filter_cgroup.c` only attaches `cgroup/connect4`/`connect6`, so unconnected UDP (`sendto`/`sendmsg` with an address, e.g. DNS exfil direct to an attacker's port 53) is never filtered. Add `cgroup/sendmsg4` + `cgroup/sendmsg6` programs sharing the same maps/verdict logic, attach them in `pkg/filter/filter_cgroup.go` (`NewCgroupFilter`). Connected-socket `send()` skips these kernel hooks, so the warm-path benchmark must be unchanged.
- 1B — TC direction: `link.AttachTCXEgress` on a veth host-side peer or VM tap (`filter_tc.go:44-48`) sees host→workload traffic, not workload egress — on the documented topology (README: "veth", `fcr-*` taps) allowlist mode blocks return traffic by the workload's own daddr instead of filtering its egress. Add an explicit `direction` field to `AttachRequest` (default EGRESS to preserve current in-netns/uplink behavior; INGRESS for host-side veth/tap peers, where daddr is the true destination) rather than silently flipping the attach point, and document which side/direction pairs are correct.
- 1C — TC ethertype fail-open: in allowlist mode `filter_tc.c:217-246` parses a raw `ethhdr` and lets every non-IPv4/IPv6 ethertype through (`return TC_ACT_OK`), so VLAN-tagged (802.1Q) frames bypass the allowlist entirely, and L3 devices (tun/wireguard, where there is no ethhdr) misparse and fall through open. (Block-all is unaffected — it shoots at `:212` before the parse.) Use `skb->protocol`, handle VLAN, and default-deny unknown ethertypes in allowlist mode with an explicit ARP allowance.
- 1D — Policy-controlled carve-outs: `is_link_local_v4` always-allows 169.254.0.0/16 in both programs — including 169.254.169.254, the cloud metadata service, a credential-theft target the sandboxing use case must be able to block. Move localhost/link-local/ND-multicast carve-outs into a small config map populated at filter creation (defaults: localhost on, v4 link-local OFF, IPv6 `ff02::/16` + ARP on for TC so NDP/gateway resolution survives allowlist mode; v4 broadcast/multicast decided here too).

Out of scope:
- Raw-socket (CAP_NET_RAW) bypass of cgroup hooks — document as a known limitation instead (TC mode covers it).
- Per-port/protocol rules.

Completion gate:
A traffic-level Docker-gate test exists and passes for each bypass (unconnected UDP blocked in cgroup allowlist mode; veth-pair workload egress filtered in TC mode with correct direction; VLAN frame dropped in allowlist mode; metadata IP blockable), and `make bench-docker` shows warm connected-path overhead still ~noise.

Testing plan:
- New cgroup test: `net.ListenPacket` + `WriteTo` (no connect) to a disallowed IP must fail/drop in allowlist and block-all modes; connected path still allowed when allowlisted.
- New TC e2e: veth pair + netns, client in netns, attach on host peer with new direction; assert allowed IP works, disallowed blocked, and established connection severed on rule removal (README claim, currently untested — `e2e_test.go:90` "TC on dummy interface can't test real traffic").
- VLAN bypass test via `ip link add link ... type vlan` in netns.
- Re-run `make bench-docker`; record numbers in README.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 1A: `sendmsg4`/`sendmsg6` hooks in cgroup filter | Commit `e82d345`: shared `filter_dst4/6` helpers + sendmsg hooks over same maps; `TestCgroupUnconnectedUDP` (neg-verified against HEAD). |
| Complete | Work | 1B: `direction` field on `AttachRequest` (EGRESS default, INGRESS for host-side veth/tap peers) + docs | Commit `6d8ca58`: `TcDirection` on AttachRequest/Subscribed/Attachment/AttachmentInfo, `NewTCFilter` ingress/egress, persisted via store column, `TestTCVethDirection` (first real TC traffic test, built-in negative verification). |
| Complete | Work | 1C: `skb->protocol` parsing, VLAN handling, default-deny unknown ethertypes (ARP allowed) | Commit `47c751b`: `bpf_skb_load_bytes_relative(BPF_HDR_START_NET)` + bounded 802.1Q/QinQ walk, fail-closed in allowlist; `TestTCVethVlanAllowlist` (QinQ neg-verified); ARP allowance traffic-pinned via post-attach neigh flush (neg-verified). |
| Complete | Work | 1D: carve-out flags; disable v4 link-local always-allow by default; add `ff02::/16` for TC | Commit `1bc85b7`: `volatile const carveout_flags` (zero per-packet cost), LinkLocalV4 OFF by default; `TestCgroupMetadataServiceBlockable` + `TestTCVethMetadataBlockable` (flag-flip proves const rewrite reaches program, neg-verified); README security note. |
| Complete | Test | Veth-pair TC e2e incl. connection-severing assertion | Commits `6d8ca58`/`47c751b`: `tc_veth_test.go` netns+veth harness; severing proven on a UDP flow (per-packet, no conntrack — TCP data stops rather than RST, documented). |
| Complete | Gate | All four bypass tests pass in Docker gate; warm-path bench unchanged | `make test-docker`/`-cgroup`/`-tc` green at each commit; `make bench-docker` warm connected path within noise (deltas -143/+104/+42 ns across runs, inside baseline spread). |
| Complete | Doc | Raw-socket limitation + direction guidance in README | Direction table (`6d8ca58`), security note (`1bc85b7`), raw-socket/cgroup limitation note (this commit). |

## Phase 2: Rule lifecycle correctness (TTLs, bulk updates, capacity)

Goal:
Rules expire when they say they will, full resyncs never open transient allow/block windows, and the filter degrades loudly (not silently) at capacity.

Scope:
- 2A — Implement CIDR TTLs: `CIDREntry.ttl` (control.proto:208-211) and README's "optional TTLs" are accepted and silently ignored (`controlplane.go` AllowCidr/DenyCidr/applySubscribedAck/applyBulkUpdate never read `entry.Ttl`). Track expirations per attachment in the daemon and remove entries via a janitor goroutine.
- 2B — Expire DNS-populated IPs: `dns.go addIPToFilter` inserts /32s forever (TTL only gates the local `ipCache`), so long-lived attachments accumulate entries until the 4096-entry LPM map fills and `AllowIP` fails — after which resolved domains stop being connectable. Reuse the 2A janitor keyed by the DNS TTL (with a configurable floor), evict expired `ipCache` entries (currently unbounded), and surface map-full errors as a counter/log + heartbeat stat. Make `max_entries` load-time configurable via the bpf2go spec.
- 2C — BulkUpdate without windows: `applyBulkUpdate` (controlplane.go:460-498) does ClearRules-then-rebuild, so every CP resync briefly blocks all allowed traffic in allowlist mode (and allows all denied traffic in denylist mode), and permanently drops DNS-populated IPs that clients still hold in resolver caches (blocked until the client re-resolves). Compute the diff against current state and apply add/remove deltas; preserve unexpired DNS-populated entries.
- 2D — Command outcome reporting: bulk/CIDR command failures are logged locally and the CP is never told (e.g. `parseBulkCIDRs` aborts the whole update silently). Add a command-ack/error DaemonEvent so the CP can converge on truth.

Out of scope:
- Persisting rules in the daemon store (the CP remains the source of truth; Phase 3 pinning keeps kernel state across restarts instead).

Completion gate:
TTL'd CIDR and DNS-added IP demonstrably expire in a Docker-gate test; a bulk update replacing N rules with N-1 of them never blocks the surviving rule's traffic (loop test); map-full produces a visible error stat, not silent drop of new allows.

Testing plan:
- Unit: janitor expiry with fake clock; diff-apply produces minimal add/remove sets; ipCache eviction.
- Integration: allowlisted UDP flow stays up across 100 BulkUpdates containing its CIDR; TTL'd entry blocks after expiry; map filled to capacity surfaces stat and recovers after expiry.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 2A: TTL registry + janitor; honor `CIDREntry.ttl` everywhere it arrives | Commit `2bf56a6`: per-attachment ttlRegistry + daemon-wide janitor; TTL wired at all four entry points; leaf-lock makes re-add/expiry atomic; fake-clock unit tests + -race concurrency test. |
| Complete | Work | 2B: DNS-entry expiry, ipCache eviction, map-full stat, configurable max_entries | Commit `22e81aa`: DNSFilterSink routes DNS IPs through the registry; ipCache deleted (inFilter dedup); max-deadline/permanent-pin aliasing; `AttachmentStats.map_full_drops`; `filter.max_rule_entries`; real-ENOSPC + traffic-expiry Docker tests. |
| Complete | Work | 2C: diff-apply BulkUpdate preserving unexpired DNS entries | Commit `165e89b`: two-source (CP/DNS) registry; reconcile with deltas (survivors never removed); window-free mode ordering (reconcile new-mode list → SetMode → other list, closing the allowlist→denylist fail-open); 80-bulk traffic test + ordered-call-log test, both neg-verified. |
| Complete | Work | 2D: command ack/error event in proto + daemon + README CP contract | Commit `c7d59d8`: opt-in `ControlCommand.command_id` + `CommandResult` DaemonEvent; handleCommand reports true outcomes (partial-bulk = failure); best-effort non-blocking; unit + e2e tests. |
| Complete | Gate | Expiry, no-window, and capacity tests green in Docker gate | `TestDaemonCIDRTTLExpiryTraffic`, `TestBulkUpdateNoTransientWindowTraffic`, `TestDaemonMapFullSurfacedAndRecovers` all green under `make test-docker` + `make check-docker` (-race). |

## Phase 3: Daemon lifecycle, state, and watcher resilience

Goal:
A daemon restart or crash does not silently drop enforcement or corrupt bookkeeping; watchers cannot die silently or spin.

Scope:
- 3A — Pin BPF state to bpffs: today every link/map dies with the process (TCX links + cgroup links are fd-based), so every crash/upgrade is a fail-open window and all rules are lost until CP resync; restore (`server.go Start`) recreates empty filters in the persisted *mode*, which in allowlist mode means block-everything until resync. Pin links + maps under `/sys/fs/bpf/netfence/<attachment-id>/`, restore from pins on start, and make shutdown behavior an explicit config (`detach_on_stop: true|false`, default keep-enforcing). This is the highest-leverage architecture change: zero-downtime upgrades and kernel-held enforcement while the daemon is down.
- 3B — Stable daemon identity: `NewServer` (server.go:52-57) assigns a random UUID per boot when `data_dir` is empty and `netfenced-<hostname>` otherwise — the proto promises "stable across restarts" (control.proto:48-49) and hostname coupling collides for two daemons on one host. Persist a generated UUID in the store/data dir; fall back to ephemeral only for `:memory:`.
- 3C — Store correctness: (a) default `DBPath()` is `:memory:` and mattn/go-sqlite3 gives each pooled connection its own empty DB → intermittent "no such table" under concurrent gRPC calls; set `SetMaxOpenConns(1)` (also removes SQLITE_BUSY) or use shared-cache memory DSN. (b) `attached_at` is stored as RFC3339Nano text whose trailing-zero trimming breaks lexical ordering (whole-second values sort after fractional ones) → pagination can skip/duplicate; store fixed-width or UnixNano. (c) Fold `scanAttachment`/`scanAttachmentRows` onto the already-declared-but-unused `scanner` interface (store.go:203).
- 3D — Watcher resilience: netlink v1.3.1 `defer close(ch)`-es the updates channel on receive error (e.g. ENOBUFS under veth churn), and `watchInterfaces` (watcher.go:137) ignores channel closure → infinite hot loop plus permanent loss of removal detection. Receive with `, ok`, resubscribe with backoff, use a buffered channel, and run `onRemoved` off the event loop (it currently does eBPF close + store delete + CP send inline). Also replace the one-fsnotify-watcher-per-cgroup design (watcher.go:86-102) with a single shared watcher — the kernel's default 128 inotify instances/user caps attachments today.
- 3E — Attach flow hygiene: the rollback ladder in `Attach` (server.go:310-396) is four hand-rolled copies of cleanup with different orderings, store-save happens before the filter exists, and a Detach racing `SubscribeAndWait` can let Attach return success for a removed attachment. Restructure as staged setup with one deferred-rollback path and a final commit under lock; verify port-pool restore hygiene while there.

Out of scope:
- Multi-daemon HA / leader election.

Completion gate:
Kill -9 and restart the daemon mid-traffic in the Docker gate with pinning enabled: enforcement holds during downtime (blocked stays blocked, allowed stays allowed) and restored attachments carry their rules; watcher survives a forced netlink error without CPU spin; >200 cgroup attachments watchable.

Testing plan:
- Integration: pin/restore round-trip (attach → kill daemon → verify block persists → restart → verify state re-adopted, single attachment not duplicated).
- Unit: netlink-closed-channel resubscribe; attach rollback invariants (no leaked port/store row/filter on each failure injection point); store pagination across whole-second timestamps; concurrent store ops with `:memory:`.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 3A: bpffs pinning + restore-from-pins + `detach_on_stop` config | Links + maps pinned under `<bpf_pin_dir>/<id>/`; `LoadPinned{Cgroup,TC}Filter` re-adopt (no re-attach, no transient window, `GetMode` read not replayed); `Filter.Detach()` (unpin+detach) vs `Close()` (keep-enforcing). Restore validates the adopted link's identity (`Info().Cgroup().CgroupId` / `TCX().Ifindex`) against the live target and refuses defunct links (fail-closed → recreate) — closes a reviewer-found fail-open on target reincarnation. ttlRegistry reseeded from adopted maps; orphan pin dirs reaped. `ensureBPFPinRoot` mounts bpffs. Kill-9 test proves kernel-held enforcement while the daemon is dead + re-adopt with no CP; reincarnation, round-trip, reconcile, detach_on_stop tests all negative-verified. Gate green (check/test/cgroup/tc-docker), self-verified the guarantee tests RUN not skip. |
| Complete | Decision | Default fail mode on daemon stop | Decided: keep-enforcing (`detach_on_stop: false` default) — pinned BPF state holds policy across restarts/upgrades. Recorded in README (§ "Daemon restarts, crashes, and upgrades") and `config.Load` defaults. |
| Complete | Work | 3B: persisted daemon UUID | `NewServer`'s incoherent id logic (per-boot random for empty DataDir / `netfenced-<hostname>` collision otherwise) replaced by `Store.GetOrCreateDaemonID()`: additive `metadata` KV table, `INSERT OR IGNORE` + `SELECT` (race-safe via PK, pre-existing id never overwritten), error propagated. `:memory:` gives an ephemeral id for free. 6 tests (stable across reopen, distinct per data dir, idempotent single-row, `:memory:`, old-schema migration, daemon restart identity), negative-verified against the pre-fix `netfenced-<hostname>` collision. Docker gate green. |
| Complete | Work | 3C: `:memory:` pooling fix, fixed-width timestamps, scanner dedupe | `SetMaxOpenConns(1)` for `:memory:` path (store.go), canonical fixed-width `attachedAtLayout` + idempotent `migrateAttachedAtFormat` + token canonicalization, `scanAttachment(scanner)` folds both scanners. Tests `TestMemoryStoreConcurrentOps` (negative-verified: "no such table" without the cap) and `TestListAttachmentsOrdersMixedPrecisionTimestamps` (negative-verified: out-of-order pre-fix), plus round-trip, migration idempotency, unparseable-row survival, legacy-token resume. Docker gate green (`make check-docker`, `make test-docker`). |
| Complete | Work | 3D: netlink resubscribe + async onRemoved + shared fsnotify watcher | `watcher.go` rewritten: netlink receives with `, ok` + capped-exponential resubscribe (100ms–5s, reset after 30s healthy) + post-resubscribe `reconcileInterfaces` (LinkList) closing the gap; `onRemoved` moved off the event loop to 4 deduped workers (delete-from-set at dispatch = dedupe); single shared fsnotify watcher with `dirRefs` parent-dir refcounting (225 cgroups on ONE inotify instance). Test seam: `subscribeLinks`/`listLinks` func fields (prod defaults). 6 negative-verified tests in `watcher_test.go` (resubscribe, backoff-bounded, reconcile-gap, off-loop+dedupe, shared-watcher scale, Stop idempotent). Docker gate green + `-race -count=5` flake smoke clean. |
| Complete | Work | 3D-follow: generation-safe removal across same-name/path re-attachment | Exact `watchToken` (generation + kind + target + kernel identity) now scopes watcher maps, queued callbacks, unwatch, and `handleTargetRemoved`; stale callbacks/unwatches cannot claim a newer attachment. Filter construction and watch registration are bracketed by ifindex/cgroup-ID validation, and a final registration mismatch fails `Attach` synchronously with exactly-once rollback. Deterministic blocked-callback and final-registration-race tests negative-verify the prior fail-open/success race. |
| Complete | Work | 3D-follow: identity-aware reconcile and cgroup registration/event reincarnation handling | Interface DELLINK/reconcile matches name + ifindex, so delete/recreate-same-name is removal of the old attachment. Cgroup registration and established fsnotify removal paths compare cgroup ID/inode, catching disappearance and same-path recreation even when no usable event exists. Deterministic pre-watch and delayed-event tests cover both gaps. Host daemon tests, independent Linux `-race -count=3`, focused `-race -count=10`, and full `make check-docker` equivalent gate green; skeptical reviewer approved. |
| Complete | Work | 3E: single-path attach rollback; Detach vs in-flight-subscribe race | `Attach` restructured into staged setup (port→filter→DNS→store→register→watch→subscribe→commit) with ONE deferred rollback; `cleanupAttachment` deleted. Store row now saved after filter+DNS exist. Race fixed: after `SubscribeAndWait`, re-check the exact registered `*attachmentState` under `s.mu`; if a racing Detach/target-removal removed it, return error, never success. Pointer-identity ownership check guarantees exactly-once teardown. Port-pool restore bug fixed (out-of-range persisted ports no longer pool keys). 8 deterministic tests in `attach_test.go` (race + 4 failure injections + rollback), all negative-verified (unfixed Attach returns success → fail; sabotaged ownership check → double-close). Docker gate green. |
| Complete | Gate | Kill-9 restart holds enforcement; watcher chaos test green | Kill-9 restart: `TestCgroupKill9KeepsEnforcing` (traffic blocked while daemon dead, re-adopted with no CP) + `TestCgroupKill9RecreatedTargetNotAdopted`. Watcher: `TestWatcher*` incl. resubscribe/backoff/shared-watcher scale under `-race -count=5`. All green in the Docker gate. |

## Phase 4: Control-plane channel security and robustness

Goal:
The rule-push channel — which decides what traffic every workload may send — is authenticated, encrypted, and detects dead peers quickly.

Scope:
- 4A — TLS/mTLS/token auth: `controlplane.go:98` hardcodes `insecure.NewCredentials()` and config has no TLS block; anyone who can MITM the CP URL can push ALLOW rules. Add `control_plane.tls` (ca/cert/key/server-name) and optional bearer-token metadata; keep plaintext only as an explicit `insecure: true` opt-in.
- 4B — Keepalive + backoff: no gRPC keepalive params, so a silently dead TCP path leaves state CONNECTED (DNS-proxy queries then eat 5s timeouts each) until kernel timeouts; reconnect is a fixed 5s loop (`Run`, controlplane.go:77-92). Add client keepalive, and exponential backoff with jitter.
- 4C — Reconnect/queue semantics: events queued in `sendCh` survive a reconnect and are sent after the fresh `SyncRequest` (duplicate/ stale Subscribed/Unsubscribed interleavings); document the CP idempotency contract in control.proto and README, and drop stale queued events on reconnect (Sync supersedes them).
- 4D — Re-sync on restore (restart convergence): after 3A re-adopts pinned rules, the ttlRegistry is reseeded as CP-permanent (TTL deadlines aren't persisted), so an incremental-only control plane never removes rules the workload resolved pre-restart — they persist until some `BulkUpdate` arrives (bounded over-allow, README-documented). Decision (user, 2026-07-18): re-drive the `Subscribed`→`SubscribedAck` handshake for each restored attachment on start so the CP always pushes full desired state, which delta-reconciles away stale rules (no transient block — keep-enforcing until the ack lands). Works for all control planes.

Out of scope:
- CP-side reference implementation beyond the test control plane.

Completion gate:
Daemon connects with mTLS in an integration test; plaintext requires the explicit opt-in flag; a blackholed CP connection is detected and re-established within keepalive+backoff bounds in a test.

Testing plan:
- Integration: mTLS handshake against test CP with generated certs; `insecure: true` path; keepalive detection with iptables-dropped traffic in the Docker gate.
- Unit: backoff schedule; queued-event drop-on-reconnect.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Complete | Work | 4A: TLS/mTLS/token config + wiring | `control_plane.tls` (ca/cert/key/server_name, path or inline PEM), `insecure`, `auth_token`. `BuildControlPlaneCreds` (built once at startup) → TLS (MinVersion 1.2, CA pool or system roots, mTLS client cert when cert+key present) / explicit insecure / fail-closed default; bearer token via PerRPCCredentials with `RequireTransportSecurity()==!insecure`. `config.Validate` fails closed: URL without tls/insecure → error. `connect()` refuses to dial without transport creds (no plaintext fallback). 5 integration tests (mTLS + token, untrusted-CA/wrong-SNI/plaintext-CP rejection, insecure opt-in) + creds/config unit tests; negative-verified (plaintext-CP discriminator + validation fail against pre-4A). Hardening: key material never echoed in cert-read errors; warn on insecure+token. Docker gate green. |
| Incomplete | Risk | Local daemon API (unix socket) still uses insecure creds | Reviewer 4A MINOR-4: `cmd/netfenced/cmd/attach.go` dials the local `unix://` admin socket with `insecure.NewCredentials()`. Filesystem perms are the boundary for a local socket, so likely fine — but decide explicitly under Phase 6 (local API/CLI). |
| Complete | Work | 4B: gRPC keepalive + jittered exponential backoff | `connect()` adds `WithKeepaliveParams{Time,Timeout,PermitWithoutStream:true}` (defaults 30s/10s); `Run()`'s fixed 5s reconnect replaced by `reconnectBackoff` (floor 1s → double → cap `reconnect_backoff_max` default 30s, ±20% jitter, reset-to-floor only after ≥30s healthy, ctx-interruptible). Config `keepalive_time`/`keepalive_timeout`/`reconnect_backoff_max` (0=default). `TestControlPlane_KeepaliveDetectsDeadPeer` via a `stallableProxy` silent blackhole: detects in 12s (10s grpc ping-clamp + 2s timeout); negative-verified (stays CONNECTED past 30s pre-4B, which also proves the blackhole is truly silent). 6 backoff unit tests. README documents the knobs + the CP-side `KeepaliveEnforcementPolicy` requirement. Docker gate green (`make check-docker`). Reviewer subagent died mid-gate; coordinator self-reviewed the diff + ran the gate. |
| Complete | Work | 4C: reconnect queue semantics + documented CP idempotency contract | Per-connection epoch (`sendEpoch atomic.Uint64`) stamped by a new `enqueue()` (all 4 producers); `connect()` bumps it before the Sync snapshot; `sendLoop` drops older-epoch events (superseded by the fresh `SyncRequest`) EXCEPT a still-pending `Subscribed` (so a `SubscribeAndWait` blocked across a reconnect still gets its ack). No drain step → no producer/deadlock race. Idempotency contract documented in `control.proto` (Sync/Subscribed/Unsubscribed comments, regenerated pb.go — comments only, no schema change) + README. 3 loopback-gRPC tests (exact-sequence purge, subscribe-across-reconnect, full-backlog no-deadlock), negative-verified (stale Heartbeat/Unsubscribed/CommandResult replayed pre-4C). Coordinator-reviewed the diff + full `check-docker` green. |
| Incomplete | Work | 4D: re-sync (re-drive Subscribed→SubscribedAck) on restore for restart convergence | NOT STARTED (implementer stopped mid-investigation 2026-07-18; working tree clean at 4C). Decided (user, 2026-07-18) as the fix for the 3A reseed-permanent over-allow. Design: mark every attachment restored in `Start()` (adopted-from-pins AND recreate-empty fallback) `needsResync`; when the CP stream is up, re-drive `Subscribed→SubscribedAck` per flagged attachment (off `connect()`'s main select, contract-safe per 4C idempotency), clear the flag only on a successful ack (fail-static otherwise). KEY IMPLEMENTATION NOTE: `applySubscribedAck` (controlplane.go:610) applies rules ADDITIVELY (AllowCIDR/DenyCIDR) — a restore-resync must route through the reconcile path (`applyBulkUpdate`→`ReconcileCIDRs`) so stale adopted rules are actually REMOVED, not just re-added. Missing: implementation + test that a post-restart re-sync removes stale adopted rules while never transiently blocking a surviving one (+ recreate-empty→converges, + no CP → rules persist). |
| Incomplete | Gate | mTLS + dead-peer tests green (+ full phase pending 4D) | mTLS: `TestControlPlane_MTLS` + rejection tests green (4A). Dead-peer: `TestControlPlane_KeepaliveDetectsDeadPeer` green (4B). Reconnect purge: 3 tests green (4C). Remaining: 4D restart-convergence test. Phase closes when 4D lands. |

## Phase 5: DNS server completeness

Goal:
The per-attachment DNS server behaves like a real resolver for filtered workloads: reachable from them, correct over TCP, honoring the per-attachment configuration the proto already promises, and remaining policy-correct under bounded rule-map pressure.

Scope:
- 5A — Bootstrap reachability: in IP-allowlist mode nothing guarantees the DNS server's own address is connectable (`config.go` default listen `127.0.0.1` is unreachable from a container netns; the DNS IP:port isn't auto-allowed in the eBPF map, and cgroup mode has no port granularity). Auto-allow the per-attachment DNS address at attach time and document listen-address requirements for container topologies (README's `10.0.0.1:53` example vs actual default).
- 5B — TCP + truncation: server is UDP-only (`dns.go Start` uses `ListenPacket`) and the upstream client never retries truncated answers over TCP, so large responses (DNSSEC, many records) dead-end. Serve TCP on the same address; on upstream TC-bit, retry with `net: "tcp"`.
- 5C — Per-attachment upstreams: `DnsConfig.upstream_servers` (control.proto:202-204) is accepted and ignored — plumb it through `ReplaceRules` and use it (fallback to global default).
- 5D — Modern record types: decide and implement HTTPS/SVCB handling (answers carry ipv4hint/ipv6hint addresses that never enter the filter → hinted connects get blocked in allowlist mode); simplest correct default: strip HTTPS/SVCB hint fields (or whole records) from responses in filtering modes.
- 5E — Stats semantics: SERVFAIL paths (proxy unavailable, upstream failure) currently count as "blocked" (`dns.go:231-243`) — split error counters from policy blocks so heartbeat stats mean what they say.
- 5F — Prompt domain de-allow: track domain→resolved-IP ownership so removing a domain through `ReplaceDNSRules` evicts its DNS-only addresses immediately instead of waiting for TTL expiry; preserve an address still owned by another allowed domain or an explicit control-plane CIDR.
- 5G — Source-aware bounded capacity and churn: keep authoritative control-plane CIDRs in bounded, non-evictable LPM maps and preflight oversized replacements so they are rejected atomically rather than partially applied. Put DNS-derived allow host addresses in a separately bounded exact-IP tier with configurable per-attachment entry, per-response, and per-matched-policy-domain address limits; bound the TTL/domain-ownership metadata and ownership edges by corresponding caps. Reclaim expired entries first, then LRU-evict only DNS-only allows within a configurable rolling per-attachment eviction/admission budget. Once that budget is exhausted, preserve the current working set and return SERVFAIL instead of admitting a new address; new connections to already-admitted addresses do not consume the budget. Never evict an explicit control-plane entry or any deny entry, and never return a DNS address that was not admitted to the filter. If an authoritative deny cannot be installed, put the attachment in an explicit degraded fail-closed state (`BLOCK_ALL` or equivalent) until reconciliation succeeds. Export per-map occupancy/high-water marks, DNS evictions, admission failures, budget throttles, and degraded state through logs and heartbeat stats; rate-limit repetitive pressure logs and document operator recovery and retry semantics.

Out of scope:
- DoT/DoH upstreams; DNSSEC validation.

Completion gate:
A container in the Docker gate using only its assigned DNS address completes: allowlist-mode bootstrap (no manual DNS-IP rule), a >512-byte answer via TCP fallback, and per-attachment upstream override — all verified by traffic. With deliberately tiny map capacities and a fake-clock eviction window, pressure evicts only DNS-derived allows and never exceeds the configured budget; once exhausted, the existing working set remains connectable and new DNS admissions return SERVFAIL. Explicit control-plane and deny rules survive, userspace metadata stays within its caps, and deny admission failure is visibly fail-closed and recovers after reconciliation.

Testing plan:
- Integration: allowlist-mode container resolves+connects with zero manual DNS-address rules; truncated-answer domain resolves via TCP; two attachments with different upstreams resolve differently.
- Unit: TC-bit retry, upstream selection, stats split, SVCB stripping.
- Unit: deterministic expired-first/LRU selection with a fake-clock rolling budget, per-response/per-policy-domain limits, bounded TTL/ownership metadata, protected CP/deny entries, atomic capacity preflight, DNS answer admission, degraded-state entry/recovery, and domain ownership/refcount eviction.
- Integration: force tiny capacities and a small eviction budget in cgroup and TC modes; prove DNS-only allows can displace only eligible DNS entries up to the budget, further unique answers get SERVFAIL without disturbing the working set, admission resumes after expiry/window recovery, explicit rules survive, and deny pressure blocks rather than fails open.
- Benchmark: because the separate DNS exact-IP tier changes BPF lookups, run `make bench-docker`; connected-socket overhead remains ~noise and DNS query performance remains within the project threshold.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | 5A: auto-allow DNS address per attachment + topology docs | Missing: implementation + bootstrap test. |
| Incomplete | Work | 5B: TCP listener + upstream TCP fallback | Missing: implementation + truncation test. |
| Incomplete | Work | 5C: honor `DnsConfig.upstream_servers` | Missing: plumbing (currently ignored proto field). |
| Incomplete | Work | 5D: HTTPS/SVCB hint policy | Missing: decision + implementation. |
| Incomplete | Work | 5E: split error vs blocked counters | Missing: implementation. |
| Incomplete | Work | 5F: evict a domain's resolved IPs promptly when it is de-allowed (ReplaceDNSRules / domain removal) | Deferred from Phase 2 (2B reviewer F4): today a removed domain's IPs age out by TTL rather than being evicted — strictly better than pre-2B (never expired), but prompt eviction needs a domain→IPs reverse index. Missing: reverse index + eviction + test. |
| Incomplete | Work | 5G: source-aware bounded DNS admission/eviction + atomic CP admission + fail-closed deny pressure | Missing: separate exact-IP DNS allow tier, entry/domain/response/metadata caps, rolling eviction budget, working-set preservation with SERVFAIL throttling, protected authoritative/deny entries, atomic preflight, degraded-state recovery, occupancy/eviction/throttle stats, and README/proto contract. |
| Incomplete | Test | Capacity-and-churn traffic tests and BPF/DNS benchmarks | Missing: tiny-capacity cgroup+TC tests proving eviction stops at the configured budget, metadata stays bounded, the working set survives throttling, DNS never returns uninstalled IPs, deny failure blocks, expiry/window recovery converges, and `make bench-docker` stays within thresholds. |
| Incomplete | Gate | Bootstrap/TCP/upstream/capacity tests green in Docker gate | Missing: tests. |

## Phase 6: Local API and CLI completeness

Goal:
The daemon is usable and inspectable without a control plane, and the local API can express everything the CP protocol can.

Scope:
- 6A — Local rule management: `DaemonService` has only Attach/Detach/List/GetStatus — with no CP configured an attachment is stuck in DISABLED forever and rules can't be inspected. Add SetMode/AllowCIDR/DenyCIDR/RemoveCIDR/DNS-rule RPCs (mirroring ControlCommand semantics) plus a GetRules/inspect RPC, and `netfenced rules <id>` / `netfenced set-mode` CLI.
- 6B — API warts: `remove_cidr` removes from both allow and deny lists with no way to target one (control.proto:140-141) — add an optional list selector; document equal-specificity deny-wins for domain rules (dns.go `evaluateDomainLocked`).
- 6C — Socket hardening note: document the 0660 unix-socket trust boundary (whoever reaches it controls host eBPF) and make the group configurable.

Completion gate:
`netfenced attach` → `set-mode allowlist` → `allow-cidr` → traffic verified, all with no control plane configured; rules inspectable via CLI.

Testing plan:
- Integration: standalone (no-CP) lifecycle test driving only the local API; CLI smoke tests in the Docker gate.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | 6A: rule-management + inspect RPCs and CLI | Missing: proto, server, CLI, standalone e2e. |
| Incomplete | Work | 6B: remove-cidr selector; domain-precedence docs | Missing: proto field + README. |
| Incomplete | Work | 6C: configurable socket group + trust-boundary doc | Missing: config + doc. |
| Incomplete | Gate | Standalone no-CP lifecycle test green | Missing: test. |

## Phase 7: Simplification and dead-weight removal

Goal:
One source of truth for enforcement logic and zero unused code, with no behavior change (guarded by the existing Docker gate staying green).

Scope:
- 7A — Go filter dedup: `TCFilter` and `CgroupFilter` duplicate ~200 lines of identical map logic (AllowIP/DenyIP/Remove*/ClearRules/GetStats/SetMode/GetMode differ only in the objects struct) — extract a shared rule-maps core; filters keep only attach/close.
- 7B — BPF dedup: `filter_tc.c` and `filter_cgroup.c` duplicate map definitions, LPM keys, carve-out helpers, and verdict logic — extract `bpf/filter_common.h` (Phase 1 changes land first so the shared logic is the fixed version).
- 7C — Dead code: delete unused `pkg/gologger` (its `init()` mutates global zerolog state if ever imported), `GetCgroupPath`, `FindCgroupByPID`, `TCFilter.InterfaceName`, `CgroupFilter.CgroupPath`; rename misleading `pkg/filter/main.go` (library file, not a main).
- 7D — Endianness robustness: cgroup BPF localhost/link-local checks are little-endian-only (`filter_cgroup.c:90-107` vs the TC program's `bpf_ntohl` versions), and Go key marshaling relies on a LittleEndian trick (`main.go:32-56`) — normalize BPF helpers to byte-order-safe forms and switch LPM key `Addr` to `[4]byte`/`[16]byte`.
- 7E — `handleDNS` lock structure: the per-branch RLock/RUnlock dance (dns.go:198-260) makes every new mode a leak hazard — compute the decision in one locked helper, act unlocked.
- 7F — Config knobs: heartbeat interval (30s) and reconnect backoff base (5s) hardcoded; DNS `allocatePort` can't skip externally-occupied ports (bind-test on allocate). Fold in while touching the files.

Completion gate:
`make check-docker` and full `make test-docker` green with a net-negative diff (target ≥400 lines removed); `make bench-docker` unchanged.

Testing plan:
- Existing Docker-gate suites are the regression harness; no new behavior to test beyond bind-test unit coverage.

Status ledger:

| Status | Type | Item | Evidence / Gap |
| --- | --- | --- | --- |
| Incomplete | Work | 7A: shared Go rule-maps core | Missing: refactor; gate green. |
| Incomplete | Work | 7B: `filter_common.h` extraction | Missing: refactor after Phase 1; gate green. |
| Incomplete | Work | 7C: delete gologger + unused helpers; rename main.go | Missing: deletions (verified unused via grep 2026-07-17). |
| Incomplete | Work | 7D: endian-safe BPF helpers + byte-array LPM keys | Missing: refactor + bpfeb build check. |
| Incomplete | Work | 7E: handleDNS single-lock decision helper | Missing: refactor. |
| Incomplete | Work | 7F: heartbeat/backoff knobs; port bind-test | Missing: implementation. |
| Incomplete | Gate | Net-negative diff with full gate + bench green | Missing: final run. |
