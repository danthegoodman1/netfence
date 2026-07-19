# Netfence

_Like Envoy xDS, but for eBPF filters._

Netfence runs as a daemon on your VM/container hosts and automatically injects eBPF filter programs into cgroups and network interfaces, with a built-in DNS server that resolves allowed domains and populates the IP allowlist.

Netfence daemons can be driven through their local Unix-socket API alone, or
connect to a central control plane that you implement via gRPC to synchronize
allowlists/denylists with your backend.

Your control plane pushes network rules like `ALLOW *.pypi.org` or `ALLOW 10.0.0.0/16` to attached interfaces/cgroups. When a VM/container queries DNS, Netfence resolves it, adds the IPs to the eBPF filter, and drops traffic to unknown IPs before it leaves the host with warmed-path overhead that is effectively indistinguishable from a normal socket connect in current benchmarks.

## Features

- Attach eBPF filters to network interfaces (TC) or cgroups
- Policy modes: disabled, allowlist, denylist, block-all
- IPv4 and IPv6 CIDR support with optional TTLs
- Per-attachment UDP/TCP DNS server with domain allowlist/denylist and ordered upstream overrides
- Domain rules support subdomains with specificity-based matching (more specific rules win)
- Resolved domains auto-populate IP filter
- Metadata on daemons and attachments for associating with VM ID, tenant, etc.
- Support for proxying DNS queries to the control plane to make DNS decisions per-attachment

### Security note: default carve-outs

In allowlist mode, IPv4 link-local (169.254.0.0/16) is **no longer auto-allowed
by default** — so the cloud metadata service (169.254.169.254) is blocked unless
explicitly allowlisted. This is deliberate: the metadata service is a
credential-theft target, and sandboxed workloads must not be able to reach it
implicitly. Localhost (127.0.0.0/8, ::1) and IPv6 neighbor discovery
(fe80::/10, ff02::/16) remain allowed by default so basic connectivity and NDP
keep working. To permit the metadata service for a workload, allowlist
`169.254.169.254/32` (a per-attachment carve-out override via the control plane
is a planned follow-up).

IPv4 broadcast (255.255.255.255) and multicast (224.0.0.0/4) have no carve-out
and are subject to policy, so under TC allowlist mode traffic like DHCP-renewal
broadcasts is blocked unless explicitly allowlisted. Carve-out checks run before
the denylist, so a carved range can only be blocked by turning its carve-out off
— and because IPv4 link-local is now off by default, denylist mode can block the
metadata service too.

## Differences from other options

A few major benefits to this solution that other options don't usually support:

- Immediate severing of existing connections when rules change to disallow an IP (interface attach only)
- Support all network protocols, and direct to IP networking. For example, the awesome [httpjail](https://github.com/coder/httpjail) doesn't allow you to connect direct to IPs, or direct TCP/UDP connections like connecting to databases.
- Dynamic resolving of DNS and pre-resolution filtering (so there's no `secretdata.someattacker.com` exfiltration)

To my knowledge, no other solutions offers all of these features together.

Known limitation: cgroup attachments filter at the socket layer (`connect`/`sendmsg`
hooks), so a process with `CAP_NET_RAW` can craft raw packets that bypass them. Use
a TC (interface) attachment, which filters at the device layer, for workloads that
may hold `CAP_NET_RAW`.

However, this does have a bit more overhead than something like [httpjail](https://github.com/coder/httpjail).

## Performance snapshot

These numbers were measured in the privileged Docker Linux gate on `linux/arm64`
using `make bench-docker`. Values are medians of five samples.

### Warm socket path

The warm socket benchmark uses connected UDP sockets to isolate the
`cgroup/connect4` eBPF hook cost from TCP handshake latency. In this path DNS has
already resolved the domain, the IP is still within TTL, and the IP/CIDR is
already present in the eBPF map.

| Path | Median latency |
| --- | ---: |
| Normal socket connect, no eBPF | ~2.647 us |
| Warm allowlist, protected LPM hit | ~2.691 us |
| Warm allowlist, DNS exact-host hit | ~2.741 us |
| Allowlist miss, local block | ~1.652 us |

The measured spread between the normal, protected-LPM, and DNS exact-host
connect paths is within sample noise.

There is no "kernel miss asks parent process" path today. A cgroup allowlist
miss is decided locally by eBPF and is blocked immediately.

### DNS query path

These numbers measure the DNS server path, not the warmed socket connect path.

| Path | Median latency |
| --- | ---: |
| Proxy query cold, in-process policy function | ~31.336 us |
| Proxy query warm | ~27.964 us |
| Allowlist query cold with local upstream | ~53.510 us |
| Allowlist query warm with local upstream | ~53.432 us |

Cold rows synchronize through the real attachment mutation barrier and clear
the benchmark ownership graph and fake exact-map snapshot between queries.
The timer runs continuously to preserve UDP scheduler locality, while `ns/op`
subtracts the separately reported `fixture-reset-ns/op` wall time (including
any tail of the prior handler after the client received its packet) and thus
measures the current client Exchange. `raw-total-ns/op` reports both together.
The reset preserves configured policy domains and backing storage, and the
benchmark asserts one physical exact-map add per query. Warm rows prime
ownership once and assert one physical add across the run.

The internal ownership microbenchmarks below are scalability diagnostics, not
end-to-end DNS query-path acceptance rows. The cached helper is retained only
for tests and benchmarks; it wraps one record at a time and repeats domain
validation. Both it and normal resolver traffic traverse the attachment
mutation barrier, while normal resolver traffic admits each complete response
as one transaction.

| Internal scalability diagnostic | Current median | Memory / allocations |
| --- | ---: | ---: |
| Cold new-key admission, empty ownership graph | ~370.3 ns | 232 B, 5 allocs/op |
| Cold new-key admission, 4,095 unrelated entries | ~451.2 ns | 232 B, 5 allocs/op |
| Physical-capacity pressure and LRU replacement | ~3.820 ms | ~4.23 MB (4,226,243 B), 4,336 allocs/op |
| Exhausted physical-budget precheck | ~611.9 ns | 344 B, 9 allocs/op |
| Maximum-edge pressure, 64-address response | ~6.849 ms | ~7.66 MB (7,658,774 B), 2,233 allocs/op |
| Maximum-graph work guard, permitted full plan | ~2.763 ms | ~4.26 MB (4,264,386 B), 3,074 allocs/op |
| Maximum-graph work guard, exhausted pre-projection rejection | ~10.935 us | 8.76 KB (8,760 B), 14 allocs/op |
| Churn-budget operation near the numeric ceiling | ~18.98 ns | 0 B, 0 allocs/op |
| Coherent ownership-stats snapshot | ~2.094 ns | 0 B, 0 allocs/op |
| No-op expiry scan across 4,095 entries | ~74.849 us/scan | 0 B, 0 allocs/op |

# Design

## Architecture

```
+------------------+         +-------------------------+
|  Your Control    |<------->|  Daemon (per host)      |
|  Plane (gRPC)    |  stream |                         |
+------------------+         |  +-------------------+  |
                             |  | DNS Server        |  |
                             |  | (per-attachment)  |  |
                             |  +-------------------+  |
                             +-------------------------+
                                        |
                                 +------+------+
                                 |             |
                              TC Filter    Cgroup Filter
                              (veth, eth)  (containers)
```

Each attachment gets a unique DNS address (port) provisioned by the daemon. Containers/VMs must be configured to use their assigned DNS address; filtering ordinary workload DNS traffic does not transparently redirect it.

### DNS resolver topology and behavior

`dns.listen_addr` must identify one concrete IPv4 or IPv6 address that every
attached workload can reach. Wildcard addresses are rejected because they
cannot be advertised as resolver endpoints. A configured hostname is resolved
once when the daemon starts and the resulting concrete IP is used for binding,
advertising, persistence, and filter bootstrap. The default `127.0.0.1` is
appropriate only when the workload shares the daemon's network namespace; a
container or VM in another namespace normally needs a reachable host/bridge
address instead.

```yaml
dns:
  listen_addr: 10.0.0.1
  port_min: 11000
  port_max: 11500
  # Daemon-global fallback when DnsConfig.upstream_servers is empty.
  upstream: 1.1.1.1:53
  # Hard daemon ceilings for each attachment's bounded DNS exact ownership.
  # Zero/unset uses these defaults (max_ips_per_family instead derives from
  # filter.max_dns_rule_entries).
  max_ips_per_family: 4096
  max_ips_per_response: 64
  max_ips_per_policy_domain: 1024
  max_tracked_domains: 1024
  max_ownership_edges: 8192
  # Rolling physical-admission/LRU mutation budget and slow-planning work
  # allowance. The window is daemon-global and immutable until restart;
  # DnsConfig.max_churn_units may only lower the daemon ceiling.
  max_churn_units: 8192
  churn_window: 1m
```

Attach returns the concrete `dns_address`; configure that exact address as the
workload's resolver. Netfence installs a protected, non-expiring `/32` or
`/128` allow entry for the listener IP so allowlist mode can bootstrap without
a control-plane DNS-IP rule. The current filters enforce IP prefixes, not
destination ports, so that protected entry permits every port at the listener
IP (not only its DNS port); this is especially important for cgroup attachment
threat models. Use a dedicated listener IP when that broader reachability is
not acceptable.

The assigned endpoint serves both UDP and TCP. UDP replies are truncated to a
legacy client's 512-byte limit or its advertised EDNS size and carry `TC` when
needed, allowing the workload to retry the same endpoint over TCP. For upstream
resolution, a truncated UDP answer is retried over TCP against the same
upstream first. A transport failure, `SERVFAIL`, or `REFUSED` then advances to
the next configured upstream in order.

`DnsConfig.upstream_servers` overrides the daemon-global `dns.upstream` for one
attachment. Entries use `host:port` syntax (bracket IPv6 literals), are
canonicalized and de-duplicated in first-seen order, and are limited to eight
unique servers. An empty list selects the global fallback.

In filtering modes, Netfence strips `ipv4hint` and `ipv6hint` parameters from
HTTPS/SVCB answers, including their corresponding `mandatory` references,
because hinted addresses have not independently passed filter admission.
Disabled mode preserves upstream answers unchanged.

DNS query counters are mutually exclusive: `dns_queries_allowed` counts
successfully answered policy-allowed queries (including NXDOMAIN),
`dns_queries_blocked` counts policy `REFUSED` responses, and
`dns_queries_errors` counts resolver, proxy, filter-admission, response-write,
and other error paths. A query increments exactly one bucket.

Every address-bearing response in a filtering DNS mode is admitted to the
attachment's exact IPv4/IPv6 HASH tier as one transaction before any A/AAAA
address from its answer, authority, or additional sections is returned. If
the complete response cannot be represented, the resolver returns `SERVFAIL`
with no address and preserves the previously admitted working set. PROXY
decisions that return addresses must set `add_to_filter`; otherwise they also
fail closed as `SERVFAIL`. Disabled DNS mode is the explicit pass-through
exception.

Exact entries carry TTL edges from the normalized query to the matched policy
owner. Removing or denying a domain promptly removes its last DNS-only exact
addresses, while a shared address survives another live query owner and an
overlapping control-plane CIDR continues independently in the protected LPM
tier. DNS DENYLIST default-allow and explicit-allow answers are tracked too,
even while packet DENYLIST ignores exact allows, so a later packet-mode switch
to ALLOWLIST can use already-returned cached addresses without a requery.

All normal/live userspace ownership state is bounded by the five ownership
settings above. Restored synthetic provisional edges are exempt from those
logical limits so they cannot be forgotten before reconciliation, but remain
bounded by the physical IPv4/IPv6 exact maps. Configured policy domains and
live query domains share
`max_tracked_domains`, and each `(query, matched owner, IP)` TTL record consumes
one `max_ownership_edges` slot.

On pressure, admission projects expired TTL edges away first. It then reclaims
complete logical query/owner edges with the least physical collateral before
recency, followed by deterministic resolver-observed LRU (canonical IP breaks
ties). A physical eviction removes the whole DNS exact key and all of its DNS
owners. The incoming physical IP and exact incoming `(IP, query, owner)` edge
are protected for the response transaction. Restored provisional ownership
protects its physical key until authoritative reconciliation, but unrelated
normal DNS metadata sharing that key may still be reclaimed. Authoritative
control-plane/system allows and every deny remain in separate LPM tiers and
are never candidates for DNS reclamation.

The rolling per-attachment churn budget charges one unit for a new physical
exact key and one for each live physical DNS key evicted; a full old-to-new
replacement therefore costs two. Refreshes, logical-only reclamation, expiry,
and policy removal cost zero. Events remain active while their age is less than
`dns.churn_window` and expire at the exact boundary. `DnsConfig.max_churn_units`
may only lower the daemon ceiling; zero inherits it. The window cannot be
changed by the control plane, and changing the daemon ceiling/window requires
a restart. Lowering and later raising an attachment limit does not forget
still-active history.

A separate rolling work ledger bounds expensive ownership-graph planning. Fast
refreshes and ordinary admissions never touch it. Before a pressure path clones
or analyzes the graph, Netfence charges stable work units derived from current
physical keys, ownership edges, tracked domains, and response size relative to
their immutable daemon/map ceilings. That attempt charge is retained even when
the plan proves impossible or a later exact-map transaction fails, closing the
zero-mutation retry path for CPU/allocation pressure without changing the
transactional physical-churn accounting above. At the default ceilings, the
allowance admits eight maximum-equivalent graph passes per window; lowering
`DnsConfig.max_churn_units` retains at least one. Lowering and later raising the
limit never rescales or forgets active work history.

When no eligible DNS state can satisfy a bound, or either rolling allowance is
exhausted, Netfence preserves the admitted working set and returns `SERVFAIL`
without returning the unadmitted address. Capacity failures increment
`map_full_drops`; physical-churn and planning-work throttles do not. Heartbeats
expose exact-map current, capacity, and process-generation high-water values
plus cumulative DNS LRU evictions, all admission failures, and an aggregate
budget-throttle count covering both rolling guards. Capacity, physical-budget,
and work-budget pressure/recovery logs are rate-limited independently.
Operators can wait for TTL/window recovery, reduce response/domain churn or
repeated cap-pressure attempts, or raise `DnsConfig.max_churn_units` up to the
daemon `dns.max_churn_units` ceiling. Raising the daemon ceiling requires a
restart; increasing `filter.max_dns_rule_entries` also requires recreating the
attachment because pinned maps cannot be resized in place.

### Protected CIDR capacity and fail-closed recovery

Authoritative control-plane CIDRs and daemon-system rules use four independent,
non-evictable LPM maps: allow/deny × IPv4/IPv6. Each map has
`filter.max_rule_entries` slots. The DNS listener `/32` or `/128` bootstrap is a
system allow and counts against the corresponding protected allow map. DNS
exact-host entries remain in their separate maps and cannot consume these
slots. No protected rule is ever LRU-evicted: explicit allows, system rules,
and every deny remain until an authorized removal or complete replacement.

A complete `SubscribedAck` or `BulkUpdate` is canonicalized and its final
occupancy is checked for all four maps before mutation. Capacity is based on the
final state, so replacing keys in a full map is valid; oversized state is
rejected without evicting or partially accepting rules. Survivors are not
removed and re-added. If a later map syscall fails, Netfence restores and
verifies the exact pre-call four-map inventory. The proven mode after rollback
is the old mode or `BLOCK_ALL` (normally `BLOCK_ALL`), so the daemon still holds
the attachment fail closed until a complete authoritative retry succeeds.

Protected-policy safety state is persisted with the attachment and exported in
heartbeats. `BLOCK_ALL` by itself is a normal, healthy configured mode:
`policy_degraded` is false when `policy_degraded_reason` is empty. A risky
protected mutation that starts while healthy `BLOCK_ALL` first journals
`protected_policy_mutation_in_progress`. This is a transient crash journal, not
a stable failure diagnosis: the live operation may publish its intended mode
before the final journal-clear save, and successful completion clears the
journal itself. If startup finds it after a crash, startup first forces and
proves `BLOCK_ALL`, then persists
`protected_policy_mutation_interrupted`. Stable degraded reason codes are:

- `protected_policy_mutation_interrupted`
- `authoritative_protected_policy_failed`
- `incremental_deny_install_failed`
- `incremental_allow_removal_failed`
- `incremental_mode_change_failed`

These are stable classifications, never raw syscall/store text. The
in-progress journal is an internal persisted crash boundary; heartbeat stats
serialize with the owning mutation and therefore observe either its successful
clear or a stable failure conversion, not the live intermediate journal.
Stable degraded/interrupted reasons hold packet enforcement in proven
`BLOCK_ALL` and reject incremental CIDR and packet-mode commands.
Independent DNS configuration changes and DNS TTL expiry may continue under
that proven hold, but cannot clear the stable reason or reactivate packet
policy. Recovery from a stable reason requires one complete LPM **and** DNS
desired state: apply `BulkUpdate` through the control plane or local API (or
answer a restored attachment's fresh `Subscribed` with `SubscribedAck`).
Netfence stages the full protected state,
applies the authoritative DNS state, activates the requested mode, and clears
the durable reason only after every step succeeds. Prefer a unique `command_id`
on a control-plane recovery `BulkUpdate` and require a successful
`CommandResult`; the local API rejects `command_id` because its unary RPC result
already reports success or failure.

Heartbeats expose current physical entries, hard capacity, and
daemon-generation high-water independently for all four protected maps. The
bootstrap is included; adopted pinned entries initialize the new generation's
high-water. `map_full_drops` is cumulative and includes protected capacity
rejections. If an occupancy read fails, the daemon retains the last proven
snapshot and emits a warning at most once per 30 seconds instead of inventing
new counts. To recover from pressure, reduce the complete desired rules below
each per-map capacity and retry the full update. Raising
`filter.max_rule_entries` is load-time only and requires recreating an existing
pinned attachment. If the daemon cannot prove `BLOCK_ALL` or durably record its
safety marker, it stops mutation admission; repair the map/store fault and
restart rather than assuming enforcement reopened.

## Per host

Run the daemon, which:
- Exposes a local gRPC API (`DaemonService`) for attachments, policy, and inspection
- Optionally connects to your control plane via bidirectional stream (`ControlPlane.Connect`)
- Loads and manages eBPF programs

**Start the daemon:**

```bash
# Start with default config
netfenced start

# Start with custom config file
netfenced start --config /etc/netfence/config.yaml
```

**Check daemon status:**

```bash
netfenced status
```

With no `control_plane.url`, a new attachment commits in disabled packet/DNS
mode and can be configured immediately through the local API or CLI. No
control-plane process is required for the standalone workflow documented under
“Per attachment.”

### Local Unix-socket trust boundary

The local gRPC API has no per-RPC authentication. Filesystem access to its Unix
socket is the authorization boundary, and every process that can connect is a
fully trusted host-network administrator: it can attach or detach host eBPF
programs, replace packet and DNS policy, and open or close workload traffic.
Keep socket-group membership narrow and protect the socket's parent directory.

```yaml
# Defaults to /var/run/netfence.sock.
socket: /run/netfence/netfence.sock
# Unix group name or numeric GID. Empty/unset uses the daemon's effective GID.
socket_group: netfence-admin
```

`NETFENCE_SOCKET` and `NETFENCE_SOCKET_GROUP` are the equivalent environment
variables. At startup the daemon binds the socket in a private staging
directory, sets its group and mode `0660` while it is unreachable, and then
publishes it atomically. The daemon removes any pre-existing Unix socket at the
configured target—it does not distinguish a stale socket from one owned by
another live daemon—so exactly one daemon must own a socket path. It refuses to
remove a non-socket target. On Linux, no-replace rename prevents overwriting a
new path created after that removal; shutdown removes the published path only
while it still identifies the daemon's own socket inode. An invalid group,
ownership/mode failure, or non-socket target fails startup without publishing a
permissive endpoint.

### Control-plane transport security (TLS / mTLS / bearer token)

The control-plane channel is the highest-value attack surface in the system
(whoever controls it can push `ALLOW` rules to every workload), so the daemon
**fails closed**: if `control_plane.url` is set, the config must explicitly
choose a transport — either a `control_plane.tls` block or
`control_plane.insecure: true`. A URL with neither is rejected at startup;
there is no implicit-plaintext default. (This is a deliberate behavior change:
older versions silently dialed the control plane unencrypted.)

```yaml
control_plane:
  url: cp.internal:443
  tls:
    # CA bundle used to verify the control-plane server certificate.
    # Path to a PEM file or inline PEM; omit to use the system root pool.
    ca: /etc/netfence/cp-ca.pem
    # Client certificate + key (path or inline PEM). Setting BOTH enables
    # mTLS: the daemon presents this cert to the control plane. Setting only
    # one is a config error.
    cert: /etc/netfence/daemon.pem
    key: /etc/netfence/daemon.key
    # Optional hostname override for server certificate verification (SNI),
    # e.g. when dialing by IP.
    server_name: cp.internal
  # Optional bearer token, sent as `authorization: Bearer <token>` metadata
  # on every control-plane RPC. Refused on a plaintext channel unless
  # `insecure: true` was explicitly set (so a misconfiguration can't leak it).
  auth_token: "..."
```

TLS with system roots only (public CA-issued server cert, no mTLS) is just an
empty block:

```yaml
control_plane:
  url: cp.example.com:443
  tls: {}
```

Plaintext for local development is an explicit opt-in (mutually exclusive
with `tls`):

```yaml
control_plane:
  url: localhost:9000
  insecure: true
```

Certificates and keys are loaded once at startup, so a bad path/PEM fails the
start with a clear error instead of surfacing on every reconnect.

### Control-plane liveness (keepalive) and reconnect backoff

The daemon sends HTTP/2 keepalive pings on the control-plane connection so a
silently dead path (cable pull, dropped NAT mapping, blackholed route) is
detected and torn down in roughly `keepalive_time + keepalive_timeout` —
instead of sitting `CONNECTED` for minutes until the kernel's TCP
retransmission timeout while every proxied DNS query eats its full timeout.
Reconnects are paced by a jittered exponential backoff (starts at 1s,
doubles, ±20% jitter, capped at `reconnect_backoff_max`); the backoff resets
to the floor only after a connection has stayed healthy for 30s, so a
control plane that accepts connections and immediately drops them keeps
backing off instead of being hammered at the floor.

```yaml
control_plane:
  # Send a keepalive ping after this much inactivity… (default 30s; gRPC
  # clamps the effective interval to a 10s minimum client-side)
  keepalive_time: 30s
  # …and declare the peer dead if no ack arrives within this (default 10s).
  keepalive_timeout: 10s
  # Cap on the jittered exponential reconnect backoff (default 30s).
  reconnect_backoff_max: 30s
```

Zero/unset values mean the defaults — they do **not** disable keepalive or
the backoff. Your control plane must permit this ping cadence in its gRPC
keepalive enforcement policy (see below), or it will reject the daemon with
`ENHANCE_YOUR_CALM (too_many_pings)`.

### Daemon restarts, crashes, and upgrades (pinned BPF state)

The daemon pins every attachment's BPF links and rule maps to bpffs
(`filter.bpf_pin_dir`, default `/sys/fs/bpf/netfence`, one directory per
attachment ID). Because pinned state is held by the kernel — not the daemon
process — **enforcement continues while the daemon is down**: a crash
(`kill -9`), a graceful stop, or an upgrade leaves the last-known policy
(mode + all rules) enforcing, and the next daemon start re-adopts the pinned
state as-is. Restore never re-attaches or rewrites the live maps, so there is
no window where an allowlisted workload is blocked or a blocked destination
is allowed, and no duplicate attachment.

Stop behavior is explicit config (`filter.detach_on_stop`):

```yaml
filter:
  # false (default): stopping the daemon KEEPS ENFORCING — filters stay
  # attached via their bpffs pins and are re-adopted on the next start
  # (fail-closed across restarts/upgrades).
  # true: stopping the daemon detaches filters and removes their pins —
  # traffic is unfiltered while the daemon is down (explicit fail-open).
  detach_on_stop: false
  # bpffs directory for pinned state. Must be on a bpffs mount; the daemon
  # mounts bpffs at /sys/fs/bpf if needed (privileged). An explicit "" turns
  # pinning off entirely (BPF state then dies with the process).
  bpf_pin_dir: /sys/fs/bpf/netfence
  # Capacity of each authoritative/system LPM map (allowed/denied per family).
  # Protected entries are non-evictable; the DNS listener bootstrap consumes
  # one slot in its address family. Changing pinned-map capacity requires
  # recreating the attachment.
  max_rule_entries: 4096
  # Independent capacity of each DNS-derived exact-host HASH map (IPv4/IPv6).
  # These entries can never consume or evict authoritative/deny capacity.
  max_dns_rule_entries: 4096
```

An explicit `Detach` (RPC/CLI), or removal of a live coherently-owned target,
destroys the pinned state along with the attachment. On restart, target
absence does not authorize guessing: future, uncommitted, mixed, or otherwise
unverifiable persisted pins are preserved and startup aborts for inspection.

Pin directories are a versioned persistence format. The schema marker is
pinned last, only after every required map and link exists. Upgrading a
pre-exact-tier attachment pins the two new empty exact maps with an
in-progress marker, atomically replaces each link's program while reusing the
live authoritative maps, verifies program/map identity, and commits the
marker last. A crash or ambiguous update leaves the marker uncommitted; the
next start re-updates every link using the same maps. Old and new program
generations enforce the same authoritative LPM policy during that bounded
mixed state, so migration never unpins or recreates a viable filter. Unknown,
incomplete, or unverifiable pin sets are preserved and abort startup for
inspection instead of being guessed away.

Notes on re-adopted state:
- Every successfully restored attachment is marked for authoritative
  reconciliation. On each control-plane connection the daemon sends the
  `SyncRequest` first, then a complete `Subscribed` declaration for each
  restored attachment still needing reconciliation. Reply with a fresh
  `SubscribedAck`: its mode, CIDRs, TTLs, and DNS config are the complete
  desired state. The daemon applies a delta (unchanged CIDRs are never
  removed), and clears the restore marker only after the entire ack applies.
  A timeout, disconnect, or validation failure leaves enforcement unchanged.
  A filter/map/DNS/store apply failure can leave a partial delta, but the
  reconcile does not use a wholesale map clear or remove/re-add unchanged
  survivors; the restore marker remains set and the daemon retries after a
  later connection.
- Rule TTL deadlines themselves are not persisted. Re-adopted rules are
  provisionally treated as permanent until the fresh `SubscribedAck` lands;
  that authoritative ack replaces their lifetimes exactly, including
  shortening a deadline or turning a provisionally permanent rule back into
  a finite-TTL rule. Restored exact DNS keys are inventoried and represented
  by bounded provisional owners (the actual pinned map capacities are the
  bound); the first authoritative DNS config discards every synthetic claim,
  removes keys left ownerless, and preserves a key only when it separately has
  a normal live owner. A non-canonical/colliding inventory aborts restore
  without guessing or partially publishing ownership metadata.
- There is no persisted local desired-state document. If no control plane is
  configured or reachable, no automatic rule changes occur: an adopted pinned
  map continues enforcing its last-known protected CIDRs, represented in the
  userspace registry as provisional until a complete update. A restore that
  cannot adopt valid pins recreates the attachment in its persisted mode with
  empty maps (fail-closed for allowlist/block-all). A standalone orchestrator
  must replay `netfenced apply-rules` after every daemon restart to replace the
  provisional packet state and restore its complete desired state and TTLs.
- DNS domain rules, per-attachment upstream overrides, and attachment DNS
  limits are runtime desired state supplied through either the local API or
  control plane; they are not persisted. A restored attachment whose last DNS
  mode was ALLOWLIST, DENYLIST, or PROXY starts its resolver in an empty
  ALLOWLIST posture, returning `REFUSED` until a complete `BulkUpdate` or
  `SubscribedAck` applies. An explicitly DISABLED DNS mode remains forwarding.
  If either committed UDP/TCP listener later dies unexpectedly, the attachment
  is quarantined in IP `BLOCK_ALL` and reported as an error unsubscribe.
- The per-attachment DNS server is a userspace component and stops with the
  daemon; while the daemon is down, pinned already-resolved exact IPs keep
  working under the last-known packet policy, but new names cannot be resolved
  through it. Their lost userspace deadlines are treated provisionally rather
  than guessed until authoritative reconciliation.

## Per attachment

Your orchestration system calls the daemon's local API.

**RPC:**

```
DaemonService.Attach(interface_name: "veth123", tc_direction: TC_DIRECTION_INGRESS, metadata: {vm_id: "abc"})
// or
DaemonService.Attach(cgroup_path: "/sys/fs/cgroup/...", metadata: {container_id: "xyz"})
```

**CLI:**

```bash
# Attach to a host-side veth peer or VM tap (TC) - use ingress direction
netfenced attach --interface veth123 --direction ingress --metadata vm_id=abc

# Attach to a cgroup
netfenced attach --cgroup /sys/fs/cgroup/... --metadata container_id=xyz

# Attach to an uplink inside the workload's own netns (TC) - egress is the default
netfenced attach --interface eth0 --metadata tenant=acme,env=prod
```

**TC direction:** the `tc_direction` field (CLI `--direction`) selects which
TCX hook the filter attaches to, and picking the correct one depends on which
side of the link the interface is on:

| Interface | Correct direction | Why |
| --- | --- | --- |
| Uplink (e.g. `eth0`), or any interface inside the workload's own netns | `egress` (default) | The workload's outbound packets are transmitted out through it; their destination address is the true destination. |
| Host-side veth peer or VM tap (e.g. `fcr-*`) | `ingress` | The workload's outbound packets arrive at the host **on** that interface. Egress there would instead see host→workload return traffic and filter by the workload's own address rather than the true destination. |

Direction only applies to interface (TC) attachments; it is ignored for
cgroup attachments.

- Daemon attaches an eBPF filter to the target.
- When `control_plane.url` is configured, the daemon sends
  `Subscribed{id, target, type, metadata}` and waits for `SubscribedAck` with
  initial config (mode, CIDRs, DNS rules). If the control plane does not respond
  within the timeout (default 5s, configurable via
  `control_plane.subscribe_ack_timeout`), the attachment is rolled back and the
  attach call fails. Validation and other pre-commit failures follow the same
  ordinary rollback rule.
- With no control plane configured, attach commits immediately in disabled mode;
  use the local policy commands below to configure it.
- A valid initial policy that reaches a protected-map/store failure is the deliberate committed-error exception: the daemon retains the attachment in durable `BLOCK_ALL` instead of destructively rolling it back. With a bounded timeout, `Attach` returns an error containing the retained attachment ID; the caller can discover that ID by matching the target in `List`, and the control plane must recover it with a complete `BulkUpdate`.
- With `subscribe_ack_timeout: 0`, a new `Attach` returns after queuing
  `Subscribed`; a later ack is still validated and applied. This zero value
  does not disable restored-attachment reconciliation: restore attempts wait
  up to 5s in the background and retry on a later connection if needed. If
  that later ack hits protected pressure, the already-returned attachment is
  retained in `BLOCK_ALL`; `SubscribedAck` emits neither `CommandResult` nor
  error `Unsubscribed`, and the daemon does not automatically re-drive the
  declaration before restart. Detect `policy_degraded` plus its reason,
  occupancy/capacity, and `map_full_drops` in `Heartbeat`, then send a complete
  `BulkUpdate` with `command_id` to obtain an explicit recovery result.
- Daemon watches for target removal and sends `Unsubscribed` automatically

**RPC:**

```
DaemonService.Detach(id)
```

**CLI:**

```bash
netfenced detach --id <attachment-id>
```

**List attachments:**

```bash
netfenced list
netfenced list --all  # fetch all pages
```

### Local policy and inspection

Every local mutation is a thin CLI encoding of the single
`DaemonService.ApplyCommand(ControlCommand)` RPC. Supply the attachment ID
returned by `attach`:

```bash
# Packet policy and protected CIDRs.
netfenced set-mode <id> allowlist
netfenced allow-cidr <id> 10.0.0.0/8
netfenced allow-cidr <id> 192.0.2.10/32 --ttl 5m
netfenced deny-cidr <id> 10.20.0.0/16
netfenced remove-cidr <id> 10.20.0.0/16 --list deny
# --list accepts allow, deny, or both (the default).

# DNS policy.
netfenced set-dns-mode <id> denylist
netfenced allow-domain <id> example.com --subdomains
netfenced deny-domain <id> blocked.example.com
netfenced remove-domain <id> blocked.example.com

# Deterministic current-policy inspection as protobuf JSON.
netfenced rules <id>
```

Packet modes are `disabled`, `allowlist`, `denylist`, and `block-all`; DNS modes
are `disabled`, `allowlist`, `denylist`, and `proxy`. DNS `proxy` requires a
reachable configured control plane. Domain matching uses the most-specific
matching suffix; when equally specific allow and deny rules both match, deny
wins. CIDRs and domains are canonicalized. Negative, malformed, or otherwise
invalid TTLs, enums, CIDRs, domains, selectors, and nested messages are rejected
before mutation, so an invalid command is a policy no-op.

For a complete replacement, `apply-rules` reads the existing `BulkUpdate`
protobuf JSON shape from a file or stdin:

```bash
cat >rules.json <<'JSON'
{
  "mode": "POLICY_MODE_ALLOWLIST",
  "allowCidrs": [{"cidr": "10.0.0.0/8"}],
  "dns": {
    "mode": "DNS_MODE_DENYLIST",
    "denyDomains": [{"domain": "blocked.example.com", "includeSubdomains": true}]
  }
}
JSON
netfenced apply-rules <id> --file rules.json
# Equivalent stdin form:
netfenced apply-rules <id> --file - < rules.json
```

`ApplyCommand` accepts only `SetMode`, `AllowCIDR`, `DenyCIDR`, `RemoveCIDR`,
`BulkUpdate`, `SetDnsMode`, `AllowDomain`, `DenyDomain`, and `RemoveDomain`.
Stream-only sync/ack variants, unknown or empty commands, and local
`command_id` values are rejected. `BulkUpdate` is also the only local operation
that can recover a stable degraded packet policy; it must contain the complete
LPM and DNS desired state.

The optional `ControlCommand.remove_cidr_list` selector can target the allow
list, deny list, or both when the command variant is `RemoveCIDR`. Its legacy
unspecified value and explicit `BOTH` both remove from both lists, preserving
the original protocol behavior.

Local and control-plane mutations share one parser, mutation barrier, TTL
registry, fail-closed recovery path, and policy owner. There is deliberately no
local-versus-control-plane ownership arbitration: conflicting operations on an
individual policy list take effect in their committed order, regardless of
source. In particular, a later complete control-plane `BulkUpdate` or
`SubscribedAck` can replace local state.

`GetRules`/`netfenced rules` returns a coherent, deterministic userspace
registry snapshot. Each CIDR reports allow/deny list, local-or-control-plane
`policyOwned`, daemon `systemOwned`, absolute `expiresAt`, restored
`provisional`, and last committed kernel `installed` state. An installed entry
with neither owner is a failed-removal retry, not desired policy. DNS output is
the live, normalized effective `DnsConfig`. Inspection intentionally does not
enumerate protected kernel maps or expose dynamically resolved DNS exact-host
cache entries; use heartbeat telemetry for protected-map occupancy.

## On the control plane (you implement this)

Implement `ControlPlane.Connect` RPC - a bidirectional stream:

Configure your gRPC server's keepalive enforcement policy to permit the
daemon's ping cadence (`control_plane.keepalive_time`, default 30s): set
`MinTime` at or below that interval and `PermitWithoutStream: true`. The gRPC
default policy (5 minutes) treats the daemon's pings as abusive and closes
the connection with `ENHANCE_YOUR_CALM (too_many_pings)`. In Go:

```go
grpc.NewServer(grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
    MinTime:             10 * time.Second,
    PermitWithoutStream: true,
}))
```

**Receive from daemon:**
- `SyncRequest` on connect/reconnect (lists current attachments)
- `Subscribed` when new attachments are added, and after `SyncRequest` for restored attachments that still need fresh authoritative state
- `Unsubscribed` when attachments are removed
- `Heartbeat` with stats
- `CommandResult{command_id, id, success, error}` — outcome of any command you sent with a non-empty `command_id` (opt-in correlation nonce on `ControlCommand`; commands without one produce no result). `success` is true only if the command fully applied — a partially-applied `BulkUpdate` reports failure with the aggregated error. Results are best-effort: treat a missing result as unknown, not failed.

**Send to daemon:**
- `SyncAck` after receiving SyncRequest
- `SubscribedAck{mode, cidrs, dns_config}` after receiving Subscribed (required - daemon waits for this)
- `SetMode{mode}` - change IP filter policy mode
- `AllowCIDR{cidr, ttl}` / `DenyCIDR` / `RemoveCIDR` (optionally select
  allow, deny, or both; unspecified retains legacy “both” behavior)
- `SetDnsMode{mode}` - change DNS filtering mode
- `AllowDomain{domain}` / `DenyDomain` / `RemoveDomain` (most-specific match
  wins; deny wins an equal-specificity tie)
- `BulkUpdate{mode, cidrs, dns_config}` - full state sync

When the control plane receives `Subscribed`, it must reply with a complete
`SubscribedAck`. For a new attachment the daemon normally waits for that ack
before returning success to the local caller. For a restored attachment the
handshake runs in the background while the pinned last-known policy keeps
enforcing. Use the metadata to identify the VM/tenant/container and return the
complete desired mode, CIDRs (including TTLs), and DNS state; an omitted DNS
config means disabled with empty domain lists.

### Reconnects and idempotency (required)

`SyncRequest` is the authoritative reconciliation point: on every
(re)connect it is the first event on the stream and lists the daemon's
complete current attachment set. Reconcile your view against it — add
attachments you didn't know about, drop ones absent from the list. On
reconnect the daemon purges events that were queued against the previous
connection (the sync supersedes them), so you will not see stale
`Heartbeat`s, `Unsubscribed`s for attachments already absent from the sync,
or `CommandResult`s from the dead connection replayed after it. Two edge
cases remain by design, and your control plane MUST handle them
idempotently:

- A `Subscribed` can follow a `SyncRequest` that already lists the same id.
  This happens when a new attachment's ack was pending across reconnect, and
  deliberately for every restored attachment until one authoritative ack
  applies completely. Treat it as an update, reply with a fresh complete
  `SubscribedAck`, and never discard it as a duplicate. `SyncRequest`
  reconciles attachment inventory; `SubscribedAck` reconciles desired policy.
- An event generated concurrently with the (re)connect can race the sync
  snapshot in either direction. Treat an `Unsubscribed` for an unknown or
  already-removed attachment id as a no-op.

### Rule lifetimes (TTLs)

- CIDR entries (`AllowCIDR`/`DenyCIDR` commands, and the CIDR lists in `SubscribedAck`/`BulkUpdate`) carry an optional TTL. TTL'd rules are removed by a daemon janitor once they expire (scan interval `ttl_janitor_interval`, default 1s); rules without a TTL are permanent.
- Incremental `AllowCIDR`/`DenyCIDR` re-adds extend a CIDR to the later deadline — they never shorten one — and an incremental re-add without a TTL makes it permanent. In contrast, the complete state in `SubscribedAck`/`BulkUpdate` replaces each control-plane lifetime exactly, so authoritative reconciliation can shorten a TTL or change permanent to finite without removing/re-adding the live map entry. Use `RemoveCIDR` to drop an incremental rule early.
- DNS-resolved IPs enter only the exact tier with the record TTL floored by `dns.min_filter_ttl` (default 60s; zero/unset means the default, not "no floor"). An upstream TTL of zero therefore lives for the floor; an omitted PROXY TTL is explicitly defaulted to 300s before the floor is applied. A permanent or longer-lived CIDR rule covering the same address remains independently installed in the protected LPM tier when exact DNS ownership expires.
- Authoritative/system allow CIDRs and deny CIDRs remain in four protected, non-evictable LPM maps sized by `filter.max_rule_entries` per attachment (default 4096 each); see “Protected CIDR capacity and fail-closed recovery” above. DNS-derived host addresses use separate exact-match HASH maps sized by `filter.max_dns_rule_entries` (default 4096 per IP family), so they cannot consume or evict authoritative or deny capacity. Complete DNS-response admission validates/canonicalizes every address and preflights physical and logical capacity before mutation. A DNS exact-map kernel error restores its exact pre-call snapshot; if that rollback cannot be proven, the resolver suppresses the answer and quarantines the attachment in durable IP `BLOCK_ALL` before accepting another mutation.
