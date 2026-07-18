# Netfence

_Like Envoy xDS, but for eBPF filters._

Netfence runs as a daemon on your VM/container hosts and automatically injects eBPF filter programs into cgroups and network interfaces, with a built-in DNS server that resolves allowed domains and populates the IP allowlist.

Netfence daemons connect to a central control plane that you implement via gRPC to synchronize allowlists/denylists with your backend.

Your control plane pushes network rules like `ALLOW *.pypi.org` or `ALLOW 10.0.0.0/16` to attached interfaces/cgroups. When a VM/container queries DNS, Netfence resolves it, adds the IPs to the eBPF filter, and drops traffic to unknown IPs before it leaves the host with warmed-path overhead that is effectively indistinguishable from a normal socket connect in current benchmarks.

## Features

- Attach eBPF filters to network interfaces (TC) or cgroups
- Policy modes: disabled, allowlist, denylist, block-all
- IPv4 and IPv6 CIDR support with optional TTLs
- Per-attachment DNS server with domain allowlist/denylist
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
using `docker compose run --build --rm bench ...`.

### Warm socket path

The warm socket benchmark uses connected UDP sockets to isolate the
`cgroup/connect4` eBPF hook cost from TCP handshake latency. In this path DNS has
already resolved the domain, the IP is still within TTL, and the IP/CIDR is
already present in the eBPF map.

| Path | Mean latency |
| --- | ---: |
| Normal socket connect, no eBPF | ~3.037 us |
| Warm allowlist, IP already in eBPF map | ~3.042 us |
| Measured overhead | ~4 ns, effectively noise |
| Allowlist miss, local block | ~1.803 us |

There is no "kernel miss asks parent process" path today. A cgroup allowlist
miss is decided locally by eBPF and is blocked immediately.

### DNS query path

These numbers measure the DNS server path, not the warmed socket connect path.

| Path | Mean latency |
| --- | ---: |
| Proxy query cold, in-process policy function | ~26.7 us |
| Proxy query warm | ~25.3 us |
| Allowlist query cold with local upstream | ~68.0 us |
| Allowlist query warm with local upstream | ~67.4 us |
| Cached "already added to filter" check (also refreshes the entry's TTL deadline) | ~0.2 us |

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

Each attachment gets a unique DNS address (port) provisioned by the daemon. Containers/VMs should be configured to use their assigned DNS address.

## Per host

Run the daemon, which:
- Exposes a local gRPC API (`DaemonService`) for attaching/detaching filters
- Connects to your control plane via bidirectional stream (`ControlPlane.Connect`)
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
```

An explicit `Detach` (RPC/CLI) or a removed target always destroys the
pinned state along with the attachment.

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
  a finite-TTL rule.
- If no control plane is configured or reachable, no automatic rule changes
  occur: an adopted pinned map continues enforcing its last-known contents. A
  restore that cannot adopt valid pins recreates the attachment in its
  persisted mode with empty maps (fail-closed for allowlist/block-all) and
  uses the same `SubscribedAck` handshake to repopulate it.
- The per-attachment DNS server is a userspace component and stops with the
  daemon; while the daemon is down, already-resolved (still unexpired) IPs
  keep working but new names cannot be resolved through it.

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

- Daemon attaches eBPF filter to the target
- Daemon sends `Subscribed{id, target, type, metadata}` to the control plane and waits for `SubscribedAck` with initial config (mode, CIDRs, DNS rules)
- If the control plane doesn't respond within the timeout (default 5s, configurable via `control_plane.subscribe_ack_timeout`), the attachment is rolled back and the attach call fails
- With `subscribe_ack_timeout: 0`, a new `Attach` returns after queuing
  `Subscribed`; a later ack is still validated and applied. This zero value
  does not disable restored-attachment reconciliation: restore attempts wait
  up to 5s in the background and retry on a later connection if needed.
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
- `AllowCIDR{cidr, ttl}` / `DenyCIDR` / `RemoveCIDR`
- `SetDnsMode{mode}` - change DNS filtering mode
- `AllowDomain{domain}` / `DenyDomain` / `RemoveDomain`
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
- DNS-resolved IPs enter the filter with the record TTL floored by `dns.min_filter_ttl` (default 60s; zero/unset means the default, not "no floor") and expire the same way. A permanent (or longer-lived) CIDR rule covering the same address is never removed by DNS expiry.
- Each rule map holds `filter.max_rule_entries` entries per attachment (default 4096, load-time sizing with no per-packet cost). When a map is full, new adds fail loudly and are counted in the `map_full_drops` heartbeat stat instead of being silently dropped.
