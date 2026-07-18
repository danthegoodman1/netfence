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
| Cached "already added to filter" check | ~66.7 ns |

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
- Daemon sends `Subscribed{id, target, type, metadata}` to control plane and waits for `SubscribedAck` with initial config (mode, CIDRs, DNS rules)
- If the control plane doesn't respond within the timeout (default 5s, configurable via `control_plane.subscribe_ack_timeout`), the attachment is rolled back and the attach call fails
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

**Receive from daemon:**
- `SyncRequest` on connect/reconnect (lists current attachments)
- `Subscribed` when new attachments are added
- `Unsubscribed` when attachments are removed
- `Heartbeat` with stats

**Send to daemon:**
- `SyncAck` after receiving SyncRequest
- `SubscribedAck{mode, cidrs, dns_config}` after receiving Subscribed (required - daemon waits for this)
- `SetMode{mode}` - change IP filter policy mode
- `AllowCIDR{cidr, ttl}` / `DenyCIDR` / `RemoveCIDR`
- `SetDnsMode{mode}` - change DNS filtering mode
- `AllowDomain{domain}` / `DenyDomain` / `RemoveDomain`
- `BulkUpdate{mode, cidrs, dns_config}` - full state sync

When the daemon receives `Subscribed`, it blocks waiting for `SubscribedAck` before returning success to the caller. This ensures the attachment has its initial configuration before traffic flows. Use the metadata to identify which VM/tenant/container this attachment belongs to and respond with the appropriate initial rules.
