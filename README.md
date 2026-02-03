# Netfence

_Like Envoy xDS, but for eBPF filters._

Netfence runs as a daemon on your VM/container hosts and automatically injects eBPF filter programs into cgroups and network interfaces, with a built-in DNS server that resolves allowed domains and populates the IP allowlist.

Netfence daemons connect to a central control plane that you implement via gRPC to synchronize allowlists/denylists with your backend.

Your control plane pushes network rules like `ALLOW *.pypi.org` or `ALLOW 10.0.0.0/16` to attached interfaces/cgroups. When a VM/container queries DNS, Netfence resolves it, adds the IPs to the eBPF filter, and drops traffic to unknown IPs before it leaves the host without any performance penalty.

## Features

- Attach eBPF filters to network interfaces (TC) or cgroups
- Policy modes: disabled, allowlist, denylist, block-all
- IPv4 and IPv6 CIDR support with optional TTLs
- Per-attachment DNS server with domain allowlist/denylist
- Domain rules support subdomains with specificity-based matching (more specific rules win)
- Resolved domains auto-populate IP filter
- Metadata on daemons and attachments for associating with VM ID, tenant, etc.
- Support for proxying DNS queries to the control plane to make DNS decisions per-attachment

## Differences from other options

A few major benefits to this solution that other options don't usually support:

- Immediate severing of existing connections when rules change to disallow an IP (interface attach only)
- Support all network protocols, and direct to IP networking. For example, the awesome [httpjail](https://github.com/coder/httpjail) doesn't allow you to connect direct to IPs, or direct TCP/UDP connections like connecting to databases.
- Dynamic resolving of DNS and pre-resolution filtering (so there's no `secretdata.someattacker.com` exfiltration)

To my knowledge, no other solutions offers all of these features together.

However, this does have a bit more overhead than something like [httpjail](https://github.com/coder/httpjail).

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
DaemonService.Attach(interface_name: "veth123", metadata: {vm_id: "abc"})
// or
DaemonService.Attach(cgroup_path: "/sys/fs/cgroup/...", metadata: {container_id: "xyz"})
```

**CLI:**

```bash
# Attach to a network interface (TC)
netfenced attach --interface veth123 --metadata vm_id=abc

# Attach to a cgroup
netfenced attach --cgroup /sys/fs/cgroup/... --metadata container_id=xyz

# Attach with metadata
netfenced attach --interface eth0 --metadata tenant=acme,env=prod
```

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
