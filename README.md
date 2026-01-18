# Netfence

_Like Envoy xDS, but for VM/container firewalls._

Netfence runs as a daemon on your VM/container hosts and automatically injects filter programs into cgroups and network interfaces, with a built-in DNS server that resolves allowed domains and populates the IP allowlist.

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

- Run the daemon, which:
  - Exposes a local gRPC API (`DaemonService`) for attaching/detaching filters
  - Connects to your control plane via bidirectional stream (`ControlPlane.Connect`)
  - Loads and manages eBPF programs

## Per attachment

Your orchestration system calls the daemon's local API:

```
DaemonService.Attach(interface_name: "veth123", metadata: {vm_id: "abc"})
// or
DaemonService.Attach(cgroup_path: "/sys/fs/cgroup/...", metadata: {container_id: "xyz"})
```

- Daemon attaches eBPF filter to the target
- Daemon sends `Subscribed{id, target, type, metadata}` to control plane
- Daemon watches for target removal and sends `Unsubscribed` automatically
- Or explicitly detach via `DaemonService.Detach(id)`

## On the control plane (you implement this)

Implement `ControlPlane.Connect` RPC - a bidirectional stream:

**Receive from daemon:**
- `SyncRequest` on connect/reconnect (lists current attachments)
- `Subscribed` when new attachments are added
- `Unsubscribed` when attachments are removed
- `Heartbeat` with stats

**Send to daemon:**
- `SyncAck` after receiving SyncRequest
- `SetMode{mode}` - change IP filter policy mode
- `AllowCIDR{cidr, ttl}` / `DenyCIDR` / `RemoveCIDR`
- `SetDnsMode{mode}` - change DNS filtering mode
- `AllowDomain{domain}` / `DenyDomain` / `RemoveDomain`
- `BulkUpdate{mode, cidrs, dns_config}` - full state sync

Use the metadata from `Subscribed` to identify which VM/tenant/container this attachment belongs to, then push appropriate rules.
