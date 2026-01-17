# Super eBPF

A control plane for network filters per-interface/cgroup so you can give each VM or container its own egress filtering policy.

Specifically great for VMs. This is what I made for our agent VMs so we can define DNS names that the VMs can access (apt, pip, npm) but prevent internet access to anything else to reduce the exfiltration surface area. Using a custom DNS server that sends the IPs to a whitelist map shared with an eBPF filter for each container. Works fantastic.

Make this a pre-made control daemon and eBPF program, and the user just manages attaching to new interfaces/cgroups and implementing the gRPC control plane.

## Features

- Attach eBPF filters to network interfaces (TC) or cgroups
- Policy modes: disabled, allowlist, denylist, block-all
- IPv4 and IPv6 CIDR support with optional TTLs
- Per-attachment DNS server with domain allowlist/denylist
- Domain rules support subdomains with specificity-based matching (more specific rules win)
- Resolved domains auto-populate IP filter
- Metadata on attachments for associating with VM ID, tenant, etc.

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
