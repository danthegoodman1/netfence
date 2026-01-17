A control plane for network filters per-interface/cgroup so you can give each VM or container its own egress filtering policy.

Can monetize via licensing and/or managed control plane, and managed/integrated DNS server (push delta before resolving DNS) to power it.

Specifically great for VMs. This is what I made for our agent VMs so we can define DNS names that the VMs can access (apt, pip, npm) but prevent internet access to anything else to reduce the exfiltration surface area. Using a custom DNS server that sends the IPs to a whitelist map shared with an eBPF filter for each container. Works fantastic.

Make this a pre-made control daemon and eBPF program, and the user just manages attaching to new interfaces/cgroups and implementing the gRPC control plane.

## Features

- Attach eBPF filters to network interfaces (TC) or cgroups
- Policy modes: disabled, allowlist, denylist, block-all
- IPv4 and IPv6 CIDR support
- TTLs on CIDRs (daemon auto-expires)
- Metadata on attachments for associating with VM ID, tenant, etc.

## Future

- Subdomains/patterns
- Sever existing connections on rule change
- CoreDNS plugin or standalone DNS server with API

# Design

## Architecture

```
+------------------+         +-------------------+
|  Your Control    |<------->|  Daemon           |
|  Plane (gRPC)    |  stream |  (per host)       |
+------------------+         +-------------------+
                                    |
                             +------+------+
                             |             |
                          TC Filter    Cgroup Filter
                          (veth, eth)  (containers)
```

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
- `SetMode{mode}` - change policy mode
- `AllowCIDR{cidr, ttl}` - add to allowlist
- `DenyCIDR{cidr, ttl}` - add to denylist
- `RemoveCIDR{cidr}` - remove from lists
- `BulkUpdate{mode, allow_cidrs, deny_cidrs}` - full state sync

Use the metadata from `Subscribed` to identify which VM/tenant/container this attachment belongs to, then push appropriate rules.
