A control plane for network filters per-interface so you can give each VM 

Can monetize via licensing and/or managed control plane, and managed/integrated DNS server (push delta before resolving DNS) to power it.

Specifically great for VMs. This is what I made for our agent VMs so we can define DNS names that the VMs can access (apt, pip, npm) but prevent internet access to anything else to reduce the exfiltration surface area. Using a custom DNS server that sends the IPs to a whitelist map shared with an eBPF filter for each container. Works fantastic.

Make this a pre-made control daemon and eBPF program, and the user just manages attaching to new interfaces and implementing the gRPC control plane.

Can extend it to allow:

- Subdomains or not (patterns?)
- TTLs (managed by the daemon)
- decide whether to sever existing connections (would have to ad-hoc resolve DNS then, might cause false positives for killing connections)
- Dynamic changing of default allow/deny
- CIDR ranges?

Maybe provide a CoreDNS plugin, or just a whole DNS server with API

# Design

## Per host

- Have some eBPF locally that can be loaded
- Run an instance of the pre-made control daemon which contacts your grpc server

## Per interface

- You install the eBPF program on the interface
- daemon detects new and removed interfaces with some pattern like `fcr-*` and report subscribe to control plane, and unsubscribe when it is removed (resyncs on start in case of crash)
- You remove the eBPF filter

## On the control plane

- The control daemons tell you about subscribe and unsubscribe with some metadata (so you can associate with VM id, tenant, etc.)
- You push deltas like "allow ip", "deny ip", "change to block all by default" "change to allow all by default", e tc.
- Eventually the interface "unsubscribes" and you can forget about it
