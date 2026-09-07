# Local change to smoltcp 0.14.0

Source: https://crates.io/crates/smoltcp/0.14.0 (Cargo.lock pins other dependencies).
Upstream licenses are retained in this directory.

One change in `src/iface/interface/ipv6.rs`: permit unassigned IPv6 unicast destinations
when `Interface::set_any_ip(true)` and the route gateway is owned by the interface,
matching the existing IPv4 AnyIP contract. The default (AnyIP disabled) is unchanged.
Harbor needs this for transparent packet-to-flow dispatch. This directory is a source
dependency, not a separately running networking core.

Review this patch when upgrading smoltcp. Packet tests cover IPv4 and IPv6 streams,
half-close, UDP and unassigned IPv6 destinations.
