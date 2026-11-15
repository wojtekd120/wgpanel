# Guest isolation design (Stage 2)

Stage 2 code is present but disabled by default. WGPanel has an explicit guest
profile with a separate interface, endpoint, server public key, address pool
and DNS. It never falls back from a guest profile to `wg0` settings. The UI
offers `Guest (isolated)` only after `WGPANEL_GUEST_ENABLED=true`.

Enabling the UI flag is the final step, not the first. Isolation comes from the
host nftables policy and systemd dependency shipped in `scripts/` and
`deploy/`. A label or different address alone is not a security boundary.

## MVP scope

The implementation uses a separate `wg1`, UDP port `51821` and a candidate subnet such as
`10.10.20.0/24` only after checking `ip -4 route`, `ip -6 route`, Docker
networks and all WireGuard AllowedIPs for collisions. Add per-interface
profiles containing interface role, endpoint, public key, pool, server address,
DNS policy and client IPv6 policy. A guest profile must never fall back to
`wg0` settings.

Build the firewall as an idempotent, dedicated nftables table managed by one
systemd unit. Do not append anonymous iptables rules on every `PostUp`.
Required policy:

* drop `wg1 -> wg1` before any established-state allowance;
* drop new traffic in both directions between `wg1` and `wg0`;
* allow established return traffic from the internet to `wg1`;
* drop guest destinations in loopback, link-local, RFC1918, carrier-grade NAT,
  Docker and all configured private/site-to-site sets;
* drop guest traffic to every local VPS address in an early prerouting chain,
  before Docker DNAT, and drop all `INPUT` arriving on `wg1` unless a narrowly
  documented local DNS exception exists;
* drop new host/private output to `wg1`, while allowing established replies;
* anti-spoof source addresses not belonging to the guest pool;
* masquerade only `10.10.20.0/24` arriving on `wg1` and leaving the actual
  public uplink;
* optionally allow only TCP/UDP 53 to one explicitly configured local DNS
  address, while keeping its web UI and every other VPS service blocked;
* drop all IPv6 arriving on `wg1` for the IPv4-only MVP and omit IPv6
  AllowedIPs/address/DNS from guest profiles.

An nftables `accept` in an early base chain is not assumed to bypass UFW or
Docker chains; a `drop` is final. Hook priorities and the pre-DNAT public-IP
rule must be tested on the actual nftables ruleset (`nft -a list ruleset`), not
only with `iptables -S`.

## Test gate

First reproduce UFW and Docker ordering in network namespaces or a disposable
VM. Capture packet counters and test:

* guest to public IPv4 succeeds;
* guest to the private VPN server, every private peer, every routed LAN
  prefixes, a second guest and administrative ports fails;
* private peer, VPS host and private LAN cannot initiate to a guest;
* the VPS public address cannot hairpin to SSH, WGPanel or Docker-published
  admin services;
* arbitrary guest IPv6 fails;
* existing `wg0`, site-to-site, LAN route and NETMAP behavior remain intact.

Only after this gate should `WGPANEL_GUEST_ENABLED` be set to `true`. Guest
creation, export and QR generation then use only the `wg1` profile. Guest
server-side AllowedIPs are fixed to the assigned `/32`, client AllowedIPs are
fixed to IPv4 `0.0.0.0/0`, and no IPv6 route is exported.
