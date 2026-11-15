# Routing and NETMAP

WGPanel does not create a site-LAN route or NETMAP rule. Their persistent
source must remain in `wg0.conf` (`PostUp`/`PostDown`) or in a separately
documented host firewall/routing service. The round-trip renderer preserves
these interface lines.

The values below use RFC 5737 documentation networks and are examples only.
Substitute the actual site peer address and routed LAN. A typical idempotent
`PostUp` route is:

```ini
PostUp = ip route replace 198.51.100.0/24 via 192.0.2.10 dev wg0
```

Keep the existing, tested NETMAP rules rather than copying a generic example.
An example behavior is destination `203.0.113.0/24` translated to
`198.51.100.0/24` for traffic arriving on `wg0`, with a matching reverse path.

Read-only verification commands:

```bash
ip -4 route get 198.51.100.55
ip -4 route show 198.51.100.0/24
wg show wg0 allowed-ips
iptables-nft -t nat -S | grep -E 'NETMAP|198\.51\.100\.0/24|203\.0\.113\.0/24'
```

Expected properties, not canned output: the route resolves through `wg0` and
the site peer; the `example-site` public key owns both required prefixes; the
NETMAP pair is still present once, not duplicated.
