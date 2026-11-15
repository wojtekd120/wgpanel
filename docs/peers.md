# Peer lifecycle and AllowedIPs

## Two different fields

`server_allowed_ips` is WireGuard cryptokey routing on the server. For an
example site peer it can contain both:

```text
192.0.2.10/32, 198.51.100.0/24
```

These are RFC 5737 documentation addresses and must be replaced with real
deployment values. The host route identifies the peer; the LAN prefix says
that a routed LAN is behind that peer. WGPanel requires the assigned host
route and rejects a CIDR that overlaps a prefix owned by another managed or
unmanaged peer.

`client_allowed_ips` is written only to a generated client profile. It decides
which destinations the client sends into its tunnel, for example a split
tunnel subnet or `0.0.0.0/0`. It is never used to render the server peer.

For new peers, the assigned `/32` is added to server-side AllowedIPs
automatically. The create form accepts only additional prefixes. The edit form
shows the complete server-side list.

## Existing peer migration

The schema adds `peers.server_allowed_ips TEXT NOT NULL DEFAULT ''`. Before
the application can re-render a legacy managed peer, startup matches its
public key against the real config and imports every existing prefix. Taking
ownership of an unmanaged peer does the same.

Do not manually set this database column to only the tunnel address for a
site-to-site peer. Use the UI or API and retain all routed networks.

## Conflict policy

WGPanel rejects equal, parent/child and otherwise overlapping IPv4 or IPv6
networks across different peers. Existing state is imported without rewriting
the interface; an operator can inspect and resolve historical conflicts before
the next relevant edit.
