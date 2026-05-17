# Using WGPanel With Existing WireGuard

WGPanel 0.1.2-beta is designed to run on a server that may already have `/etc/wireguard/wg0.conf`.

WGPanel 0.1.3-beta also supports multiple interfaces. `wg0` is the default, but interfaces such as `wg1`, `wg-test`, `homevpn`, and `wg.prod` are supported. WGPanel never accepts arbitrary config paths: interface `NAME` maps only to `/etc/wireguard/NAME.conf`.

## Safe Config Model

WGPanel reads the current `wg0.conf` before every apply. It preserves `[Interface]` settings, comments, `PostUp`, `PostDown`, `MTU`, `Table`, routing rules, and unmanaged `[Peer]` blocks.

Peers created or imported by WGPanel are managed peers. Existing peers that are not in SQLite are unmanaged peers. WGPanel shows unmanaged peers in the UI, but does not remove, disable, modify, reorder, or rewrite them.

## Taking Ownership

Existing peers can be imported with “Take ownership.” This stores metadata such as name, notes, assigned IP, and expiration. It does not require and does not reveal the client private key.

Old client configs cannot be regenerated after import because WGPanel does not store client private keys.

## Enable, Disable, Delete

Disabling a managed peer removes that peer from the active candidate WireGuard config and runs `wg syncconf wg0`. Enabling it re-adds the peer. Deleting a managed peer removes only that managed peer.

Unmanaged peers are never disabled or deleted by WGPanel.

## Expiration

Expiration is metadata by default. Expired peers show as expired but are not automatically disabled unless `WGPANEL_AUTO_DISABLE_EXPIRED=true` or `POST /api/maintenance/expire` is run.

When expiration disables a peer, it uses the same real disable behavior: the managed peer is removed from the active config and `wg syncconf wg0` is applied.

## Backups

Before each real apply, WGPanel’s root-owned helper copies the current config to:

```text
/etc/wireguard/backups/wg0.conf.YYYYMMDD-HHMMSS.bak
```

Backups stay under `/etc/wireguard/backups`, not `/run`, because `/run` is temporary.

Restore a backup with:

```bash
sudo cp /etc/wireguard/backups/<backup> /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

## Test Safely First

Use a VM before pointing WGPanel at a production VPN server:

```bash
sudo wg show wg0
sudo cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.manual-test.bak
docker compose up -d --build
docker compose exec wgpanel wg show wg0
```

Create a test peer, disable it, enable it, and confirm existing unmanaged peers remain present in `wg show wg0`.
