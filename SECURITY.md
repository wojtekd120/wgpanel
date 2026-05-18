# Security

## Threat Model

WGPanel assumes the host administrator controls Docker, `/etc/wireguard`, and the `.env` file. The web UI is intended to be exposed only behind HTTPS and protected by the built-in login session.

## Private Keys

Generated client private keys are shown only once immediately after peer creation. They are not stored in SQLite and cannot be recovered later. Existing/imported peers cannot have client configs regenerated unless the client private key is provided in a future feature.

The server private key in `/etc/wireguard/<interface>.conf` is never exposed through the UI or API. WGPanel never intentionally logs client configs or private keys.

Encrypted-at-rest client private key storage could be added later as an explicit opt-in feature. It is not implemented in this beta.

## Docker Capabilities

The Docker service uses host networking, `NET_ADMIN`, and `/dev/net/tun` so `wg show <interface>` and `wg syncconf <interface>` operate against the host network namespace. The container does not use `privileged: true` and does not add `SYS_MODULE` by default.

WireGuard should be installed and loaded on the host.

## Sudo Helper Model

FastAPI runs as the unprivileged `wgpanel` user. Passwordless sudo is limited to the root-owned helper commands needed for apply, restore, backup creation, and self-test:

```text
/usr/local/sbin/wgpanel-helper apply --interface * --config /run/wgpanel/*.conf
/usr/local/sbin/wgpanel-helper restore --interface * --backup /etc/wireguard/backups/*.bak
/usr/local/sbin/wgpanel-helper backup --interface *
/usr/local/sbin/wgpanel-helper self-test
```

The helper is root-owned. It rejects config paths outside `/run/wgpanel`, validates the config with `wg-quick strip`, creates a backup, and then applies with `wg syncconf <interface>`.

Diagnostics verifies the same restricted path with:

```bash
sudo -n /usr/local/sbin/wgpanel-helper self-test
```

The self-test does not modify live WireGuard config. If this cannot be verified automatically, WGPanel shows a warning instead of a hard failure.

## Config Backups

Before each real apply, WGPanel creates a timestamped backup under `/etc/wireguard/backups`. Backups and `wg0.conf` are not world-readable because they contain the server private key.

Restore with:

```bash
sudo cp /etc/wireguard/backups/<backup> /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

## Known Limitations

WGPanel beta does not provide speed or data limits. WireGuard has no native per-peer speed/data limit; this requires `tc` or `nftables` integration.

WGPanel preserves unmanaged peers, but always test on a VM before first production use.

## First-Run Setup

When no admin exists and no `WGPANEL_ADMIN_PASSWORD_HASH` is configured, WGPanel redirects first browser visits to `/setup`. The setup page creates the first admin account and stores only a password hash in SQLite.

Do not expose first-run setup over public plain HTTP. If `WGPANEL_HOST=0.0.0.0`, complete setup immediately or stop the service. Password reset requires shell or Docker access to the server:

```bash
docker compose exec wgpanel wgpanel-admin reset-password
```

Advanced one-time setup tokens may still be created from the server shell for recovery workflows, but they are not required for normal installation.
