# Native Systemd Install

Docker Compose is the recommended easiest install path. The native systemd installer is supported and tested for users who prefer WGPanel to run directly on Debian/Ubuntu without Docker.

## Quick Install

```bash
sudo ./scripts/install-systemd.sh
```

The installer is interactive. It can use an existing WireGuard interface, create a new basic WireGuard config, or skip WireGuard setup and only install WGPanel.

Run it from a complete repository checkout:

```bash
git clone https://github.com/wojtekd120/wgpanel.git
cd wgpanel
sudo ./scripts/install-systemd.sh
```

The installer checks that `backend/requirements.txt`, `backend/app`, `frontend/package.json`, and `helper/wgpanel-helper` exist before it copies files to `/opt/wgpanel`. It excludes `.git`, `node_modules`, virtualenvs, SQLite databases, logs, and `.env`.

## Existing WireGuard

Choose the existing WireGuard option. The installer:

- detects `/etc/wireguard/<interface>.conf`
- creates a timestamped backup under `/etc/wireguard/backups`
- starts `wg-quick@<interface>` if you approve
- leaves existing peers unmanaged until you take ownership in WGPanel

## New WireGuard Setup

Choose the new WireGuard option. The installer asks for VPN subnet, server VPN address, listen port, public endpoint, and DNS. It generates server keys and writes `/etc/wireguard/<interface>.conf` only after confirmation if a config already exists.

## First-Run Browser Setup

After install, open the printed URL. WGPanel redirects to `/setup` and asks for admin username, password, and confirmation. No password hash or setup token is required for normal installs.

Password reset from the server shell:

```bash
wgpanel-admin reset-password
```

If the wrapper is not in your shell path:

```bash
/opt/wgpanel/backend/.venv/bin/python /opt/wgpanel/backend/scripts/wgpanel_admin.py reset-password
```

## HTTPS Reverse Proxy

For production, bind WGPanel to `127.0.0.1`, set `WGPANEL_SECURE_COOKIES=true`, and use Caddy or Nginx in front.

Example Caddy reverse proxy:

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

For LAN testing only, HTTP is allowed with `WGPANEL_SECURE_COOKIES=false`.

## Uninstall

```bash
sudo ./scripts/uninstall-systemd.sh
```

The uninstall script leaves `/etc/wireguard` untouched by default. It asks separately before removing WireGuard configs and creates a backup first.

## Troubleshooting

- Check service logs: `journalctl -u wgpanel -f`
- Check health: `curl http://127.0.0.1:8080/healthz`
- Check WireGuard: `sudo wg show wg0`
- Check helper permission: `sudo -u wgpanel sudo -n -l`
- Check helper self-test: `sudo -u wgpanel sudo -n /usr/local/sbin/wgpanel-helper self-test`
- Check config readability: `sudo -u wgpanel test -r /etc/wireguard/wg0.conf`

## Manual Test Checklist

- Existing WireGuard install on a clean Debian VM.
- New WireGuard config install on a clean Debian VM.
- First-run browser setup.
- Password reset with `wgpanel-admin reset-password`.
- Uninstall without deleting WireGuard.
- Uninstall with WireGuard removal after confirming backup creation.
