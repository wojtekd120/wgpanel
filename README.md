# WGPanel

**Version:** `0.1.5-beta`

WGPanel is a self-hosted web UI for managing WireGuard peers.

**Beta warning:** Test on a VM or back up your WireGuard config before using WGPanel on an important server.

WGPanel is designed to preserve existing WireGuard peers. Existing peers are shown as unmanaged until imported or taken over. WGPanel should only modify peers it manages. See [README_EXISTING_WIREGUARD.md](README_EXISTING_WIREGUARD.md).

## What WGPanel Does

- Shows WireGuard interface status, latest handshakes, RX/TX, and peer activity.
- Creates WireGuard client peers and allocates the next free VPN IP.
- Shows generated client config and QR code once.
- Enables, disables, deletes, and edits metadata for managed peers.
- Preserves unmanaged existing peers.
- Supports multiple interfaces such as `wg0`, `wg1`, `wg-test`, and `homevpn`.
- Creates backups before applying config changes.

## What WGPanel Does Not Do

- It does not store generated client private keys.
- It does not expose the server private key.
- It does not manage arbitrary WireGuard config paths from the UI.
- It does not provide speed/data limits. WireGuard has no native per-peer speed/data limit; future support would require `tc`/`nftables`.
- It is not a replacement for installing WireGuard on the host.

## Quick Start: Docker Compose

1. Install dependencies:

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose wireguard wireguard-tools
sudo systemctl enable --now docker
```

2. Clone WGPanel:

```bash
git clone https://github.com/wojtekd120/wgpanel.git
cd wgpanel
```

3. Create `.env`:

```bash
cp .env.example .env
nano .env
```

Minimum values:

```dotenv
WGPANEL_INTERFACE=wg0
WGPANEL_SERVER_ENDPOINT=YOUR_SERVER_IP_OR_DOMAIN:51820
WGPANEL_SERVER_PUBLIC_KEY=YOUR_SERVER_PUBLIC_KEY
WGPANEL_SECURE_COOKIES=false
```

4. Start:

```bash
docker compose up -d --build
```

5. Open:

```text
http://SERVER_IP:8080
```

On first visit, WGPanel redirects to `/setup`. Create the admin username and password in the browser. No setup token or manual password hash is needed for normal installs.

## First Login And Recovery

After browser setup, sign in with the admin user you created.

Reset the admin password from the server shell:

```bash
docker compose exec wgpanel wgpanel-admin reset-password
```

Advanced password hash generation remains available:

```bash
docker compose run --rm wgpanel hash-password
```

Backend development/test dependencies are installed with:

```bash
cd backend
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Existing WireGuard Safety

Before first start, make your own backup too:

```bash
sudo mkdir -p /root/wgpanel-backups
sudo cp /etc/wireguard/wg0.conf /root/wgpanel-backups/wg0.conf.before-wgpanel.$(date +%Y%m%d-%H%M%S)
```

WGPanel reads `/etc/wireguard/<interface>.conf` before every apply and preserves unmanaged peer blocks, comments, `PostUp`, `PostDown`, routes, and interface settings.

## Diagnostics And Backups

The dashboard shows a compact system-check summary. Open **Diagnostics** for grouped WireGuard, config, backup, helper/sudo, HTTPS, and runtime checks with Docker-aware fix commands and copy buttons.

The helper/sudo check safely runs the restricted helper self-test. It does not modify live WireGuard config. If peer apply works but Diagnostics shows a warning, click **Recheck** and inspect `docker compose logs wgpanel`.

Open **Backups** to list backups, create a backup now, view redacted diffs, download redacted backup text, or restore after typing `RESTORE <interface>`.

## Mobile UI

WGPanel is mobile-friendly: dashboard cards stack, peer rows become cards, long keys/config blocks wrap, and Diagnostics/Backups are readable on small screens.

Manual mobile check widths: `360px`, `390px`, `430px`, `768px`, and desktop.

## HTTPS

For local/LAN HTTP testing:

```dotenv
WGPANEL_HOST=0.0.0.0
WGPANEL_SECURE_COOKIES=false
```

For production, put WGPanel behind HTTPS with Caddy or Nginx:

```dotenv
WGPANEL_HOST=127.0.0.1
WGPANEL_SECURE_COOKIES=true
```

Do not expose plain HTTP WGPanel to the public internet.

## Install Without Docker

Docker Compose is the recommended easiest path. Native systemd installation is available for users who prefer not to run Docker:

```bash
sudo ./scripts/install-systemd.sh
```

See [INSTALL_SYSTEMD.md](INSTALL_SYSTEMD.md).

## Troubleshooting

**Cannot connect to Docker daemon**

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Log out and log back in.

**docker compose build cannot reach deb.debian.org**

The Compose file uses `build.network: host`. Check VM internet/NAT and DNS.

**Permission denied: /etc/wireguard/wg0.conf**

The Docker entrypoint should fix permissions inside the container. Open **Diagnostics** for the correct Docker-aware command. Never use `chmod 644`; `wg0.conf` contains the server private key.

**I cannot open the panel**

WGPanel uses host networking. Open `http://SERVER_IP:8080`, check firewall rules, or use an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@server
```

## Advanced Docs

- [README_EXISTING_WIREGUARD.md](README_EXISTING_WIREGUARD.md)
- [SECURITY.md](SECURITY.md)
- [ADVANCED_INSTALL.md](ADVANCED_INSTALL.md)
- [INSTALL_SYSTEMD.md](INSTALL_SYSTEMD.md)
- [CHANGELOG.md](CHANGELOG.md)

## License

WGPanel is released under the [MIT License](LICENSE).
