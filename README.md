# WGPanel

**Version:** `0.1.3-beta`

WGPanel is a self-hosted web UI for managing WireGuard peers.

**Beta warning:** This is beta software. Test on a VM or backup your WireGuard config before using on an important server.

WGPanel is designed to preserve existing WireGuard peers. Existing peers are shown as unmanaged until imported or taken over. WGPanel should only modify peers it manages. See [README_EXISTING_WIREGUARD.md](README_EXISTING_WIREGUARD.md).

## What WGPanel Does

- Shows WireGuard interface status, latest handshakes, RX/TX, and peers.
- Creates WireGuard client peers and allocates the next free VPN IP.
- Shows generated client config and QR code once.
- Enables, disables, deletes, and edits metadata for managed peers.
- Preserves unmanaged existing peers.
- Supports multiple interfaces such as `wg0`, `wg1`, `wg-test`, `homevpn`.
- Creates backups before applying config changes.

## What WGPanel Does Not Do

- It does not store generated client private keys.
- It does not expose the server private key.
- It does not manage arbitrary config paths from the UI.
- It does not provide speed/data limits. WireGuard has no native per-peer speed/data limit; future support would require `tc`/`nftables`.
- It is not a replacement for host WireGuard installation.

## Requirements

- Debian/Ubuntu server
- Docker and Docker Compose
- WireGuard already installed on the host
- A working host interface, usually `wg0`
- Existing config at `/etc/wireguard/wg0.conf`

## Quick Start: Docker Compose

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose wireguard wireguard-tools
sudo systemctl enable --now docker

git clone https://github.com/wojtekd120/wgpanel.git
cd wgpanel

cp .env.example .env
```

Edit `.env`. Minimum values:

```dotenv
WGPANEL_INTERFACE=wg0
WGPANEL_WG_CONFIG=/etc/wireguard/wg0.conf
WGPANEL_SERVER_ENDPOINT=YOUR_SERVER_IP_OR_DOMAIN:51820
WGPANEL_SERVER_PUBLIC_KEY=YOUR_SERVER_PUBLIC_KEY
WGPANEL_SECURE_COOKIES=false
```

Use `WGPANEL_SECURE_COOKIES=false` for local HTTP testing. Use `WGPANEL_SECURE_COOKIES=true` behind HTTPS in production.

Back up your config before first start:

```bash
sudo mkdir -p /root/wgpanel-backups
sudo cp /etc/wireguard/wg0.conf /root/wgpanel-backups/wg0.conf.before-wgpanel.$(date +%Y%m%d-%H%M%S)
```

Run preflight checks:

```bash
./scripts/preflight.sh
```

Start WGPanel:

```bash
docker-compose up -d --build
docker-compose logs -f wgpanel
```

Open:

```text
http://SERVER_IP:8080
```

On first run, WGPanel prints a setup URL in the logs. Open it and create the admin account. Beginners do not need to manually generate a password hash.

## First Login

If setup mode is active, get the token with:

```bash
docker-compose logs wgpanel
docker-compose exec wgpanel cat /var/lib/wgpanel/setup-token
```

Reset an admin password from the server shell:

```bash
docker-compose exec wgpanel wgpanel-admin reset-password
```

If the setup token expired:

```bash
docker-compose exec wgpanel wgpanel-admin create-setup-token
```

Advanced password hash generation is still available:

```bash
docker-compose run --rm wgpanel hash-password
./scripts/generate-admin-password.sh
```

## Add Your First Client

1. Log in.
2. Choose the WireGuard interface in the top bar.
3. Click New Client.
4. Choose split tunnel, full tunnel, or custom AllowedIPs.
5. Save the generated config or QR code immediately.

The private key is shown only once and cannot be recovered later.

The dashboard includes an onboarding checklist with pass/warn/fail checks and fix commands for common host setup issues. It also works on phone-sized screens with stacked cards and wrapped keys/config blocks.

For cautious changes, use **Preview changes** under the new-client form. It shows generated config output without modifying `/etc/wireguard/<interface>.conf` and without running `wg syncconf`.

Mobile UI manual check: open browser devtools at `360px`, `390px`, `430px`, `768px`, and desktop widths. The dashboard cards should stack, peer rows should become cards, forms should be single-column, and QR/config blocks should stay inside the viewport.

## Existing WireGuard Server Safety

WGPanel reads the current `/etc/wireguard/<interface>.conf` before every apply. It preserves unmanaged peer blocks, comments, `PostUp`, `PostDown`, routes, and interface settings. WGPanel never accepts arbitrary config paths from the UI; interface `wg1` maps only to `/etc/wireguard/wg1.conf`.

## Backup And Restore Basics

WGPanel also creates timestamped backups under `/etc/wireguard/backups` before real applies.

Manual restore:

```bash
sudo cp /root/wgpanel-backups/<backup-file> /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

WGPanel backup restore:

```bash
sudo cp /etc/wireguard/backups/<backup-file> /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

## Troubleshooting

**Cannot connect to Docker daemon**

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Log out and log back in.

**docker-compose build cannot reach deb.debian.org**

The Compose file uses `build.network: host`. Check VM internet/NAT and DNS.

**Permission denied: /etc/wireguard/wg0.conf**

Expected permissions:

```text
/etc/wireguard root:wgpanel 750
/etc/wireguard/wg0.conf root:wgpanel 640
```

The Docker entrypoint should fix this. Never use `chmod 644` because `wg0.conf` contains the server private key.

**No module named app**

Use the supported command:

```bash
docker-compose run --rm wgpanel hash-password
```

**I cannot open the panel**

WGPanel uses host networking. Open `http://SERVER_IP:8080`, check firewall rules, or use an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@server
```

## Easy Test Mode

For local HTTP testing:

```dotenv
WGPANEL_SECURE_COOKIES=false
```

No reverse proxy is required. Use `http://SERVER_IP:8080`.

For production:

```dotenv
WGPANEL_SECURE_COOKIES=true
```

Put WGPanel behind HTTPS with Caddy or Nginx. Do not expose plain HTTP to the internet.

## Changing WireGuard Interface

`wg0` is the default. WGPanel discovers interfaces from `wg show interfaces` and `/etc/wireguard/*.conf`. Use the top-bar selector to switch interfaces. Supported names include `wg0`, `wg1`, `wg-test`, `homevpn`, and `wg.prod`.

WGPanel never accepts arbitrary config paths from the UI.

## License

WGPanel is released under the [MIT License](LICENSE).

## Advanced Docs

- [README_EXISTING_WIREGUARD.md](README_EXISTING_WIREGUARD.md)
- [SECURITY.md](SECURITY.md)
- [ADVANCED_INSTALL.md](ADVANCED_INSTALL.md)
- [CHANGELOG.md](CHANGELOG.md)
