# Advanced Install

## Systemd Without Docker

Create the unprivileged user:

```bash
sudo adduser --system --group --home /var/lib/wgpanel wgpanel
sudo mkdir -p /opt/wgpanel /etc/wgpanel /var/lib/wgpanel /run/wgpanel
sudo chown wgpanel:wgpanel /var/lib/wgpanel /run/wgpanel
sudo chmod 750 /var/lib/wgpanel /run/wgpanel
```

Install backend dependencies and build the frontend, then install `deploy/wgpanel.service`.

## Reverse Proxy

For production, serve WGPanel behind HTTPS with Caddy or Nginx and keep:

```dotenv
WGPANEL_SECURE_COOKIES=true
```

## Docker Capabilities

The Docker service uses:

- `network_mode: host`
- `build.network: host`
- `cap_add: NET_ADMIN`
- `/dev/net/tun`
- `/etc/wireguard:/etc/wireguard:rw`

It does not use `privileged: true` and does not add `SYS_MODULE` by default. WireGuard should be installed and loaded on the host.

## Helper And Sudoers

FastAPI runs as `wgpanel`. The root-owned helper applies configs:

```text
/usr/local/sbin/wgpanel-helper apply --interface <name> --config /run/wgpanel/<file>.conf
```

The helper validates the interface name and candidate config path before calling `wg-quick strip` and `wg syncconf`.

## Production Hardening

- Keep `.env` mode `0600`.
- Keep `/etc/wireguard/*.conf` non-world-readable.
- Restrict access to the web UI with HTTPS and firewall rules.
- Review `/etc/wireguard/backups` periodically.
