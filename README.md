# WGPanel

Self-hosted WireGuard admin panel for Ubuntu/Debian.

## Stack

- FastAPI backend
- React + Vite + Tailwind frontend
- SQLite metadata store
- WireGuard interface `wg0`
- WireGuard config `/etc/wireguard/wg0.conf`

## Security model

The backend must run as an unprivileged `wgpanel` user. It never runs arbitrary shell commands and all subprocess calls use argv arrays. The backend can read `/etc/wireguard/wg0.conf`, generate a complete candidate config under `/run/wgpanel`, then call only:

```bash
sudo /usr/local/sbin/wgpanel-helper apply --config /run/wgpanel/<file>.conf
```

The helper is root-owned and validates that config paths are under `/run/wgpanel` before calling `wg-quick strip` and `wg syncconf wg0`. Private client keys are returned once in the create response and are not stored in SQLite.

## Local development

Backend:

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
WGPANEL_SECURE_COOKIES=false uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Generate admin password hash

```bash
cd backend
. .venv/bin/activate
python scripts/hash_password.py
```

Put the printed value in `/etc/wgpanel/wgpanel.env` as `WGPANEL_ADMIN_PASSWORD_HASH`.

## Production install

### Docker Compose

This is the recommended production path when you want WGPanel containerized while still managing the host WireGuard interface. The Compose service uses `network_mode: host`, `cap_add: NET_ADMIN`, and `/dev/net/tun` so `wg show wg0 dump`, `wg-quick strip`, and `wg syncconf wg0` operate against the host network namespace. It does not add `SYS_MODULE` by default.

Install Docker Engine, Docker Compose V2, and WireGuard on the Ubuntu/Debian host first. The host should already be able to run `sudo wg show wg0` before WGPanel starts.

Run this preflight on the host:

```bash
docker compose version
test -c /dev/net/tun
sudo test -f /etc/wireguard/wg0.conf
sudo wg show wg0
```

Then create `.env`:

```bash
cp .env.example .env
```

Set at least these values:

```dotenv
WGPANEL_SERVER_ENDPOINT=vpn.example.com:51820
WGPANEL_SERVER_PUBLIC_KEY=your_server_public_key
WGPANEL_ADMIN_PASSWORD_HASH=your_password_hash
```

Generate the password hash without keeping the password in shell history:

```bash
docker compose build wgpanel
docker compose run --rm --entrypoint python wgpanel scripts/hash_password.py
```

Build and start WGPanel:

```bash
docker compose build
docker compose up -d --build
```

Watch startup logs:

```bash
docker compose logs -f
```

Check WireGuard visibility from the running container:

```bash
docker compose exec wgpanel wg show wg0
```

The app listens on `127.0.0.1:8080` by default through host networking. Put it behind HTTPS with Nginx or Caddy and keep `WGPANEL_SECURE_COOKIES=true`.

The Compose file stores SQLite data in the `wgpanel-data` Docker volume, bind mounts host `/etc/wireguard` read/write, and uses a tmpfs at `/run/wgpanel` for generated candidate configs. The container does not use `privileged: true`. The image grants `cap_net_admin` only to `/usr/bin/wg` so the unprivileged FastAPI process can read `wg show wg0 dump`; config application still goes through the sudo-limited helper.

On startup, the container changes the group of `/etc/wireguard/wg0.conf` to `wgpanel` and grants group read permission so the non-root app can read the bind-mounted host config. After applying a new config, the helper keeps `/etc/wireguard/wg0.conf` root-owned with group `wgpanel` and mode `0640`.

Useful verification commands:

```bash
cp .env.example .env
docker compose build
docker compose run --rm --entrypoint python wgpanel scripts/hash_password.py
docker compose up -d
docker compose logs -f
docker compose exec wgpanel wg show wg0
docker compose exec wgpanel wg show wg0 dump
docker compose exec wgpanel sudo /usr/local/sbin/wgpanel-helper --help
```

### Docker troubleshooting

If `/dev/net/tun` is missing, load the kernel module and confirm the device exists:

```bash
sudo modprobe tun
ls -l /dev/net/tun
```

Do this on the host whenever possible. Do not add `SYS_MODULE` to the container by default. Only use `SYS_MODULE` as an exceptional fallback on tightly controlled systems where you intentionally need the container to load kernel modules, and remove it again after fixing host WireGuard availability.

If WireGuard commands fail with an operation-not-permitted error, confirm the Compose service has `cap_add: NET_ADMIN` and was recreated after changes:

```bash
docker compose up -d --force-recreate
docker compose exec wgpanel wg show wg0
```

If `wg0` does not exist, bring up the host interface before starting WGPanel:

```bash
sudo apt-get update
sudo apt-get install wireguard wireguard-tools
sudo systemctl enable --now wg-quick@wg0
sudo wg show wg0
```

If login succeeds but the browser does not keep the session behind a reverse proxy, make sure the public site is HTTPS when `WGPANEL_SECURE_COOKIES=true`. For plain local HTTP testing only, set:

```dotenv
WGPANEL_SECURE_COOKIES=false
```

### Systemd without Docker

```bash
sudo adduser --system --group --home /var/lib/wgpanel wgpanel
sudo mkdir -p /opt/wgpanel /etc/wgpanel /var/lib/wgpanel /run/wgpanel
sudo chown wgpanel:wgpanel /var/lib/wgpanel /run/wgpanel
sudo chmod 750 /var/lib/wgpanel /run/wgpanel
```

Copy this repository to `/opt/wgpanel`, then install backend dependencies:

```bash
cd /opt/wgpanel/backend
sudo -u wgpanel python3 -m venv .venv
sudo -u wgpanel .venv/bin/pip install -r requirements.txt
```

Build the frontend:

```bash
cd /opt/wgpanel/frontend
npm install
npm run build
```

Install the helper:

```bash
sudo install -o root -g root -m 0750 helper/wgpanel-helper /usr/local/sbin/wgpanel-helper
```

Install sudoers:

```bash
sudo cp backend/apply_sudoers.example /etc/sudoers.d/wgpanel
sudo chmod 0440 /etc/sudoers.d/wgpanel
sudo visudo -cf /etc/sudoers.d/wgpanel
```

Create `/etc/wgpanel/wgpanel.env` from `deploy/wgpanel.env.example`, then set the real endpoint, server public key, and password hash.

Install and start systemd service:

```bash
sudo cp deploy/wgpanel.service /etc/systemd/system/wgpanel.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgpanel
```

Serve `127.0.0.1:8080` behind Nginx/Caddy with HTTPS. Keep `WGPANEL_SECURE_COOKIES=true` in production.

## API behavior

- `GET /healthz` returns a simple unauthenticated health response for container and reverse-proxy checks.
- Dashboard reads live status from `wg show wg0 dump`.
- Peer metadata is stored in SQLite: name, public key, assigned IP, created time, disabled flag, optional expiry.
- New clients receive the next free IP from `10.8.0.0/24`, skipping `10.8.0.1`.
- Peer names, WireGuard keys, IPs, and CIDRs are validated. Names containing shell metacharacters are rejected.
- Dry-run peer creation renders the server/client config and QR code but does not persist metadata or apply WireGuard changes.

## Tests

```bash
cd backend
. .venv/bin/activate
pytest
```
