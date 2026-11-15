# Stage 1 deployment

These steps do not stop `wg0`. Keep a second SSH session or provider console
available. Substitute the actual release directory and timestamp.

## 1. Observe before changing

```bash
sudo wg show wg0 allowed-ips
ip -4 route show 198.51.100.0/24
sudo iptables-nft -t nat -S | grep -E 'NETMAP|192\.168\.(1|99)\.0/24'
docker compose ps
```

Record peer counts and identify example-site by its public key. Do not print
`wg0.conf`, because it contains private material.

## 2. Make explicit pre-upgrade backups

```bash
stamp="$(date -u +%Y%m%d-%H%M%S)"
sudo install -d -m 700 /etc/wireguard/backups
sudo install -o root -g root -m 600 /etc/wireguard/wg0.conf "/etc/wireguard/backups/wg0.conf.before-stage1.${stamp}.bak"
docker compose exec -T wgpanel python -c 'import os,sqlite3,time; s=sqlite3.connect("/var/lib/wgpanel/wgpanel.db"); p="/var/lib/wgpanel/backups/wgpanel.db.before-stage1.%d.bak"%time.time(); os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True); d=sqlite3.connect(p); s.backup(d); d.close(); s.close(); os.chmod(p,0o600)'
```

The command emits no keys. Confirm files and modes with `sudo stat` without
displaying their contents.

## 3. Build and start only WGPanel

```bash
git diff --check
docker compose build wgpanel
docker compose up -d wgpanel
docker compose ps
docker compose logs --tail=100 wgpanel
```

Starting the container runs the metadata migration. It does not apply a new
WireGuard config on startup. Inspect the peer in the UI: server-side AllowedIPs
must show `192.0.2.10/32, 198.51.100.0/24`.

## 4. Dry-run and first controlled mutation

Create a preview client first. Verify the redacted diff retains PostUp,
PostDown, unmanaged peers and both example-site prefixes. Then add one real test
client. Immediately verify:

```bash
sudo wg show wg0 allowed-ips
ip -4 route get 198.51.100.55
sudo iptables-nft -t nat -S | grep -E 'NETMAP|192\.168\.(1|99)\.0/24'
```

Compare peer counts with the baseline. Test the existing VPN and home-LAN path
from an authorized peer.

## 5. Persistence checks

Restart only WGPanel first:

```bash
docker compose restart wgpanel
```

Repeat the checks above. Restart `wg-quick@wg0` only from an out-of-band
console or when SSH is demonstrably not dependent on `wg0`:

```bash
sudo systemctl restart wg-quick@wg0
```

After that optional step, repeat AllowedIPs, route, NETMAP, peer-count and
end-to-end tests. A container restart and a WireGuard service restart are
different tests; do not claim the latter if it was skipped.
