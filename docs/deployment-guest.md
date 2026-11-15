# Guest VPN deployment (Stage 2)

Nothing in this procedure overwrites `wg0.conf`. Run it from a provider console
or with a second SSH session. Leave `WGPANEL_GUEST_ENABLED=false` until the
isolation tests pass.

## 1. Collect host facts

Run these on the VPS and retain the output. The config command redacts private
and preshared keys.

```bash
ip -br link
ip -4 -j route show table all
ip -6 -j route show table all
sudo wg show all allowed-ips
docker network ls
docker network inspect $(docker network ls -q)
sudo nft -a list ruleset
sudo ufw status verbose
sudo iptables-nft-save
sudo ss -lntup
sudo sed -E 's/^([[:space:]]*(PrivateKey|PresharedKey)[[:space:]]*=).*/\1 <redacted>/' /etc/wireguard/wg0.conf
```

The data needed before choosing defaults is: actual public uplink, every VPS
public IPv4 address, existing routes/WireGuard/Docker networks, nftables hook
priorities, UFW policy, Docker-published ports and the current `wg0` PostUp and
PostDown rules.

## 2. Install and run preflight only

```bash
sudo install -D -o root -g root -m 0755 scripts/guest_network_preflight.py /usr/local/lib/wgpanel/guest_network_preflight.py
sudo install -D -o root -g root -m 0755 scripts/wgpanel-guest-firewall /usr/local/sbin/wgpanel-guest-firewall
sudo install -D -o root -g root -m 0600 deploy/guest-firewall.env.example /etc/wgpanel/guest-firewall.env
sudoedit /etc/wgpanel/guest-firewall.env
sudo WGPANEL_GUEST_FIREWALL_CONFIG=/etc/wgpanel/guest-firewall.env /usr/local/sbin/wgpanel-guest-firewall check
```

Set `PUBLIC_UPLINK` and `VPS_PUBLIC_IPV4` to observed values. A collision is a
hard stop; choose another guest subnet and update both firewall and WGPanel
settings.

## 3. Create `wg1` without touching `wg0`

This writes a new file only if `wg1.conf` does not exist:

```bash
sudo test ! -e /etc/wireguard/wg1.conf
sudo sh -c 'umask 077; key=$(wg genkey); { printf "[Interface]\nPrivateKey = %s\nAddress = 10.10.20.1/24\nListenPort = 51821\n" "$key"; } > /etc/wireguard/wg1.conf'
sudo chmod 600 /etc/wireguard/wg1.conf
sudo wg-quick strip /etc/wireguard/wg1.conf >/dev/null
```

Do not add firewall mutations to `wg1` PostUp. The dedicated nftables service
owns one named table and replaces it atomically.

## 4. Install fail-closed service ordering

```bash
sudo install -D -o root -g root -m 0644 deploy/wgpanel-guest-firewall.service /etc/systemd/system/wgpanel-guest-firewall.service
sudo install -D -o root -g root -m 0644 deploy/wg-quick@wg1.service.d/10-wgpanel-guest-firewall.conf /etc/systemd/system/wg-quick@wg1.service.d/10-wgpanel-guest-firewall.conf
sudo systemctl daemon-reload
sudo systemctl enable --now wgpanel-guest-firewall.service
sudo nft -a list table inet wgpanel_guest
```

The firewall service has no automatic `ExecStop` removal. Stopping the service
therefore cannot silently make a still-running `wg1` fail open. Explicit
removal is allowed only during rollback after `wg1` is down.

Verify IPv4 forwarding is already enabled; do not replace unrelated sysctl
files:

```bash
sysctl net.ipv4.ip_forward
```

If it is `0`, create a dedicated sysctl drop-in, apply it, and recheck. Permit
UDP 51821 and the guest forwarding path using the host's existing UFW policy.
For the proposed `eth0` uplink the explicit rules are:

```bash
sudo ufw allow 51821/udp comment 'WGPanel guest WireGuard'
sudo ufw route allow in on wg1 out on eth0 from 10.10.20.0/24 to any comment 'WGPanel guest internet'
```

Substitute the observed uplink; do not add a second copy when an equivalent
rule already exists. Then start the interface:

```bash
sudo systemctl enable --now wg-quick@wg1
sudo wg show wg1 public-key
sudo wg show wg1
```

## 5. Update Compose configuration

Add the following to `.env`, using the public key printed above and the real
public endpoint:

```dotenv
WGPANEL_GUEST_ENABLED=false
WGPANEL_GUEST_INTERFACE=wg1
WGPANEL_GUEST_SERVER_ENDPOINT=VPN_PUBLIC_HOST:51821
WGPANEL_GUEST_SERVER_PUBLIC_KEY=WG1_PUBLIC_KEY
WGPANEL_GUEST_CLIENT_ADDRESS_POOL=10.10.20.0/24
WGPANEL_GUEST_SERVER_ADDRESS=10.10.20.1
WGPANEL_GUEST_CLIENT_DNS=1.1.1.1
```

The existing `/etc/wireguard:/etc/wireguard:rw` mount already includes
`wg1.conf`; no Docker socket or nftables capability is added. Rebuild and
restart only WGPanel:

```bash
docker compose build wgpanel
docker compose up -d wgpanel
```

After checking Diagnostics and the `wg1` interface in WGPanel, change only
`WGPANEL_GUEST_ENABLED=true` and recreate the WGPanel container. Create one
Guest client and save its one-time profile.

## 6. Isolation verification

Use two disposable guest clients plus an existing private client. Check nft
counters before and after every negative test:

```bash
sudo nft -a list table inet wgpanel_guest
sudo wg show wg1
```

Required results:

* guest public IPv4 and public DNS work;
* guest to `192.0.2.1`, `192.0.2.10`, every private peer,
  `198.51.100.0/24`, `203.0.113.0/24`, `203.0.113.128/25`, Docker networks,
  second guest, SSH and WGPanel fail;
* guest to the VPS public IPv4 on published/admin ports fails before DNAT;
* private peer, VPS host and private LAN cannot initiate a new flow to guest;
* manually assigned guest IPv6 cannot pass;
* existing `wg0` peer count, example-site prefixes, LAN route, NETMAP and
  site-to-site connectivity remain unchanged.

Do not call an unanswered ping sufficient: test TCP/UDP admin ports and inspect
the matching nft counter.

## Guest rollback

Disable Guest creation first, then stop the new interface. This does not touch
`wg0`:

```bash
# Set WGPANEL_GUEST_ENABLED=false in .env, then:
docker compose up -d wgpanel
sudo systemctl disable --now wg-quick@wg1
sudo /usr/local/sbin/wgpanel-guest-firewall remove
sudo systemctl disable wgpanel-guest-firewall.service
```

Keep `/etc/wireguard/wg1.conf` as a root-only rollback artifact unless its
removal is separately approved. Remove the UFW 51821 rule only after confirming
its exact numbered/rule identity. Never flush nftables, UFW or Docker rules as
a rollback shortcut.
