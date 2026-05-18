#!/usr/bin/env bash
set -euo pipefail

say() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
confirm() { read -r -p "$1 [y/N]: " ans; [[ "$ans" == "y" || "$ans" == "Y" ]]; }
ask() {
  local prompt="$1" default="$2" value
  read -r -p "$prompt [$default]: " value
  printf '%s' "${value:-$default}"
}
need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "run this script with sudo: sudo ./scripts/install-systemd.sh"
  fi
}

need_root
[[ -f /etc/os-release ]] || die "cannot detect OS"
. /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *debian* ]] || die "Debian/Ubuntu required"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

say "WGPanel native systemd installer"
install_path="$(ask 'Install path' '/opt/wgpanel')"
data_dir="$(ask 'Data directory' '/var/lib/wgpanel')"
config_dir="$(ask 'Config directory' '/etc/wgpanel')"
runtime_dir="$(ask 'Runtime directory' '/run/wgpanel')"
wgpanel_user="$(ask 'WGPanel user' 'wgpanel')"
host="$(ask 'WGPanel host' '127.0.0.1')"
port="$(ask 'WGPanel port' '8080')"
interface="$(ask 'WireGuard interface' 'wg0')"

say "WireGuard setup"
echo "1. Yes, use existing interface/config"
echo "2. No, create a new WireGuard config"
echo "3. Skip WireGuard setup and only install WGPanel"
read -r -p "Choose [1]: " wg_mode
wg_mode="${wg_mode:-1}"

if confirm "Install missing packages with apt now?"; then
  apt update
  apt install -y git sudo python3 python3-venv nodejs npm wireguard wireguard-tools curl rsync
fi

[[ -c /dev/net/tun ]] || die "/dev/net/tun is missing. Load/install WireGuard support on the host first."

wg_config="/etc/wireguard/${interface}.conf"
client_pool="10.8.0.0/24"
server_address="10.8.0.1"
listen_port="51820"
endpoint="$(ask 'Public WireGuard endpoint' "vpn.example.com:${listen_port}")"
client_dns="$(ask 'Client DNS' '1.1.1.1')"
server_public_key=""

mkdir -p /etc/wireguard/backups
chmod 700 /etc/wireguard/backups

if [[ "$wg_mode" == "1" ]]; then
  [[ -f "$wg_config" ]] || die "$wg_config does not exist"
  backup="/etc/wireguard/backups/${interface}.conf.before-wgpanel.$(date +%Y%m%d-%H%M%S).bak"
  cp -a "$wg_config" "$backup"
  chmod 600 "$backup"
  if ! wg show "$interface" >/dev/null 2>&1; then
    if confirm "$interface is not active. Start wg-quick@${interface}?"; then
      systemctl enable --now "wg-quick@${interface}"
    fi
  fi
  server_public_key="$(awk -F= '/^PrivateKey[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$wg_config" | wg pubkey 2>/dev/null || true)"
  say "Existing peers remain unmanaged until imported."
elif [[ "$wg_mode" == "2" ]]; then
  client_pool="$(ask 'VPN subnet' '10.8.0.0/24')"
  server_address="$(ask 'Server VPN address' '10.8.0.1')"
  listen_port="$(ask 'WireGuard UDP listen port' '51820')"
  endpoint="$(ask 'Public WireGuard endpoint' "vpn.example.com:${listen_port}")"
  client_dns="$(ask 'Client DNS' '1.1.1.1')"
  if [[ -f "$wg_config" ]]; then
    confirm "$wg_config exists. Back it up and overwrite?" || die "not overwriting existing config"
    cp -a "$wg_config" "/etc/wireguard/backups/${interface}.conf.before-overwrite.$(date +%Y%m%d-%H%M%S).bak"
  fi
  private_key="$(wg genkey)"
  server_public_key="$(printf '%s\n' "$private_key" | wg pubkey)"
  umask 077
  cat > "$wg_config" <<EOF_CONF
[Interface]
PrivateKey = $private_key
Address = ${server_address}/24
ListenPort = ${listen_port}
EOF_CONF
  chmod 600 "$wg_config"
  systemctl enable --now "wg-quick@${interface}"
else
  [[ -f "$wg_config" ]] && server_public_key="$(awk -F= '/^PrivateKey[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$wg_config" | wg pubkey 2>/dev/null || true)"
fi

server_public_key="$(ask 'Server public key' "$server_public_key")"
secure_cookies="$(ask 'Secure cookies? true behind HTTPS, false for local HTTP' 'true')"

say "Installing WGPanel files"
id "$wgpanel_user" >/dev/null 2>&1 || adduser --system --group --home "$data_dir" "$wgpanel_user"
mkdir -p "$install_path" "$config_dir" "$data_dir" "$runtime_dir"
rsync -a --delete --exclude .git ./ "$install_path/"
chown -R "$wgpanel_user:$wgpanel_user" "$data_dir" "$runtime_dir"
chown root:"$wgpanel_user" "$config_dir"
chmod 750 "$config_dir" "$data_dir" "$runtime_dir"

say "Installing backend"
python3 -m venv "$install_path/backend/.venv"
"$install_path/backend/.venv/bin/pip" install -r "$install_path/backend/requirements.txt"

say "Building frontend"
(cd "$install_path/frontend" && npm install && npm run build)

say "Installing helper and sudoers"
install -o root -g root -m 0750 "$install_path/helper/wgpanel-helper" /usr/local/sbin/wgpanel-helper
install -o root -g root -m 0440 "$install_path/backend/apply_sudoers.example" /etc/sudoers.d/wgpanel
visudo -cf /etc/sudoers.d/wgpanel

say "Writing environment"
cat > "$config_dir/wgpanel.env" <<EOF_ENV
WGPANEL_INTERFACE=${interface}
WGPANEL_WG_CONFIG=/etc/wireguard/${interface}.conf
WGPANEL_HOST=${host}
WGPANEL_PORT=${port}
WGPANEL_DB_PATH=${data_dir}/wgpanel.sqlite3
WGPANEL_RUNTIME_DIR=${runtime_dir}
WGPANEL_SERVER_ENDPOINT=${endpoint}
WGPANEL_SERVER_PUBLIC_KEY=${server_public_key}
WGPANEL_CLIENT_ADDRESS_POOL=${client_pool}
WGPANEL_SERVER_ADDRESS=${server_address}
WGPANEL_CLIENT_DNS=${client_dns}
WGPANEL_SECURE_COOKIES=${secure_cookies}
WGPANEL_AUTO_DISABLE_EXPIRED=false
EOF_ENV
chown root:"$wgpanel_user" "$config_dir/wgpanel.env"
chmod 640 "$config_dir/wgpanel.env"

say "Installing systemd service"
cat > /etc/systemd/system/wgpanel.service <<EOF_SERVICE
[Unit]
Description=WGPanel WireGuard admin panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${wgpanel_user}
Group=${wgpanel_user}
WorkingDirectory=${install_path}/backend
EnvironmentFile=${config_dir}/wgpanel.env
Environment=PYTHONPATH=${install_path}/backend
ExecStart=${install_path}/backend/.venv/bin/uvicorn app.main:app --host \${WGPANEL_HOST} --port \${WGPANEL_PORT}
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectHome=true
ReadWritePaths=${data_dir} ${runtime_dir} /etc/wireguard
RuntimeDirectory=wgpanel
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
EOF_SERVICE
systemctl daemon-reload
systemctl enable --now wgpanel

if confirm "Configure HTTPS reverse proxy now?"; then
  echo "Caddy is recommended. Install Caddy and reverse proxy to 127.0.0.1:${port}."
fi

say "Verification"
systemctl status wgpanel --no-pager || true
curl -fsS "http://127.0.0.1:${port}/healthz" || true
wg show "$interface" || true
sudo -u "$wgpanel_user" test -r "$wg_config" && echo "config readable by wgpanel"
sudo -u "$wgpanel_user" sudo -n -l || true

say "Open WGPanel and create the first admin in your browser"
if [[ "$host" == "127.0.0.1" ]]; then
  echo "http://127.0.0.1:${port}"
else
  echo "http://SERVER_IP:${port}"
fi
