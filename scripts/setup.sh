#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "This setup helper must run on Linux." >&2
  exit 1
fi

if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
elif command -v docker >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  echo "Docker Compose is required." >&2
  exit 1
fi

test -f /etc/wireguard/wg0.conf || { echo "/etc/wireguard/wg0.conf is missing." >&2; exit 1; }
sudo wg show wg0 >/dev/null || { echo "sudo wg show wg0 failed." >&2; exit 1; }

if [ -f .env ]; then
  printf ".env exists. Update it? [y/N] "
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Leaving .env unchanged."; exit 0 ;;
  esac
else
  cp .env.example .env
fi

printf "WireGuard interface [wg0]: "
read -r interface
interface=${interface:-wg0}

printf "Server endpoint, e.g. vpn.example.com:51820: "
read -r endpoint

default_key=""
if [ -f /etc/wireguard/server_public.key ]; then
  default_key="$(cat /etc/wireguard/server_public.key)"
fi
printf "Server public key [%s]: " "$default_key"
read -r server_key
server_key=${server_key:-$default_key}

printf "Admin username [admin]: "
read -r admin_user
admin_user=${admin_user:-admin}

printf "Admin password: "
stty -echo
read -r admin_password
stty echo
printf "\nConfirm admin password: "
stty -echo
read -r admin_confirm
stty echo
printf "\n"

if [ "$admin_password" != "$admin_confirm" ]; then
  echo "Passwords do not match." >&2
  exit 1
fi

if [ "${#admin_password}" -lt 12 ]; then
  echo "Password must be at least 12 characters." >&2
  exit 1
fi

hash="$(printf '%s\n%s\n' "$admin_password" "$admin_password" | python3 backend/scripts/hash_password.py --stdin | tail -n 1)"
unset admin_password admin_confirm

tmp=".env.tmp"
awk -F= -v i="$interface" -v e="$endpoint" -v k="$server_key" -v h="$hash" -v u="$admin_user" '
BEGIN {
  seen_i=seen_e=seen_k=seen_h=seen_u=0
}
$1=="WGPANEL_INTERFACE" { print "WGPANEL_INTERFACE=" i; seen_i=1; next }
$1=="WGPANEL_SERVER_ENDPOINT" { print "WGPANEL_SERVER_ENDPOINT=" e; seen_e=1; next }
$1=="WGPANEL_SERVER_PUBLIC_KEY" { print "WGPANEL_SERVER_PUBLIC_KEY=" k; seen_k=1; next }
$1=="WGPANEL_ADMIN_PASSWORD_HASH" { print "WGPANEL_ADMIN_PASSWORD_HASH=" h; seen_h=1; next }
$1=="WGPANEL_ADMIN_USERNAME" { print "WGPANEL_ADMIN_USERNAME=" u; seen_u=1; next }
{ print }
END {
  if (!seen_i) print "WGPANEL_INTERFACE=" i
  if (!seen_e) print "WGPANEL_SERVER_ENDPOINT=" e
  if (!seen_k) print "WGPANEL_SERVER_PUBLIC_KEY=" k
  if (!seen_h) print "WGPANEL_ADMIN_PASSWORD_HASH=" h
  if (!seen_u) print "WGPANEL_ADMIN_USERNAME=" u
}' .env > "$tmp"
mv "$tmp" .env
chmod 600 .env

echo "Setup complete. Next:"
echo "$COMPOSE up -d --build"
echo "$COMPOSE logs -f wgpanel"
echo "Open http://SERVER_IP:8080"
