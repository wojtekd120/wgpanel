#!/usr/bin/env sh
set -eu

say() { printf '\n==> %s\n' "$*"; }
ask() {
  prompt="$1"
  default="$2"
  printf '%s [%s]: ' "$prompt" "$default"
  read -r value
  printf '%s' "${value:-$default}"
}

if [ "$(uname -s)" != "Linux" ]; then
  echo "This installer is for Linux hosts." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed. Install docker.io and docker-compose first, or run the manual README steps." >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
fi

iface="$(ask 'WireGuard interface' 'wg0')"
endpoint="$(ask 'Server endpoint, for example vpn.example.com:51820' '')"
default_pub=""
if [ -f /etc/wireguard/server_public.key ]; then
  default_pub="$(cat /etc/wireguard/server_public.key)"
fi
server_public="$(ask 'Server public key' "$default_pub")"
secure="$(ask 'Secure cookies? Use false for LAN HTTP testing, true behind HTTPS' 'false')"

tmp="$(mktemp)"
awk -v iface="$iface" -v endpoint="$endpoint" -v pub="$server_public" -v secure="$secure" '
  BEGIN { seen_iface=seen_endpoint=seen_pub=seen_secure=0 }
  /^WGPANEL_INTERFACE=/ { print "WGPANEL_INTERFACE=" iface; seen_iface=1; next }
  /^WGPANEL_SERVER_ENDPOINT=/ { print "WGPANEL_SERVER_ENDPOINT=" endpoint; seen_endpoint=1; next }
  /^WGPANEL_SERVER_PUBLIC_KEY=/ { print "WGPANEL_SERVER_PUBLIC_KEY=" pub; seen_pub=1; next }
  /^WGPANEL_SECURE_COOKIES=/ { print "WGPANEL_SECURE_COOKIES=" secure; seen_secure=1; next }
  { print }
  END {
    if (!seen_iface) print "WGPANEL_INTERFACE=" iface
    if (!seen_endpoint) print "WGPANEL_SERVER_ENDPOINT=" endpoint
    if (!seen_pub) print "WGPANEL_SERVER_PUBLIC_KEY=" pub
    if (!seen_secure) print "WGPANEL_SECURE_COOKIES=" secure
  }
' .env > "$tmp"
mv "$tmp" .env

say "Starting WGPanel"
if docker compose version >/dev/null 2>&1; then
  docker compose up -d --build
else
  docker-compose up -d --build
fi

say "Open WGPanel and create the first admin in your browser"
echo "http://SERVER_IP:8080"
