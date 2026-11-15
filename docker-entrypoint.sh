#!/bin/sh
set -eu

if [ "${1:-}" = "hash-password" ]; then
  exec python /app/backend/scripts/hash_password.py
fi

if [ "${1:-}" = "wgpanel-admin" ]; then
  shift
  exec wgpanel-admin "$@"
fi

mkdir -p /var/lib/wgpanel/backups /run/wgpanel
chown wgpanel:wgpanel /var/lib/wgpanel /var/lib/wgpanel/backups /run/wgpanel
chmod 750 /var/lib/wgpanel /run/wgpanel
chmod 700 /var/lib/wgpanel/backups

mkdir -p /etc/wireguard
chown root:wgpanel /etc/wireguard
chmod 750 /etc/wireguard
mkdir -p /etc/wireguard/backups
chown root:wgpanel /etc/wireguard/backups
chmod 750 /etc/wireguard/backups

wg_interface="${WGPANEL_INTERFACE:-wg0}"
guest_interface="${WGPANEL_GUEST_INTERFACE:-wg1}"
for configured_interface in "$wg_interface" "$guest_interface"; do
  wg_config="/etc/wireguard/${configured_interface}.conf"
  if [ -f "$wg_config" ]; then
    chown root:wgpanel "$wg_config"
    chmod 640 "$wg_config"
  fi
done

if [ ! -c /dev/net/tun ]; then
  echo "warning: /dev/net/tun is not available; WireGuard operations may fail" >&2
fi

export WGPANEL_IN_DOCKER=true
exec sudo -E -u wgpanel /opt/venv/bin/uvicorn app.main:app --host "${WGPANEL_HOST:-0.0.0.0}" --port "${WGPANEL_PORT:-8080}"
