#!/bin/sh
set -eu

if [ "${1:-}" = "hash-password" ]; then
  exec python /app/backend/scripts/hash_password.py
fi

if [ "${1:-}" = "wgpanel-admin" ]; then
  shift
  exec wgpanel-admin "$@"
fi

mkdir -p /var/lib/wgpanel /run/wgpanel
chown wgpanel:wgpanel /var/lib/wgpanel /run/wgpanel
chmod 750 /var/lib/wgpanel /run/wgpanel

mkdir -p /etc/wireguard
chown root:wgpanel /etc/wireguard
chmod 750 /etc/wireguard
mkdir -p /etc/wireguard/backups
chown root:wgpanel /etc/wireguard/backups
chmod 750 /etc/wireguard/backups

if [ -f /etc/wireguard/wg0.conf ]; then
  chown root:wgpanel /etc/wireguard/wg0.conf
  chmod 640 /etc/wireguard/wg0.conf
fi

if [ ! -c /dev/net/tun ]; then
  echo "warning: /dev/net/tun is not available; WireGuard operations may fail" >&2
fi

exec sudo -E -u wgpanel /opt/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${WGPANEL_PORT:-8080}"
