#!/bin/sh
set -eu

mkdir -p /var/lib/wgpanel /run/wgpanel
chown wgpanel:wgpanel /var/lib/wgpanel /run/wgpanel
chmod 750 /var/lib/wgpanel /run/wgpanel

if [ -f /etc/wireguard/wg0.conf ]; then
  chgrp wgpanel /etc/wireguard/wg0.conf
  chmod g+r /etc/wireguard/wg0.conf
fi

if [ ! -c /dev/net/tun ]; then
  echo "warning: /dev/net/tun is not available; WireGuard operations may fail" >&2
fi

exec sudo -E -u wgpanel /opt/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${WGPANEL_PORT:-8080}"
