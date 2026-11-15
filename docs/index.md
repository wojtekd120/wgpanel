# WGPanel operations

WGPanel is a FastAPI and React control plane for an already-running WireGuard
interface. The SQLite database stores WGPanel metadata; the current
`/etc/wireguard/<interface>.conf` remains an input to every change and is not
blindly replaced from SQLite.

The safety rules are:

* never run `wg-quick down` as part of an ordinary peer change;
* preserve unmanaged peers, interface directives, comments and unknown peer
  directives;
* back up both SQLite and the real WireGuard config before a migration;
* apply runtime changes with `wg syncconf`, then atomically replace the file;
* keep server-side and client-side `AllowedIPs` as separate data.

See [Stage 1 deployment](deployment-stage1.md) before upgrading an existing
installation. Guest isolation is a separate security project; see
[Guest isolation design](guest-isolation.md).
