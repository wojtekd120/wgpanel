# Architecture

## Runtime and persistence

Docker Compose uses host networking and mounts `/etc/wireguard` read/write.
Application data is in the `wgpanel-data` named volume at
`/var/lib/wgpanel`. Candidate configs live in the tmpfs at `/run/wgpanel` and
are mode `0600`.

The unprivileged FastAPI process reads the current config and prepares a
candidate. A restricted root helper:

1. validates the candidate with `wg-quick strip`;
2. captures `wg showconf` into a private temporary rollback file;
3. creates a root-only `0600` backup of the real config;
4. calls `wg syncconf` without stopping the interface;
5. atomically replaces `/etc/wireguard/<interface>.conf`;
6. restores the previous runtime config if the atomic replace fails.

The helper exposes only redacted backup content to the web process. Full
backups remain root-only. Database schema migration uses SQLite's online
backup API and writes a `0600` backup below the database directory.

## Configuration ownership

WGPanel owns only peers present in SQLite with `managed = 1`, plus tombstones
for peers explicitly deleted through WGPanel. Other peer blocks are preserved.
For an existing managed peer, WGPanel changes only its active `AllowedIPs`
line. `PresharedKey`, `Endpoint`, `PersistentKeepalive`, comments and unknown
directives round-trip unchanged.

Disabling a managed peer removes it from the stripped runtime configuration
but retains its full section as a marked, commented block in the persistent
file. Re-enabling restores that block, including preshared key and unknown
directives. Redacted previews and backup downloads mask secrets in both active
and disabled blocks.

This policy deliberately treats the current config and migrated database
metadata together as the source of truth. On first startup after the schema
upgrade, an empty `server_allowed_ips` value is populated from the matching
peer block in the real config before any apply is attempted.
