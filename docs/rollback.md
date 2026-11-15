# Emergency rollback

Use the provider console or a management path independent of the affected
tunnel. Stop WGPanel mutations without stopping WireGuard:

```bash
docker compose stop wgpanel
```

Restore the chosen root-only config backup through the installed helper. It
validates, uses `wg syncconf`, atomically restores the file and does not run
`wg-quick down`:

```bash
sudo /usr/local/sbin/wgpanel-helper restore --interface wg0 --backup /etc/wireguard/backups/wg0.conf.CHOSEN-TIMESTAMP.bak
```

Restore the matching database only while WGPanel is stopped:

```bash
docker compose run --rm --no-deps --entrypoint sh --user root wgpanel -lc 'install -o wgpanel -g wgpanel -m 600 /var/lib/wgpanel/backups/CHOSEN-wgpanel.db.bak /var/lib/wgpanel/wgpanel.db'
docker compose up -d wgpanel
```

Then verify runtime AllowedIPs, route, NETMAP, peer count and end-to-end paths.
Never use `git reset --hard`, delete the database, or recreate `wg0` as a
rollback shortcut.
