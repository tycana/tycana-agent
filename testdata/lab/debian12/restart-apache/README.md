# Restart ground truth, Apache after an OpenSSL update, tycana-debian12, 2026-10-16

From the staged state, as root: `apt-get install --no-upgrade apache2`, `a2enmod ssl`,
`a2ensite default-ssl`, restart apache2 (17:26:06 UTC). Then only
`apt-get install --only-upgrade libssl3 openssl` (3.0.20 to 3.0.22) at 17:26:17 UTC;
nothing restarted. `/usr/sbin/apache2` links no SSL library; `mod_ssl.so`, which
Apache opens at run time, links libssl and libcrypto. The VM was then restored from
the Lima snapshot `staged-2026-10-16`.

- `deleted-maps.tsv`: from `/proc/<pid>/maps` as root. Eleven units are stale, apache2
  and PID 1 included.
- `snapshot.json`: `tycana restart --format snapshot` in the tycanad sandbox, captured
  before the agent read the closures of run-time modules. Debian starts apache2 through
  the `apachectl` shell script, so the agent reports it as unknown either way.
