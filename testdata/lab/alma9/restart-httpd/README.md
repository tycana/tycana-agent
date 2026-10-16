# Restart ground truth, httpd after an OpenSSL update, tycana-alma9, 2026-10-16

From the staged state, as root: `dnf install httpd mod_ssl`, start httpd (17:27:07
UTC), then `dnf reinstall openssl-libs` (3.5.8), which replaces libssl, libcrypto and
the OpenSSL modules and nothing else; nothing restarted. `/usr/sbin/httpd` links no
SSL library; `mod_ssl.so` does. On EL9 the NSS module `libnss_systemd.so.2` links
libcrypto, so every process that resolved a user through it maps libcrypto too
(polkit). The VM was then restored from the Lima snapshot `staged-2026-10-16`.

- `deleted-maps.tsv`: from `/proc/<pid>/maps` as root, right after `snapshot.json`.
  Fourteen units are stale, httpd, polkit and PID 1 included.
- `snapshot.json`: `tycana restart --format snapshot` in the tycanad sandbox. Its
  `modules` list the files of the run-time modules' own closures (libcrypto via
  `libnss_systemd.so.2`, libssl via `mod_ssl.so`).

Before the agent read those closures, httpd and polkit were "none": silent misses.
