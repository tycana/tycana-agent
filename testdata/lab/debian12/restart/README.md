# Restart ground truth, tycana-debian12, 2026-10-16

*Captured again at 18:59 UTC the same day, with package change times (ADR 0020): the same
upgrade from the same Lima snapshot. The sshd session is session-5 in this capture.*

On a fresh boot (17:16:42 UTC), as root, the ten pending security updates were
installed with `apt-get upgrade` at 17:17:04 UTC: libexpat1, libpcre2-8-0, libpng16-16,
libpython3.11-minimal, libpython3.11-stdlib, libssl3, openssl, perl-base,
python3.11-minimal, python3.11. needrestart is not installed and nothing restarted.
The VM was then restored from the Lima snapshot `staged-2026-10-16`.

- `deleted-maps.tsv`: pid, cgroup, exe, deleted mapped files, from `/proc/<pid>/maps`
  as root. Twelve units are stale, PID 1 included: Debian's systemd did not re-execute,
  because systemd itself was not updated.
- `snapshot.json`: `tycana restart --format snapshot` in the tycanad sandbox
  (`scripts/lab-sandbox.sh`) at the same moment, under systemd 252.
