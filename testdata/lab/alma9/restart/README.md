# Restart ground truth, tycana-alma9, 2026-10-16

On a fresh boot (btime 1792171102, 17:18:22 UTC), as root, all 66 pending updates
were installed with `dnf upgrade` (finished 17:22:26 UTC): kernel, glibc, systemd,
dbus-broker, openssh, pam, pcre2, expat, python3 and others. The packages' scriptlets
re-executed PID 1 and restarted journald, udevd, sshd and rsyslog; nothing else
restarted. The VM was then restored from the Lima snapshot `staged-2026-10-16`.

- `deleted-maps.tsv`: pid, cgroup, exe, deleted mapped files, from `/proc/<pid>/maps`
  as root. Sixteen units are stale, session-6.scope included; PID 1 is not.
- `needs-restarting.txt`: `dnf needs-restarting -r` (exit 1) and `-s` as root.
- `snapshot.json`: `tycana restart --format snapshot` in the tycanad sandbox at the
  same moment.
- `installtime.txt` (`rpm -qa --qf "%{NAME} %{INSTALLTIME}"`) and `proc-stat-btime`:
  the inputs of the agent's own reboot hint.

The openssh update installed `/usr/libexec/openssh/sshd-session`, so the snapshot
times that program for the sshd session, which started under the old `sshd`. The
verdict holds (every file of the new program is newer than the session), but the
listed files are the new program's.
