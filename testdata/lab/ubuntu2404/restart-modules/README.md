# Restart ground truth, run-time modules only, tycana-ubuntu2404, 2026-10-16

A worst case for restart detection without privilege: only modules that programs
open at run time (dlopen) were replaced. On a fresh boot (kernel 6.8.0-147), as root:

    NEEDRESTART_SUSPEND=1 apt-get install --reinstall libnss-systemd libpam-systemd

at 17:13:02 UTC. This replaces `libnss_systemd.so.2` (NSS, loaded by libc) and
`pam_systemd.so` (PAM, loaded by libpam), and no library any program links directly.

- `deleted-maps.tsv`: pid, cgroup, exe, deleted mapped files, from `/proc/<pid>/maps`
  as root, right after the reinstall. Five units are stale: dbus, systemd-logind,
  rsyslog, session-4.scope (two sshd), user@1000.service.
- `needrestart-b.txt`: `needrestart -b` as root at the same moment. It also names
  ssh.service, for the session's sshd processes. The login name is replaced with
  `operator`.
- `snapshot.json`: `tycana restart --format snapshot` in the tycanad sandbox
  (`scripts/lab-sandbox.sh`) at the same moment. `run-u69.service` is the sandbox's
  own transient unit.

`../restart/snapshot.json` was captured before the agent listed run-time modules, and
the reinstall above has since replaced the module files whose times it would need. It
has no `modules` and no `sonames`, so it can never show "possible".

Package change times (`packages` in `snapshot.json`, added 2026-10-16 for ADR 0020):
the mtimes of `/var/lib/dpkg/info/*.list` on the VM, read later the same day by the agent; no package changed after the reinstall at 17:13:02 UTC.
