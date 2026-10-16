# Restart ground truth, tycana-ubuntu2404, 2026-10-16

Captured as root right after the VM's own unattended-upgrades run (10:34-10:35 EDT)
installed 45 packages, including kernel 6.8.0-147 and new libssl, systemd, and
libsystemd. needrestart, run by unattended-upgrades, had already restarted most
services. Used to check M2 restart detection against what root can see.

- `needrestart-b.txt`: `needrestart -b` as root (batch output).
- `deleted-maps.tsv`: pid, cgroup, exe, and the library or binary paths each process
  maps with "(deleted)", from `/proc/<pid>/maps` as root.
- `units.txt`: `systemctl show` of running services: Id, MainPID,
  ExecMainStartTimestampMonotonic, ExecStart.
- `boot_id`, `uname-r`, `boot-kernels.txt`, `reboot-required.pkgs`: kernel state.
- `dpkg-log-run.txt`: dpkg.log lines of the run. `u-u.log`: the unattended-upgrades log.

The login name of the lab user is replaced with `operator`.

`snapshot.json` is the input of `tycana restart --snapshot` for the same moment, built
after the reboot on 2026-10-16 (no package changed in between):

- Units from `units.txt`. Monotonic start times are converted with the boot's
  realtime/monotonic pair from the journal (`__REALTIME_TIMESTAMP` 1792161412419801,
  `__MONOTONIC_TIMESTAMP` 1239204895: boot at 2026-10-16T14:16:13.214906Z).
  `units.txt` lists services only, so `init.scope` (boot time) and `session-4.scope`
  (logind "New session 4", 14:16:22.712800Z, PAM service `sshd`) are added by hand.
- Programs and file birth times from the `TestLabCapture` tool in `internal/restart`,
  run on the VM for every ExecStart program in `units.txt` and `/usr/sbin/sshd`.

Package change times (`packages` in `snapshot.json`, added 2026-10-16 for ADR 0020):
`dpkg-log-run.txt`, every install and upgrade of the run, local time (EDT) converted to UTC, whole seconds (`coarse`). No package changed between the boot and the run.
