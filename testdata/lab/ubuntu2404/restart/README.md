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
