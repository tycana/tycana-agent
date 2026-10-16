# Reboot rule on Oracle Linux 9 with UEK, tycana-oel9, 2026-10-16

From the staged state (Lima snapshot `staged-2026-10-16`), as root, only
`dnf upgrade kernel-uek-core kernel-uek-modules-core` (UEK 8, 6.12.0-204 to 6.12.0-207).
`dnf needs-restarting -r` then asked for a reboot for kernel-uek-core
(`needs-restarting.txt`). The agent, with Red Hat's built-in list, said "not required":
Oracle's dnf-plugins-core (4.3.0-26.0.1) adds kernel-uek and kernel-uek-core to the list.
The agent now reads the list from the installed plugin.

- `installtime.txt`, `proc-stat-btime`: the inputs of the rule.
- `needs_restarting-excerpt.py`: the NEED_REBOOT list of Oracle's plugin, nothing else.

Ksplice is not available on this VM (it needs ULN or OCI); its effect is not tested.
