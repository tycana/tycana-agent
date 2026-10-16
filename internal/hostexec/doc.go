// Package hostexec will be the only place in the agent allowed to run a
// host command (ADR 0009, ADR 0017). It is empty in M0. When it arrives (M2)
// it holds a hardened exec wrapper with an allowlist of read-only commands
// such as "apt-get -s upgrade" and "dnf check-update", fixed argument
// shapes, no shell, a clean environment, and timeouts. tools/nowrite rejects
// os/exec imports anywhere else in the module.
package hostexec
