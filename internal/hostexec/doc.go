// Package hostexec is the only place in the agent allowed to run a host
// command (ADR 0009, ADR 0017); tools/nowrite rejects os/exec anywhere
// else in the module.
//
// Every command the agent can run is a registered Spec with a fixed
// absolute path and fixed leading arguments. Callers name a command by ID;
// they cannot supply a program, and they can add arguments only where the
// Spec has a validator (package names, for example). Each command:
//
//   - runs without a shell, with stdin closed and a fixed environment
//     (LC_ALL=C, a fixed PATH, nothing inherited);
//   - must be a regular file owned by root and not writable by group or
//     others, so a planted binary is refused;
//   - never runs as root: when the caller is root (an operator running the
//     CLI with sudo), the child runs as nobody, so even a read-only verb
//     cannot update a cache or lock file on the way;
//   - runs in its own process group, killed as a whole on timeout or when
//     its output passes a size cap.
//
// Only read-only verbs are registered: simulations and queries. The
// registry is listed verbatim in TestRegistryIsReadOnly, so adding or
// changing a command changes a reviewed test.
package hostexec
