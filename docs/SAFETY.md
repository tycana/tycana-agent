# Safety model

This is the public safety model for the Tycana agent. It states what the agent does to a host,
what it can never do, and how each claim is enforced so that you can check it rather than
trust it. It will grow with the agent; the sections marked *planned* describe milestones that
have not shipped.

## 1. The contract

**The agent never changes a host.** It reads package databases, update metadata, and service
state, and it signs what it saw. It has no write unit, no package-manager invocation beyond
read-only queries, and no code path that modifies packages, services, configuration, or any
file outside its own state directory.

Changes to a host are proposed to a human, who applies them with their own tooling. The agent
then verifies the result and issues a signed receipt. Whether a write path ever exists is a
separate future decision that would ship as a separate binary under a separate trust claim.

## 2. How the contract is enforced

| Layer | Mechanism | Where to check |
|---|---|---|
| Source | `tools/nowrite` parses every Go file and fails CI on filesystem-mutating calls, process execution, or raw syscalls outside `internal/state` and `internal/hostexec` | `make nowrite`, `.github/workflows/ci.yml` |
| State | `internal/state` writes only the host key and the signed records in the state directory | `internal/state/` |
| Process | `internal/hostexec` is the only package that runs a command; allowlisted read-only commands, fixed argument shapes, no shell, clean environment, timeouts | `internal/hostexec/` |
| Service | systemd unit with no capabilities, `ProtectSystem=strict`, the dedicated system user `tycana`, seccomp filter, private devices; the only writable path is the state directory | `packaging/systemd/tycanad.service`, `make security-score` |
| Release | reproducible builds, Sigstore signatures, SLSA L3 provenance, SBOM; no self-update | `VERIFY.md` |

The unit's `systemd-analyze security` exposure is 1.2 (1.1 until ADR 0024 removed
`PrivateUsers=yes` on 2026-10-17, so the baseline can read file owners) and CI fails if it
rises above 1.5.
The remaining exposure is network access, which the agent will need to report to a control
plane.

## 3. What the agent reads

Done in M1: installed packages from dpkg's status file and journal, or from rpm's
`rpmdb.sqlite`; the package managers' own transaction records (dpkg.log, apt history.log,
dnf's history.sqlite); os-release; the running kernel from /proc and installed kernels from
the package list and /boot; live patches from /sys. The agent never runs the package manager.
SQLite databases are opened read-only by one package (`internal/sqlitero`); when the file's
write-ahead log is empty the open is immutable and takes no lock, and when it is not, SQLite's
read-only path is used, which cannot create or change a file as the unit's user.

Done in M2: pending updates and their security classification from apt and dnf in simulate
mode, through `internal/hostexec`, and kernel and service restart state without privilege.
Done in M3: configuration baseline checks. Every reading records its source.
Nothing is inferred from third-party feeds without the vendor's data.

## 4. What the agent keeps, and what leaves the host

The agent writes only in its state directory, `/var/lib/tycanad` (mode 0700, owner
`tycana`): its host key and its signed records. At each cycle (one at start, then one each
interval, one hour by default) it signs two records with the host key, a `host-inventory`
and a `host-assessment`, and keeps them gzipped. They hold what `tycana inventory`,
`updates`, `restart`, and `baseline` show to any local user, nothing more. A collector that
fails is named in the record; a record never looks complete when it is not. Records older
than the retention (30 days by default) are deleted, but never the newest 50. The format
and how to check it without Tycana are in `VERIFY.md`.

**Halt.** While `/etc/tycana/halt` exists (any kind of file), the agent collects nothing and
signs nothing. It checks before each cycle and again before it signs. The first records after a halt state
when the agent first and last saw the file, so a halt is not mistaken for an agent that did not
run. `/etc/tycana` belongs to root, so only root can make the file.

**Self-check.** At start the agent hashes its own binary. If a package installed it, the
agent compares the hash with the package database (dpkg's MD5, rpm's file digest) and exits
with status 3 on a mismatch; the unit does not restart it. The hash and the result are in
every record. This finds a changed binary; it does not stop root, who can also change the
package database.

Nothing leaves the host yet: there is no network code. *planned*: signed records sent to a control plane
over TLS, containing package names and versions, finding identifiers, and host identity. No
file contents, no user data, no shell history, no credentials. The exact record set is
documented before it ships.

## 5. Supply chain

- Builds use the pinned Go toolchain in `go.mod`, `-trimpath`, no VCS stamping, and timestamps
  from the commit, so two builds of a tag are byte-identical. The release workflow builds on
  two separate runners and refuses to publish on a mismatch.
- Releases are signed with Sigstore keyless signing; the identity is the release workflow of
  this repository. No maintainer holds a release key.
- SLSA Build Level 3 provenance is generated by `slsa-github-generator` and verifiable with
  `slsa-verifier`.
- Each archive ships with an SPDX SBOM.
- GitHub Actions are pinned by commit hash; dependencies update through reviewed pull requests.
- There is no self-update. The agent cannot fetch or execute new code.

## 6. Threats considered

- **A compromised control plane.** It can lie to you about what it was told; it cannot make the
  agent do anything, because the agent takes no instructions that change host state.
- **A compromised release pipeline.** Signatures and provenance bind each artifact to this
  repository's workflow at a specific tag; a build from anywhere else fails verification.
- **A hostile configuration file.** Configuration selects what to observe and where to report.
  No configuration value is executed or can widen the unit's permissions.
- **Untrusted text on the host.** Package descriptions, changelogs, and service names are data.
  They are never interpreted as instructions by the agent or by any model downstream.
- **Local privilege.** The agent runs as the unprivileged system user `tycana`, with no other
  groups and an empty capability set. Compromising it yields read access to world-readable package metadata and the agent's
  own state directory, nothing more.

## 7. Reporting

See `SECURITY.md`. Any way to make the agent change a host is the highest severity we have.
