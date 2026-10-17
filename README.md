# Tycana agent

An open-source Linux host agent that knows exactly what every server is running and can prove
it to anyone who asks: the auditor, the insurer, the customer whose scanner flagged a
backported fix.

**The agent never changes a host.** It has no write unit, no package-manager invocation beyond
read-only queries, and no code path that modifies packages, services, or configuration. It
observes, reports, and signs what it saw. Changes are proposed to a human, who applies them with
whatever they already use; the agent then verifies the result and issues a signed receipt.

Status: pre-release. Nothing to install yet. When there is, verify it first: see
[VERIFY.md](VERIFY.md). The safety model is in [docs/SAFETY.md](docs/SAFETY.md).

What works today, on Debian, Ubuntu, and the RHEL 9 family, as an ordinary user:

```sh
go run ./cmd/tycana inventory                       # packages, OS, kernels
go run ./cmd/tycana inventory --format dpkg-query   # byte-identical to dpkg-query -W (see --help)
go run ./cmd/tycana inventory --format rpm-query    # byte-identical to rpm -qa --qf (see --help)
go run ./cmd/tycana history --since 2026-10-01      # what dpkg, apt, and dnf changed, and who asked
go run ./cmd/tycana updates                         # pending updates, and what the host's autopilot installs
go run ./cmd/tycana restart                         # services still running replaced code, kernel, reboot
go run ./cmd/tycana baseline                        # configuration baseline: coverage, then the score of the checked rules
```

The package list is read straight from the package manager's database, never by running it:
dpkg's status file and journal, or rpm's `rpmdb.sqlite` (rpm 4.16 and later). dnf's history
database is read the same way. Every read is checked byte for byte against `dpkg-query`,
`dpkg -l`, and `rpm -qa` on lab hosts (`scripts/lab-dpkg.sh`, `scripts/lab-rpm.sh`), as an
ordinary user and inside the shipped unit's sandbox; the captured databases in `testdata/lab/`
keep those checks running in CI. SQLite files are opened read-only through one small package,
`internal/sqlitero`, the only place allowed to import the driver.

### Baselines

`tycana baseline` checks file modes and owners, kernel parameters, packages, services, the SSH
server's configuration, mount options, and kernel modules against a built-in baseline for the
host's release (Ubuntu 24.04, Debian 12, AlmaLinux 9 today). The baselines are generated
offline from [ComplianceAsCode](https://github.com/ComplianceAsCode/content) content
(BSD-3-Clause) by `tools/cacconv`, and each check keeps its ComplianceAsCode rule id.

Each check gives the verdict OpenSCAP gives for the same rule. On the lab VMs every evaluated
check agrees with OpenSCAP run as root, including a known-bad case with six settings broken by
hand (`testdata/lab/*/baseline-*`, `TestLabAgreesWithOpenSCAP`). Rules whose check is custom
OVAL are listed as not covered, with the reason: 36 to 39 percent of each source profile today.
Counted per recommendation of the benchmark the profile follows, Tycana checks 110 of 232
automated recommendations on Ubuntu 24.04, 113 of 230 on Debian 12, and 103 of 219 on
AlmaLinux 9 (47 to 49 percent); every report starts with that count. When a rule is stricter
than the system it checks (it wants a unit masked where systemd would not start it anyway, or
an fstab line for a mount that already has the option), the result keeps the rule's verdict
and carries a note that says so.

The agent reads without privilege. What it cannot read (a root-only file, an owner its user
namespace cannot map, a mount option its sandbox may have added) is **unknown**, never
**fail**. The score is passed over passed plus failed; unknown, not-applicable, excepted, and
faulty checks are counted apart, so the number is never inflated by guesses. A local
exceptions file (`--exceptions`) takes a check out of the score with an owner, a reason, and an
expiry date.

## Signed records

The daemon `tycanad` runs as an unprivileged systemd service. Each hour it reads the host and
signs two records with a key generated on the host: the inventory, and the assessment (pending
updates, restart state, baseline). The records form a hash chain and stay on the host for 30
days. `sudo tycana status` shows the latest signed state; `sudo tycana evidence export` writes
them as one bundle; `tycana evidence verify` checks a bundle anywhere, and
[VERIFY.md](VERIFY.md) shows how to check it with OpenSSL or cosign instead.

On the four lab hosts, every record verified with OpenSSL and with cosign. The package list in
each record was identical to dpkg-query or rpm -qa.

A valid signature shows that nobody without the host's key changed a record after the agent
signed it. It does not show that the host reported the truth: root on the host can read the
key. While `/etc/tycana/halt` exists the agent collects and signs nothing, and its next
records say when the halt began and ended.

## What it will do

- Inventory every installed package and pending update, matched against vendor security feeds.
- Detect hosts and services that need a restart, and tell you when the fix actually took effect.
- Track drift from a declared baseline over time, with signed snapshots.
- Keep an exception register auditors accept: owner, reason, compensating control, expiry.
- Export evidence: signed records, OpenVEX statements for findings that do not apply, and
  reports in the shapes compliance platforms and insurers ask for.

## Principles

- Deterministic core. Ordinary code decides what is true on the host; no model runs on it.
- Reproducible, signed builds with provenance and an SBOM. No self-update.
- Tiny footprint, unprivileged where the operating system allows it.
- Report-only is the product, not a mode.

## Developing

```sh
make check    # vet, observe-only source guard, tests, build, unit security score, reproducible build
make lint     # golangci-lint v2
```

Contributions need a DCO sign-off (`git commit -s`); see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports go through [SECURITY.md](SECURITY.md), never an issue.

## License

Apache-2.0. See `LICENSE`.
