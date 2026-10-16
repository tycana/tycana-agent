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
```

The package list is read straight from the package manager's database, never by running it:
dpkg's status file and journal, or rpm's `rpmdb.sqlite` (rpm 4.16 and later). dnf's history
database is read the same way. Every read is checked byte for byte against `dpkg-query`,
`dpkg -l`, and `rpm -qa` on lab hosts (`scripts/lab-dpkg.sh`, `scripts/lab-rpm.sh`), as an
ordinary user and inside the shipped unit's sandbox; the captured databases in `testdata/lab/`
keep those checks running in CI. SQLite files are opened read-only through one small package,
`internal/sqlitero`, the only place allowed to import the driver.

## What it will do

- Inventory every installed package and pending update, matched against vendor security feeds.
- Detect hosts and services that need a restart, and tell you when the fix actually took effect.
- Track drift from a declared baseline.
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
