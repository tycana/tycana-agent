# Tycana agent

An open-source Linux host agent that knows exactly what every server is running and can prove
it to anyone who asks: the auditor, the insurer, the customer whose scanner flagged a
backported fix.

**The agent never changes a host.** It has no write unit, no package-manager invocation beyond
read-only queries, and no code path that modifies packages, services, or configuration. It
observes, reports, and signs what it saw. Changes are proposed to a human, who applies them with
whatever they already use; the agent then verifies the result and issues a signed receipt.

Status: pre-release. Nothing to install yet.

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

## License

Apache-2.0. See `LICENSE`.
