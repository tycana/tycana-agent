# Security policy

## The contract

The Tycana agent never changes a host. Any way to make `tycanad` or `tycana` modify packages,
services, configuration, or any file outside the agent's own state directory is a security
vulnerability of the highest severity, even if it requires a hostile control plane or a
hostile configuration file. Please report it as such.

## Reporting

Use GitHub's private vulnerability reporting on this repository:
https://github.com/tycana/tycana-agent/security/advisories/new

Do not open a public issue for a suspected vulnerability.

Tycana is a small project. You will get an acknowledgement within seven days and a fix or a
documented decision within ninety. Coordinated disclosure after a fix is released is welcome;
credit is given unless you ask otherwise.

## Scope

In scope: the agent binaries, the systemd unit, the release pipeline and its signatures,
the SBOM and provenance, and the documentation that tells operators how to verify them.

Out of scope until they exist: the control plane and the hosted service.

## Supported versions

There is no release yet. Once there is, the latest minor release is supported.

## What we publish

Every release carries a Sigstore signature, SLSA Build Level 3 provenance, and an SPDX SBOM.
Builds are reproducible from the tagged source. See `VERIFY.md`. There is no self-update
mechanism: the agent cannot download or run new code.
