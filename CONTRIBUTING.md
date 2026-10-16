# Contributing

Thank you. A few rules keep this project trustworthy.

## The agent never changes a host

Pull requests that add a way for the agent to modify packages, services, configuration, or
files outside its own state directory are closed, however useful. This is a product decision
(ADR 0017 in the project's decision log), not a missing feature. `make nowrite` enforces it
at the source level and runs in CI.

## Before you open a pull request

```sh
make check          # vet, nowrite, tests, build, unit security score, reproducible build
make lint           # needs golangci-lint v2
```

Go version: the one in `go.mod`. No new third-party dependencies without an issue first; the
agent is meant to stay small and auditable.

## Sign your commits (DCO)

Every commit needs a `Signed-off-by` line certifying the Developer Certificate of Origin in
`DCO`. `git commit -s` adds it. CI rejects unsigned commits.

## Pull requests

Small and focused. Describe what changed and why. Tests for behaviour. Documentation changes
in the same PR as the code they describe.

## Reporting a vulnerability

Not in an issue. See `SECURITY.md`.
