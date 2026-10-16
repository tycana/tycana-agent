# Verify a release

Do this before you run anything from a release. It takes two minutes and needs
[cosign](https://github.com/sigstore/cosign) and
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier). Replace `vX.Y.Z` with the tag.

## 1. Download

From https://github.com/tycana/tycana-agent/releases/tag/vX.Y.Z take:

- the archive for your platform, for example `tycana_X.Y.Z_linux_amd64.tar.gz`
- `checksums.txt` and `checksums.txt.sigstore.json`
- `multiple.intoto.jsonl` (the SLSA provenance)
- optionally the matching `.spdx.json` SBOM

## 2. Check the signature on the checksums

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/tycana/tycana-agent/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Expected output ends with `Verified OK`. The identity is the release workflow in this
repository, not a person. No one holds a signing key.

## 3. Check the archive against the checksums

```sh
sha256sum --check --ignore-missing checksums.txt
```

## 4. Check the provenance

```sh
slsa-verifier verify-artifact tycana_X.Y.Z_linux_amd64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/tycana/tycana-agent \
  --source-tag vX.Y.Z
```

Expected output ends with `PASSED: SLSA verification passed`. This proves the archive was built
by this repository's release workflow from the tagged commit, on GitHub's hosted runners.

## 5. Check what you are about to run

```sh
tar xzf tycana_X.Y.Z_linux_amd64.tar.gz
./tycana version
```

The commit printed must match the tagged commit on GitHub.

## Reproduce it yourself

Releases are reproducible. With the Go toolchain version named in `go.mod` of the tag:

```sh
git clone https://github.com/tycana/tycana-agent && cd tycana-agent && git checkout vX.Y.Z
goreleaser build --clean --single-target --skip=validate
sha256sum dist/*/tycanad dist/*/tycana
```

The hashes must match the binaries inside the release archive for your platform. The release
workflow itself builds twice on separate runners and refuses to publish if the results differ.

## What is not here

There is no auto-update. The agent will never fetch and run a newer version of itself. Updates
are a package upgrade you perform, through the same verification.
