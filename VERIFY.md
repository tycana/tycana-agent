# Verify a release

Do this before you run anything from a release. It takes two minutes and needs
[cosign](https://github.com/sigstore/cosign) and
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier). Replace `vX.Y.Z` with the tag.

Tool versions: cosign 3 or later (with cosign 2.x, add `--new-bundle-format` to step 2), and
slsa-verifier 2.7 or later (2.6 fails with "expected intoto:0.0.2, got dsse:0.0.1"). Both
were checked against `v0.0.1-alpha.3` on 2026-10-16.

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

## Verify a host's records without Tycana

`tycana evidence export` writes a bundle: the host's public keys and its records. Each record
is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope around an
[in-toto Statement v1](https://github.com/in-toto/attestation), signed with ECDSA P-256 and
SHA-256. `tycana evidence verify bundle.json` checks every signature and the chain. To check
without Tycana code, use OpenSSL and a few lines of Python:

```sh
python3 - bundle.json <<'PY'
import base64, json, sys
b = json.load(open(sys.argv[1]))
open("host.pub", "w").write(b["keys"][0]["public_key"])
for i, env in enumerate(b["records"], 1):
    p = base64.b64decode(env["payload"])
    t = env["payloadType"].encode()
    open(f"r{i}.pae", "wb").write(b"DSSEv1 %d %s %d %s" % (len(t), t, len(p), p))
    open(f"r{i}.sig", "wb").write(base64.b64decode(env["signatures"][0]["sig"]))
PY
for f in r*.pae; do openssl dgst -sha256 -verify host.pub -signature "${f%.pae}.sig" "$f"; done
```

Each line must say `Verified OK`. The chain: the `predicate.record.previous` field of each
record is `sha256:` and the SHA-256 of the decoded payload of the record before it, and
`predicate.record.sequence` goes up by one.

cosign (v3.0.2 tested) checks one record too. The Statement's subject is the host's public
key, so the key's DER form is the blob:

```sh
openssl pkey -pubin -in host.pub -outform DER -out host.der
python3 -c 'import json,sys; json.dump(json.load(open("bundle.json"))["records"][0], open("r1.json","w"))'
cosign verify-blob-attestation --key host.pub --signature r1.json \
  --type https://tycana.ai/attestations/host-inventory/v0.1 --insecure-ignore-tlog=true host.der
```

`--insecure-ignore-tlog` is necessary: records are not in a transparency log yet.

What this does and does not show: a valid signature shows that nobody without the host's key
changed the record after it was signed. The key is on the host, so root on that host can sign
anything; compare the key with one you kept from an earlier export (`tycana evidence verify
--key`).

## What is not here

There is no auto-update. The agent will never fetch and run a newer version of itself. Updates
are a package upgrade you perform, through the same verification.
