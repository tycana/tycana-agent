#!/usr/bin/env bash
# Build the agent twice, from the working tree and from a copy of it in a
# different directory with a cold build cache, and require identical bytes.
# This is the local form of the reproducible-build gate (ADR 0012).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

build() { # $1 = source dir, $2 = output dir
  (cd "$1" && CGO_ENABLED=0 GOFLAGS=-mod=mod \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$2/" ./cmd/...)
}

build "$root" "$work/a"
cp -a "$root" "$work/src-copy"
GOCACHE="$work/gocache" build "$work/src-copy" "$work/b"

status=0
for bin in tycana tycanad; do
  a=$(sha256sum "$work/a/$bin" | cut -d' ' -f1)
  b=$(sha256sum "$work/b/$bin" | cut -d' ' -f1)
  if [ "$a" = "$b" ]; then
    echo "reproducible: $bin $a"
  else
    echo "NOT reproducible: $bin $a != $b" >&2
    status=1
  fi
done
exit $status
