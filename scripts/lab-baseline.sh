#!/usr/bin/env bash
# Capture baseline fixtures on a tycana-* Lima VM: one run as root (the
# view OpenSCAP has) and one inside the tycanad sandbox.
#
#   scripts/lab-baseline.sh tycana-VM testdata/lab/DIR LABUSER
#
# Writes DIR/baseline-root.json.gz and DIR/baseline-sandbox.json.gz.
# LABUSER (the Lima user, named after the laptop's user) is replaced by
# "operator" in /etc/passwd and /etc/group. OpenSCAP's results for the
# same VM state go to DIR/baseline-openscap.tsv separately (MANIFEST).
set -euo pipefail

vm=${1:-}; dir=${2:-}; user=${3:-}
case "$vm" in tycana-*) ;; *) echo "usage: $0 tycana-VM testdata/lab/DIR LABUSER" >&2; exit 2;; esac
[ -n "$dir" ] && [ -n "$user" ] || { echo "usage: $0 tycana-VM testdata/lab/DIR LABUSER" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd "$root" && CGO_ENABLED=0 go test -c -o "$work/baseline.test" ./internal/baseline)
# The test binary prints "PASS" after the gzip stream; keep the stream.
clean() { gzip -dc "$1" 2>/dev/null | gzip -9n >"$2" || true; }

limactl copy "$work/baseline.test" "$vm:/tmp/tycana-baseline.test"
limactl shell "$vm" -- sudo env TYCANA_CAPTURE_BASELINE=1 "TYCANA_CAPTURE_SCRUB=$user" \
  /tmp/tycana-baseline.test -test.run=TestLabCapture >"$work/root.raw"
limactl shell "$vm" -- rm -f /tmp/tycana-baseline.test
clean "$work/root.raw" "$root/$dir/baseline-root.json.gz"

TYCANA_LAB_BIN=$work/baseline.test "$root/scripts/lab-sandbox.sh" "$vm" \
  -p Environment=TYCANA_CAPTURE_BASELINE=1 -p "Environment=TYCANA_CAPTURE_SCRUB=$user" \
  -- -test.run=TestLabCapture >"$work/sandbox.raw"
clean "$work/sandbox.raw" "$root/$dir/baseline-sandbox.json.gz"
ls -l "$root/$dir"/baseline-*.json.gz
