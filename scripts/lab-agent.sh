#!/usr/bin/env bash
# Install tycanad as its real unit on a tycana-* Lima VM, run cycles, and
# measure them (M4, tycana-hq ADR 0025).
#
#   scripts/lab-agent.sh tycana-VM OUTDIR
#
# Installs bin/tycanad and bin/tycana in /usr/bin, the unit, and the
# sysusers file; empties /var/lib/tycanad; starts the unit and waits for
# its first cycle; restarts it for a second cycle; checks that the halt
# file stops a cycle and that the next records name the halt; exports the
# bundle as root. OUTDIR gets the bundle,
# the native package list, the unit's resource counters, and the journal.
# Restore the VM's snapshot afterwards: this script changes the VM.
set -euo pipefail

vm=${1:-}; out=${2:-}
case "$vm" in tycana-*) ;; *) echo "usage: $0 tycana-VM OUTDIR" >&2; exit 2;; esac
[ -n "$out" ] || { echo "usage: $0 tycana-VM OUTDIR" >&2; exit 2; }
mkdir -p "$out"
root=$(cd "$(dirname "$0")/.." && pwd)
make -C "$root" -s build
remote() { limactl shell "$vm" -- sudo sh -c "$1"; }

for f in bin/tycanad bin/tycana packaging/systemd/tycanad.service packaging/sysusers.d/tycana.conf; do
  limactl copy "$root/$f" "$vm:/tmp/$(basename "$f")"
done
remote 'set -e
  install -m 0755 -o root -g root /tmp/tycanad /tmp/tycana /usr/bin/
  install -D -m 0644 /tmp/tycana.conf /usr/lib/sysusers.d/tycana.conf
  install -m 0644 /tmp/tycanad.service /etc/systemd/system/tycanad.service
  rm -f /tmp/tycanad /tmp/tycana /tmp/tycana.conf /tmp/tycanad.service
  systemd-sysusers /usr/lib/sysusers.d/tycana.conf
  rm -rf /var/lib/private/tycanad /var/lib/tycanad /etc/tycana/halt
  systemctl daemon-reload'

records() { remote 'ls /var/lib/tycanad/records 2>/dev/null | wc -l'; }
wait_records() {
  for _ in $(seq 1 120); do
    [ "$(records)" -ge "$1" ] && return 0
    sleep 2
  done
  echo "timeout waiting for $1 records" >&2; remote 'journalctl -u tycanad --no-pager | tail -20' >&2; exit 1
}
counters() { remote "systemctl show tycanad -p CPUUsageNSec -p MemoryPeak -p ActiveState -p ExecMainStatus -p NRestarts" | tr '\n' ' '; echo; }

remote 'journalctl --rotate -q; systemctl start tycanad'
wait_records 2
sleep 1
echo "cycle 1: $(counters)" | tee "$out/counters.txt"
remote 'systemctl restart tycanad'
wait_records 4
sleep 1
echo "cycle 2: $(counters)" | tee -a "$out/counters.txt"

# Halt: the cycle at start must not run.
remote 'mkdir -p /etc/tycana && touch /etc/tycana/halt && systemctl restart tycanad'
sleep 8
n=$(records)
echo "halted restart: $n records (want 4)" | tee -a "$out/counters.txt"
[ "$n" -eq 4 ] || { echo "halt file did not stop the cycle" >&2; exit 1; }
# The first cycle after the halt names it in both records.
remote 'rm /etc/tycana/halt; systemctl restart tycanad'
wait_records 6
remote 'systemctl stop tycanad'
h=$(remote 'zcat /var/lib/tycanad/records/0000000005.host-inventory.json.gz' | python3 -c 'import sys,json,base64; print("halted" in json.loads(base64.b64decode(json.load(sys.stdin)["payload"]))["predicate"])')
echo "record after the halt names it: $h (want True)" | tee -a "$out/counters.txt"
[ "$h" = True ] || { echo "no halt record" >&2; exit 1; }

remote 'ls -l /var/lib/tycanad/records /var/lib/tycanad/key; du -sb /var/lib/tycanad/records' > "$out/store.txt"
remote 'tycana evidence export > /tmp/bundle.json 2> /tmp/summary.txt; chmod 644 /tmp/bundle.json /tmp/summary.txt'
limactl copy "$vm:/tmp/bundle.json" "$out/bundle.json"
limactl copy "$vm:/tmp/summary.txt" "$out/summary.txt"
remote 'journalctl -u tycanad --no-pager -o cat' > "$out/journal.txt"
remote 'if command -v dpkg-query >/dev/null; then
    dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\n"
  else
    LC_ALL=C rpm -qa --qf "%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{ARCH}\n"
  fi | sort' > "$out/native-packages.tsv"
echo "done: $out"
