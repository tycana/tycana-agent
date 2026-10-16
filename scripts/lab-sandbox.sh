#!/usr/bin/env bash
# Run a tycana command on a tycana-* Lima VM inside the sandbox of the
# shipped systemd unit, so "works in the lab" means "works as tycanad".
#
#   scripts/lab-sandbox.sh tycana-VM [-p Extra=Override ...] -- inventory --format dpkg-query
#
# Every [Service] setting in packaging/systemd/tycanad.service is passed to
# systemd-run except the ones that only make sense for the long-running
# daemon (Type, ExecStart, Restart*). -p arguments after the VM name are
# appended, so a setting can be tried out before the unit is changed.
# The binary is placed in /opt/tycana-lab (the sandbox hides /tmp) and
# removed afterwards.
set -euo pipefail

vm=${1:-}
case "$vm" in tycana-*) shift ;; *) echo "usage: $0 tycana-VM [-p K=V ...] -- tycana-args..." >&2; exit 2;; esac
extra=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  [ "$1" = "-p" ] && [ $# -ge 2 ] || { echo "expected -p K=V or --" >&2; exit 2; }
  extra+=("-p" "$2"); shift 2
done
[ "${1:-}" = "--" ] && shift

root=$(cd "$(dirname "$0")/.." && pwd)
unit="$root/packaging/systemd/tycanad.service"
props=()
while IFS= read -r line; do
  case "$line" in ''|'#'*|'['*) continue ;; esac
  key=${line%%=*}
  case "$key" in Type|ExecStart|Restart|RestartSec|WantedBy) continue ;; esac
  props+=("-p" "$line")
done < <(sed -n '/^\[Service\]/,/^\[Install\]/p' "$unit")

make -C "$root" -s build
limactl copy "$root/bin/tycana" "$vm:/tmp/tycana-sandbox-bin"
limactl shell "$vm" -- sudo install -D -m 0755 -o root -g root /tmp/tycana-sandbox-bin /opt/tycana-lab/tycana
limactl shell "$vm" -- rm -f /tmp/tycana-sandbox-bin
# Lab runs before 2026-10-16 used DynamicUser= and left
# /var/lib/private/tycanad. systemd 252 then fails to migrate it for the
# static user (status 238/STATE_DIRECTORY, "Permission denied" on
# AlmaLinux 9 and Oracle Linux 9), and its /var/lib/tycanad symlink into
# private/ dangles. No package ever shipped DynamicUser, so
# only lab VMs have them; remove both.
limactl shell "$vm" -- sudo sh -c 'rm -rf /var/lib/private/tycanad; [ -L /var/lib/tycanad ] && rm /var/lib/tycanad; true'
# The unit's User= must exist; create it the way the package will.
limactl copy "$root/packaging/sysusers.d/tycana.conf" "$vm:/tmp/tycana-sysusers.conf"
limactl shell "$vm" -- sudo sh -c 'install -D -m 0644 /tmp/tycana-sysusers.conf /usr/lib/sysusers.d/tycana.conf && rm /tmp/tycana-sysusers.conf && systemd-sysusers /usr/lib/sysusers.d/tycana.conf'
trap 'limactl shell "$vm" -- sudo rm -rf /opt/tycana-lab' EXIT

q=()
for a in "${props[@]}" "${extra[@]}"; do q+=("$(printf '%q' "$a")"); done
for a in "$@"; do q+=("$(printf '%q' "$a")"); done
n=$(( ${#props[@]} + ${#extra[@]} ))
limactl shell "$vm" -- sudo sh -c "systemd-run --quiet --wait --pipe --collect ${q[*]:0:$n} /opt/tycana-lab/tycana ${q[*]:$n}"
