#!/usr/bin/env bash
# Check `tycana inventory` against dpkg on a tycana-* Lima VM, and capture
# the VM's package database as a committed test fixture.
#
#   scripts/lab-dpkg.sh compare VM        byte-compare with dpkg-query -W, row-compare with dpkg -l
#   scripts/lab-dpkg.sh capture VM NAME   write testdata/lab/NAME/ from the VM
#
# The binary runs on the VM as the unprivileged Lima user: inventory needs
# no root. Only files under /tmp/tycana-lab on the VM are created, and they
# are removed afterwards. Never point this at a VM that is not tycana-*.
set -euo pipefail

cmd=${1:-}; vm=${2:-}
case "$vm" in tycana-*) ;; *) echo "usage: $0 compare|capture tycana-VM [NAME]" >&2; exit 2;; esac

# Must equal dpkg.QueryFormat (cmd/tycana tests check this).
FORMAT='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${binary:Summary}\n'

root=$(cd "$(dirname "$0")/.." && pwd)
make -C "$root" -s build
limactl shell "$vm" -- sh -c 'rm -rf /tmp/tycana-lab && mkdir -m 700 /tmp/tycana-lab'
limactl copy "$root/bin/tycana" "$vm:/tmp/tycana-lab/tycana"
trap 'limactl shell "$vm" -- rm -rf /tmp/tycana-lab' EXIT

remote() { limactl shell "$vm" -- sh -c "$1"; }

case "$cmd" in
compare)
  remote "cd /tmp/tycana-lab && set -e
    dpkg-query -W -f='$FORMAT' > before.tsv
    ./tycana inventory --format dpkg-query > tycana.tsv
    dpkg -l > dpkg-l.txt
    dpkg-query -W -f='$FORMAT' > after.tsv
    if ! cmp -s before.tsv after.tsv; then echo 'package database changed during the run; rerun' >&2; exit 3; fi
    awk 'p{print \$1, \$2, \$3, \$4} /^\+\+\+-/{p=1}' dpkg-l.txt > l.native
    awk -F'\t' '{s=\$1; sub(/ +\$/, \"\", s); print s, \$2, \$3, \$4}' tycana.tsv > l.tycana
    echo \"host:        \$(. /etc/os-release; echo \$PRETTY_NAME), \$(uname -r), \$(dpkg --version | head -1 | sed 's/.*version //')\"
    echo \"run as:      \$(id -un) (uid \$(id -u))\"
    echo \"packages:    \$(wc -l < tycana.tsv)\"
    if cmp -s before.tsv tycana.tsv; then echo 'dpkg-query:  byte-identical' \$(sha256sum < tycana.tsv | cut -c1-16); else echo 'dpkg-query:  DIFFERENT'; diff before.tsv tycana.tsv | head -20; exit 1; fi
    if cmp -s l.native l.tycana; then echo 'dpkg -l:     all rows agree (status, name, version, arch)'; else echo 'dpkg -l:     DIFFERENT'; diff l.native l.tycana | head -20; exit 1; fi"
  ;;
capture)
  name=${3:?capture needs a fixture NAME}
  dest="$root/testdata/lab/$name"
  rm -rf "$dest" && mkdir -p "$dest/root" "$dest/expected"
  remote "cd / && tar cf - etc/os-release usr/lib/os-release var/lib/dpkg/status var/lib/dpkg/arch 2>/dev/null; true" \
    | tar xf - -C "$dest/root"
  # Logs and the zone they were written in (etc/localtime is a symlink; take its target too).
  remote 'cd / && tar cf - var/log/dpkg.log* var/log/apt/history.log* etc/localtime etc/timezone \
      "$(readlink -f /etc/localtime | cut -c2-)" 2>/dev/null; true' | tar xf - -C "$dest/root"
  # apt records the invoking login (the laptop user under Lima); this repo is public.
  for f in "$dest"/root/var/log/apt/history.log*; do
    case "$f" in *.gz) echo "warning: $f not sanitized" >&2;; *) sed -i -E 's/^(Requested-By: )[^ ]+ \(/\1operator (/' "$f";; esac
  done
  # /proc files report size 0, so tar would store them empty; read them instead.
  mkdir -p "$dest/root/proc/sys/kernel" "$dest/root/boot"
  for f in osrelease version; do remote "cat /proc/sys/kernel/$f" > "$dest/root/proc/sys/kernel/$f"; done
  for k in $(remote 'ls /boot | grep "^vmlinuz-"'); do : > "$dest/root/boot/$k"; done
  remote "dpkg-query -W -f='$FORMAT'" > "$dest/expected/dpkg-query.tsv"
  remote 'dpkg -l' > "$dest/expected/dpkg-l.txt"
  remote 'uname -r' > "$dest/expected/uname-r.txt"
  {
    echo "Captured $(date -u +%Y-%m-%dT%H:%M:%SZ) from Lima VM $vm by scripts/lab-dpkg.sh."
    echo "Host: $(remote '. /etc/os-release; echo $PRETTY_NAME'), kernel $(cat "$dest/expected/uname-r.txt"), $(remote 'dpkg --version | head -1' | sed 's/\.$//')."
    echo "root/ holds copies of the files the agent reads; boot/vmlinuz-* are empty placeholders."
    echo "Requested-By user names in var/log/apt/history.log are replaced with 'operator'; nothing else is edited."
    echo "expected/ holds the native tools' output on the same host at the same moment."
  } > "$dest/MANIFEST"
  ls -l "$dest/root/var/lib/dpkg" "$dest/expected"
  ;;
*) echo "usage: $0 compare|capture tycana-VM [NAME]" >&2; exit 2;;
esac
