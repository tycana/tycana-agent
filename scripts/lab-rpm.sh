#!/usr/bin/env bash
# Check `tycana inventory` against rpm on a tycana-* Lima VM, and capture
# the VM's package database and dnf history as a committed test fixture.
#
#   scripts/lab-rpm.sh compare VM        byte-compare with rpm -qa --qf
#   scripts/lab-rpm.sh capture VM NAME   write testdata/lab/NAME/ from the VM
#
# The binary runs on the VM as the unprivileged Lima user: inventory needs
# no root. Only files under /tmp/tycana-lab on the VM are created, and they
# are removed afterwards. Never point this at a VM that is not tycana-*.
set -euo pipefail

cmd=${1:-}; vm=${2:-}
case "$vm" in tycana-*) ;; *) echo "usage: $0 compare|capture tycana-VM [NAME]" >&2; exit 2;; esac

# Must equal rpm.QueryFormat (cmd/tycana tests check this).
FORMAT='%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{SIZE}\t%{SIGMD5}\t%{SUMMARY}\n'

root=$(cd "$(dirname "$0")/.." && pwd)
make -C "$root" -s build
limactl shell "$vm" -- sh -c 'rm -rf /tmp/tycana-lab && mkdir -m 700 /tmp/tycana-lab'
limactl copy "$root/bin/tycana" "$vm:/tmp/tycana-lab/tycana"
trap 'limactl shell "$vm" -- rm -rf /tmp/tycana-lab' EXIT

remote() { limactl shell "$vm" -- sh -c "$1"; }

case "$cmd" in
compare)
  remote "cd /tmp/tycana-lab && set -e
    LC_ALL=C rpm -qa --qf '$FORMAT' > before.tsv
    ./tycana inventory --format rpm-query > tycana.tsv
    ./tycana inventory > text.txt
    LC_ALL=C rpm -qa --qf '$FORMAT' > after.tsv
    if ! cmp -s before.tsv after.tsv; then echo 'package database changed during the run; rerun' >&2; exit 3; fi
    echo \"host:        \$(. /etc/os-release; echo \$PRETTY_NAME), \$(uname -r), \$(rpm --version)\"
    echo \"run as:      \$(id -un) (uid \$(id -u))\"
    echo \"packages:    \$(wc -l < tycana.tsv)\"
    if cmp -s before.tsv tycana.tsv; then echo 'rpm -qa:     byte-identical' \$(sha256sum < tycana.tsv | cut -c1-16); else echo 'rpm -qa:     DIFFERENT'; diff before.tsv tycana.tsv | head -20; exit 1; fi
    if grep -q \"^Kernel running  \$(uname -r)\$\" text.txt; then echo 'kernel:      running release agrees with uname -r'; else echo 'kernel:      DIFFERENT'; grep Kernel text.txt; exit 1; fi"
  ;;
capture)
  name=${3:?capture needs a fixture NAME}
  dest="$root/testdata/lab/$name"
  rm -rf "$dest" && mkdir -p "$dest/root/var/lib/rpm" "$dest/root/var/lib/dnf" "$dest/expected"
  remote "cd / && tar cf - etc/os-release usr/lib/os-release 2>/dev/null; true" | tar xf - -C "$dest/root"
  # The zone the host shows local times in (etc/localtime is a symlink; take its target too).
  remote 'cd / && tar cf - etc/localtime "$(readlink -f /etc/localtime | cut -c2-)" 2>/dev/null; true' | tar xf - -C "$dest/root"
  # The agent reads only the Packages table of rpmdb.sqlite. Copy that
  # table alone (headers byte for byte, header numbers kept) and gzip it:
  # the index tables would triple a fixture that is already large.
  # history.sqlite is small; VACUUM INTO folds its write-ahead log into a
  # plain copy. Both copies are made by opening the originals read-only.
  remote "python3 -I - <<'PY'
import gzip, sqlite3
src = sqlite3.connect('file:/var/lib/rpm/rpmdb.sqlite?mode=ro', uri=True)
dst = sqlite3.connect('/tmp/tycana-lab/rpmdb.sqlite')
dst.execute(\"CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL)\")
dst.executemany('INSERT INTO Packages(hnum, blob) VALUES (?, ?)', src.execute('SELECT hnum, blob FROM Packages ORDER BY hnum'))
dst.commit(); dst.close()
with open('/tmp/tycana-lab/rpmdb.sqlite', 'rb') as f, gzip.open('/tmp/tycana-lab/rpmdb.sqlite.gz', 'wb', compresslevel=9) as g:
    g.write(f.read())
sqlite3.connect('file:/var/lib/dnf/history.sqlite?mode=ro', uri=True).execute(\"VACUUM INTO '/tmp/tycana-lab/history.sqlite'\")
PY"
  limactl copy "$vm:/tmp/tycana-lab/rpmdb.sqlite.gz" "$dest/root/var/lib/rpm/rpmdb.sqlite.gz"
  limactl copy "$vm:/tmp/tycana-lab/history.sqlite" "$dest/root/var/lib/dnf/history.sqlite"
  # /proc files report size 0, so tar would store them empty; read them instead.
  mkdir -p "$dest/root/proc/sys/kernel" "$dest/root/boot"
  for f in osrelease version; do remote "cat /proc/sys/kernel/$f" > "$dest/root/proc/sys/kernel/$f"; done
  for k in $(remote 'ls /boot | grep "^vmlinuz-"'); do : > "$dest/root/boot/$k"; done
  remote "LC_ALL=C rpm -qa --qf '$FORMAT'" > "$dest/expected/rpm-qa.tsv"
  remote 'uname -r' > "$dest/expected/uname-r.txt"
  remote 'LC_ALL=C TZ=UTC dnf history list 2>/dev/null' > "$dest/expected/dnf-history.txt"
  # dnf resolves the recorded uid to a login name at display time; this repo is public.
  n=$(remote 'dnf history list 2>/dev/null | awk "NR==3{print \$1}"')
  for i in $(seq 1 "$n"); do remote "LC_ALL=C TZ=UTC dnf history info $i 2>/dev/null"; echo; done \
    | sed -E 's/^(User +: ).*/\1operator/' > "$dest/expected/dnf-history-info.txt"
  {
    echo "Captured $(date -u +%Y-%m-%dT%H:%M:%SZ) from Lima VM $vm by scripts/lab-rpm.sh."
    echo "Host: $(remote '. /etc/os-release; echo $PRETTY_NAME'), kernel $(cat "$dest/expected/uname-r.txt"), $(remote 'rpm --version'), $(remote 'dnf --version | head -1 | sed "s/^/dnf /"')."
    echo "root/ holds copies of the files the agent reads; boot/vmlinuz-* are empty placeholders."
    echo "var/lib/rpm/rpmdb.sqlite.gz is the Packages table of the host's rpmdb.sqlite, gzipped: the only table the agent reads, headers unmodified."
    echo "var/lib/dnf/history.sqlite is a VACUUM INTO copy of the host's dnf history (write-ahead log folded in, nothing else changed)."
    echo "The User line in expected/dnf-history-info.txt is replaced with 'operator'; nothing else is edited."
    echo "expected/ holds the native tools' output on the same host at the same moment (C locale, UTC)."
  } > "$dest/MANIFEST"
  ls -l "$dest/root/var/lib/rpm" "$dest/root/var/lib/dnf" "$dest/expected"
  ;;
*) echo "usage: $0 compare|capture tycana-VM [NAME]" >&2; exit 2;;
esac
