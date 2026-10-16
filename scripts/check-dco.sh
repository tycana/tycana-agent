#!/usr/bin/env bash
# Every commit in the range must carry a Developer Certificate of Origin
# sign-off (see DCO and CONTRIBUTING.md). Usage: check-dco.sh <base>..<head>
set -euo pipefail
range=${1:?usage: check-dco.sh <base>..<head>}
status=0
while read -r sha; do
  if ! git show -s --format=%B "$sha" | grep -qE '^Signed-off-by: .+ <.+@.+>$'; then
    echo "missing Signed-off-by: $(git show -s --format='%h %s' "$sha")" >&2
    status=1
  fi
done < <(git rev-list --no-merges "$range")
[ $status -eq 0 ] && echo "dco: all commits signed off"
exit $status
