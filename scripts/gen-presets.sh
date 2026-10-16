#!/usr/bin/env bash
# Regenerate internal/baseline/presets/ from a ComplianceAsCode checkout.
#
#   scripts/gen-presets.sh /path/to/ComplianceAsCode/content
#
# Runs ComplianceAsCode's own compiler (build-scripts/compile_product.py and
# compile_all.py; needs python3 with jinja2 and PyYAML, no cmake), then
# tools/cacconv for each product. Only products checked against OpenSCAP on
# a lab VM are listed (testdata/lab/*/baseline*); add one only with its
# lab comparison.
set -euo pipefail

cac=${1:?usage: $0 CONTENT-CHECKOUT}
cac=$(cd "$cac" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

commit=$(git -C "$cac" rev-parse HEAD)
version=$(sed -n 's/^set(SSG_\(MAJOR\|MINOR\|PATCH\)_VERSION \([0-9]*\))$/\2/p' "$cac/CMakeLists.txt" | paste -sd.)
read -r major minor patch <<<"${version//./ }"
cat >"$work/build_config.yml" <<CFG
cmake_build_type: "Release"
ssg_version: [$major, $minor, $patch]
ssg_version_str: "$version"
jinja2_cache_enabled: false
jinja2_cache_dir: ""
sce_enabled: "OFF"
CFG

# product  profile  os-release ID:VERSION_ID  preset name  title
presets=(
  "ubuntu2404 cis_level1_server ubuntu:24.04 ubuntu2404-level1-server Ubuntu 24.04 level 1 server baseline"
  "debian12 cis_level1_server debian:12 debian12-level1-server Debian 12 level 1 server baseline"
  "almalinux9 cis_server_l1 almalinux:9 almalinux9-level1-server AlmaLinux 9 level 1 server baseline"
)

for line in "${presets[@]}"; do
  read -r product profile applies name title <<<"$line"
  out="$work/$product"
  mkdir -p "$out"
  PYTHONPATH=$cac python3 "$cac/build-scripts/compile_product.py" \
    --product-yaml "$cac/products/$product/product.yml" \
    --product-properties "$cac/product_properties" \
    --compiled-product-yaml "$out/product.yml"
  echo '{}' >"$out/sce.json"
  PYTHONPATH=$cac python3 "$cac/build-scripts/compile_all.py" --resolved-base "$out" \
    --project-root "$cac" --build-config-yaml "$work/build_config.yml" \
    --product-yaml "$out/product.yml" --sce-metadata "$out/sce.json" >"$work/compile.log" 2>&1 || { cat "$work/compile.log" >&2; exit 1; }
  (cd "$root" && go run ./tools/cacconv -in "$out" -product "$product" -profile "$profile" \
    -name "$name" -title "$title" -commit "$commit" -version "$version" -applies "$applies") \
    >"$root/internal/baseline/presets/$name.yaml"
  echo "$name: $(grep -c '^  - id:' "$root/internal/baseline/presets/$name.yaml") entries"
done
