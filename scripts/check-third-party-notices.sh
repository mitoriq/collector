#!/usr/bin/env bash
set -euo pipefail

collector_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
module_path="$(awk '$1 == "module" { print $2; exit }' "$collector_root/go.mod")"
temp_dir="$(mktemp -d)"
linked_modules="$temp_dir/linked-modules.txt"
documented_modules="$temp_dir/documented-modules.txt"
go_cache_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
go_cache="$go_cache_root/mitoriq-collector-go-build-cache"

mkdir -p "$go_cache"

cleanup() {
  rm -f "$linked_modules" "$documented_modules"
  rmdir "$temp_dir"
}
trap cleanup EXIT

(
  cd "$collector_root"
  targets=(
    darwin/amd64
    darwin/arm64
    linux/amd64
    linux/arm64
    windows/amd64
    windows/arm64
  )
  for target in "${targets[@]}"; do
    GOOS="${target%%/*}" \
      GOARCH="${target##*/}" \
      CGO_ENABLED=0 \
      GOCACHE="$go_cache" \
      go list -deps -f '{{with .Module}}{{.Path}} {{.Version}}{{end}}' ./cmd/mitoriq-collector
  done
) | awk -v own="$module_path" 'NF == 2 && $1 != own' | LC_ALL=C sort -u > "$linked_modules"

awk -F '|' '
  /^\| `/ {
    module = $2
    version = $3
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", module)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", version)
    gsub(/`/, "", module)
    gsub(/`/, "", version)
    print module " " version
  }
' "$collector_root/THIRD_PARTY_NOTICES.md" | LC_ALL=C sort -u > "$documented_modules"

if ! diff -u "$linked_modules" "$documented_modules"; then
  echo "third-party notice inventory does not match linked Go modules" >&2
  exit 1
fi

echo "third-party notice inventory is current"
