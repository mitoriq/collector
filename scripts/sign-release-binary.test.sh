#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

fake_bin="${test_root}/bin"
mkdir -p "$fake_bin"
printf '%s\n' 'fixture private key' > "${test_root}/cosign.key"

cat > "${fake_bin}/cosign" <<'EOF'
#!/usr/bin/env sh
set -eu

output=""
artifact=""
for argument in "$@"; do
  case "$argument" in
    sign-blob|--yes|--key=*) ;;
    --output-signature=*) output="${argument#--output-signature=}" ;;
    *) artifact="$argument" ;;
  esac
done

if [ -z "$output" ] || [ -z "$artifact" ] || [ ! -f "$artifact" ]; then
  exit 1
fi

cat >/dev/null
printf 'signature for %s\n' "$(basename -- "$artifact")" > "$output"
if [ "${SIGN_TEST_COSIGN_FAIL_AFTER_WRITE:-false}" = "true" ]; then
  exit 1
fi
EOF
chmod +x "${fake_bin}/cosign"

cat > "${fake_bin}/go" <<'EOF'
#!/usr/bin/env sh
set -eu

if [ "${1:-}" != "version" ] || [ "${2:-}" != "-m" ] || [ ! -f "${3:-}" ]; then
  exit 1
fi
printf '%s\n' \
  "${3}: go1.24.0" \
  "        build   GOOS=${SIGN_TEST_GOOS}" \
  "        build   GOARCH=${SIGN_TEST_GOARCH}"
EOF
chmod +x "${fake_bin}/go"

real_ln="$(command -v ln)"
cat > "${fake_bin}/ln" <<'EOF'
#!/usr/bin/env sh
set -eu

if [ "${SIGN_TEST_LN_FAIL_SECOND:-false}" = "true" ]; then
  count=0
  if [ -f "$SIGN_TEST_LN_COUNT_FILE" ]; then
    count="$(cat "$SIGN_TEST_LN_COUNT_FILE")"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$SIGN_TEST_LN_COUNT_FILE"
  if [ "$count" -eq 2 ]; then
    exit 1
  fi
fi

exec "$SIGN_TEST_REAL_LN" "$@"
EOF
chmod +x "${fake_bin}/ln"

assert_absent() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    printf 'unexpected path remains: %s\n' "$1" >&2
    exit 1
  fi
}

assert_no_temporary_signature() {
  for candidate in "$1"/.mitoriq-collector-signature.*; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      printf 'temporary signature remains: %s\n' "$candidate" >&2
      exit 1
    fi
  done
}

invoke_helper() {
  printf 'fixture password\n' | \
    PATH="${fake_bin}:$PATH" \
    COSIGN_KEY_PATH="${test_root}/cosign.key" \
    SIGN_TEST_REAL_LN="$real_ln" \
    SIGN_TEST_GOARCH="$3" \
    SIGN_TEST_GOOS="$4" \
    sh "${script_dir}/sign-release-binary.sh" "$1" "$2"
}

for goarch in amd64 arm64; do
  case "$goarch" in
    amd64) variant='v1' ;;
    arm64) variant='v8.0' ;;
  esac
  dist_dir="${test_root}/positive-${goarch}/dist"
  target_dir="${dist_dir}/mitoriq-collector-linux_linux_${goarch}_${variant}"
  artifact="${target_dir}/mitoriq-collector"
  signature="${artifact}_linux_${goarch}.sig"
  archive_signature="${dist_dir}/archive-signatures/linux_${goarch}/mitoriq-collector.sig"
  mkdir -p "$target_dir"
  printf 'collector %s\n' "$goarch" > "$artifact"

  invoke_helper "$artifact" "$signature" "$goarch" linux

  if [ ! -s "$signature" ]; then
    printf 'target signature was not created: %s\n' "$signature" >&2
    exit 1
  fi
  if ! cmp -s "$signature" "$archive_signature"; then
    printf 'archive signature copy does not match target signature: %s\n' "$goarch" >&2
    exit 1
  fi
done

protected_dist="${test_root}/protected/dist"
protected_dir="${protected_dist}/mitoriq-collector-linux_linux_amd64_v1"
protected_artifact="${protected_dir}/mitoriq-collector"
protected_signature="${protected_artifact}_linux_amd64.sig"
protected_archive_signature="${protected_dist}/archive-signatures/linux_amd64/mitoriq-collector.sig"
mkdir -p "$protected_dir" "$(dirname -- "$protected_archive_signature")"
printf '%s\n' 'collector' > "$protected_artifact"
printf '%s\n' 'do not replace' > "$protected_archive_signature"

if invoke_helper "$protected_artifact" "$protected_signature" amd64 linux >/dev/null 2>&1; then
  printf '%s\n' 'sign helper overwrote an existing archive signature' >&2
  exit 1
fi
if [ "$(cat "$protected_archive_signature")" != 'do not replace' ]; then
  printf '%s\n' 'existing archive signature content changed' >&2
  exit 1
fi

target_exists_dist="${test_root}/target-exists/dist"
target_exists_dir="${target_exists_dist}/mitoriq-collector-linux_linux_arm64_v8.0"
target_exists_artifact="${target_exists_dir}/mitoriq-collector"
target_exists_signature="${target_exists_artifact}_linux_arm64.sig"
target_exists_archive_signature="${target_exists_dist}/archive-signatures/linux_arm64/mitoriq-collector.sig"
mkdir -p "$target_exists_dir"
printf '%s\n' 'collector' > "$target_exists_artifact"
printf '%s\n' 'do not replace' > "$target_exists_signature"

if invoke_helper "$target_exists_artifact" "$target_exists_signature" arm64 linux >/dev/null 2>&1; then
  printf '%s\n' 'sign helper overwrote an existing target signature' >&2
  exit 1
fi
if [ "$(cat "$target_exists_signature")" != 'do not replace' ]; then
  printf '%s\n' 'existing target signature content changed' >&2
  exit 1
fi
assert_absent "$target_exists_archive_signature"

invalid_dist="${test_root}/invalid/dist"
invalid_dir="${invalid_dist}/mitoriq-collector-linux_linux_riscv64_v1"
invalid_artifact="${invalid_dir}/mitoriq-collector"
mkdir -p "$invalid_dir"
printf '%s\n' 'collector' > "$invalid_artifact"

if invoke_helper \
  "$invalid_artifact" \
  "${invalid_artifact}_linux_riscv64.sig" \
  riscv64 \
  linux \
  >/dev/null 2>&1; then
  printf '%s\n' 'sign helper accepted an unsupported target signature name' >&2
  exit 1
fi

mismatch_dist="${test_root}/mismatch/dist"
mismatch_dir="${mismatch_dist}/mitoriq-collector-linux_linux_amd64_v1"
mismatch_artifact="${mismatch_dir}/mitoriq-collector"
mkdir -p "$mismatch_dir"
printf '%s\n' 'collector' > "$mismatch_artifact"

if invoke_helper \
  "$mismatch_artifact" \
  "${mismatch_artifact}_linux_amd64.sig" \
  arm64 \
  linux \
  >/dev/null 2>&1; then
  printf '%s\n' 'sign helper accepted a binary for a different architecture' >&2
  exit 1
fi

cosign_failure_dist="${test_root}/cosign-failure/dist"
cosign_failure_dir="${cosign_failure_dist}/mitoriq-collector-linux_linux_amd64_v1"
cosign_failure_artifact="${cosign_failure_dir}/mitoriq-collector"
cosign_failure_signature="${cosign_failure_artifact}_linux_amd64.sig"
cosign_failure_archive="${cosign_failure_dist}/archive-signatures/linux_amd64/mitoriq-collector.sig"
mkdir -p "$cosign_failure_dir"
printf '%s\n' 'collector' > "$cosign_failure_artifact"

if SIGN_TEST_COSIGN_FAIL_AFTER_WRITE=true \
  invoke_helper "$cosign_failure_artifact" "$cosign_failure_signature" amd64 linux \
  >/dev/null 2>&1; then
  printf '%s\n' 'sign helper accepted a failed cosign invocation' >&2
  exit 1
fi
assert_absent "$cosign_failure_signature"
assert_absent "$cosign_failure_archive"
assert_no_temporary_signature "$cosign_failure_dir"

link_failure_dist="${test_root}/link-failure/dist"
link_failure_dir="${link_failure_dist}/mitoriq-collector-linux_linux_arm64_v8.0"
link_failure_artifact="${link_failure_dir}/mitoriq-collector"
link_failure_signature="${link_failure_artifact}_linux_arm64.sig"
link_failure_archive="${link_failure_dist}/archive-signatures/linux_arm64/mitoriq-collector.sig"
link_count_file="${test_root}/link-count"
mkdir -p "$link_failure_dir"
printf '%s\n' 'collector' > "$link_failure_artifact"

if SIGN_TEST_LN_FAIL_SECOND=true \
  SIGN_TEST_LN_COUNT_FILE="$link_count_file" \
  invoke_helper "$link_failure_artifact" "$link_failure_signature" arm64 linux \
  >/dev/null 2>&1; then
  printf '%s\n' 'sign helper accepted a partial signature publication' >&2
  exit 1
fi
assert_absent "$link_failure_signature"
assert_absent "$link_failure_archive"
assert_no_temporary_signature "$link_failure_dir"
