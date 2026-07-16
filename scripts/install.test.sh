#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

fake_bin="${test_root}/bin"
download_dir="${test_root}/download"
moved_download_dir="${test_root}/download-moved"
install_dir="${test_root}/install"
darwin_download_dir="${test_root}/download-darwin"
darwin_moved_download_dir="${test_root}/download-darwin-moved"
darwin_install_dir="${test_root}/install-darwin"
darwin_verify_dir="${test_root}/verify-darwin"
public_key_path="${test_root}/cosign.pub"

mkdir -p "$fake_bin" "$darwin_verify_dir"
printf '%s\n' 'fixture public key' > "$public_key_path"

cat > "${fake_bin}/fixture-command" <<'EOF'
#!/usr/bin/env sh
set -eu

command_name="$(basename -- "$0")"

case "$command_name" in
  cosign|jq)
    exit 0
    ;;
  codesign)
    : > "${INSTALL_TEST_MACOS_VERIFY_DIR}/codesign"
    if [ "${1:-}" = "-dv" ]; then
      printf '%s\n' 'TeamIdentifier=TEAMID1234' >&2
    fi
    exit 0
    ;;
  spctl)
    : > "${INSTALL_TEST_MACOS_VERIFY_DIR}/spctl"
    exit 0
    ;;
  curl)
    output=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "-o" ]; then
        output="$2"
        shift 2
      else
        shift
      fi
    done
    case "$output" in
      */checksums.txt)
        printf '%s  %s\n' \
          'fixture-sha256' \
          "${INSTALL_TEST_ARCHIVE_NAME:-mitoriq-collector_1.2.3_linux_amd64.tar.gz}" > "$output"
        ;;
      *)
        : > "$output"
        ;;
    esac
    ;;
  install)
    mkdir -p "$(dirname -- "$4")"
    cp "$3" "$4"
    chmod 0755 "$4"
    mv "$INSTALL_TEST_DOWNLOAD_DIR" "$INSTALL_TEST_MOVED_DOWNLOAD_DIR"
    ;;
  mktemp)
    mkdir -p "$INSTALL_TEST_DOWNLOAD_DIR"
    printf '%s\n' "$INSTALL_TEST_DOWNLOAD_DIR"
    ;;
  openssl)
    if [ "${1:-}" = "pkey" ] && printf '%s\n' "$*" | grep -q -- '-text'; then
      printf '%s\n' 'ASN1 OID: prime256v1'
    elif [ "${1:-}" = "pkey" ]; then
      printf '%s\n' 'fixture DER'
    else
      printf '%s\n' 'SHA2-256(fixture)= fixture-sha256'
    fi
    ;;
  tar)
    if [ "${1:-}" = "-tzf" ]; then
      case "${INSTALL_TEST_TAR_MODE:-valid}" in
        valid)
          if [ "${INSTALL_TEST_UNAME_S:-Linux}" = "Darwin" ]; then
            printf '%s\n' \
              'LICENSE' \
              'NOTICE' \
              'THIRD_PARTY_NOTICES.md' \
              'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
              'THIRD_PARTY_LICENSES/modernc.org/libc/LICENSE-3RD-PARTY.md' \
              'mitoriq-collector'
          else
            printf '%s\n' \
              'LICENSE' \
              'NOTICE' \
              'THIRD_PARTY_NOTICES.md' \
              'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
              'THIRD_PARTY_LICENSES/modernc.org/libc/LICENSE-3RD-PARTY.md' \
              'mitoriq-collector' \
              'mitoriq-collector.sig'
          fi
          ;;
        traversal)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/../payload' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        unexpected)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'payload' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        missing-signature)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector'
          ;;
        extra-signature)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        duplicate-license)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        missing-notice)
          printf '%s\n' \
            'LICENSE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        missing-license)
          printf '%s\n' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        missing-third-party-notices)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        missing-binary)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'THIRD_PARTY_LICENSES/github.com/google/uuid/LICENSE' \
            'mitoriq-collector.sig'
          ;;
        missing-third-party)
          printf '%s\n' \
            'LICENSE' \
            'NOTICE' \
            'THIRD_PARTY_NOTICES.md' \
            'mitoriq-collector' \
            'mitoriq-collector.sig'
          ;;
        *) exit 1 ;;
      esac
    else
      : > "$3"
    fi
    ;;
  uname)
    case "${1:-}" in
      -s) printf '%s\n' "${INSTALL_TEST_UNAME_S:-Linux}" ;;
      -m) printf '%s\n' "${INSTALL_TEST_UNAME_M:-x86_64}" ;;
      *) exit 1 ;;
    esac
    ;;
  *)
    printf 'unexpected fixture command: %s\n' "$command_name" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${fake_bin}/fixture-command"

for command_name in codesign cosign curl install jq mktemp openssl spctl tar uname; do
  ln -s fixture-command "${fake_bin}/${command_name}"
done

set +e
output="$(
  LC_ALL=C \
    PATH="${fake_bin}:$PATH" \
    MITORIQ_COLLECTOR_INSTALL_DIR="$install_dir" \
    MITORIQ_COLLECTOR_PUBLIC_KEY_PATH="$public_key_path" \
    MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256='fixture-sha256' \
    MITORIQ_COLLECTOR_VERSION='v1.2.3' \
    INSTALL_TEST_DOWNLOAD_DIR="$download_dir" \
    INSTALL_TEST_MOVED_DOWNLOAD_DIR="$moved_download_dir" \
    sh "${script_dir}/install.sh" 2>&1
)"
status=$?
set -e

if [ "$status" -ne 0 ]; then
  printf 'installer exited with status %s:\n%s\n' "$status" "$output" >&2
  exit 1
fi

if printf '%s\n' "$output" | grep -q 'No such file or directory'; then
  printf 'EXIT cleanup reported a missing temp directory:\n%s\n' "$output" >&2
  exit 1
fi

if [ ! -x "${install_dir}/mitoriq-collector" ]; then
  printf '%s\n' 'collector binary was not installed' >&2
  exit 1
fi

if [ -e "$download_dir" ]; then
  printf '%s\n' 'installer temp directory still exists' >&2
  exit 1
fi

set +e
darwin_output="$(
  LC_ALL=C \
    PATH="${fake_bin}:$PATH" \
    MITORIQ_COLLECTOR_INSTALL_DIR="$darwin_install_dir" \
    MITORIQ_COLLECTOR_PUBLIC_KEY_PATH="$public_key_path" \
    MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256='fixture-sha256' \
    MITORIQ_COLLECTOR_MACOS_TEAM_ID='TEAMID1234' \
    MITORIQ_COLLECTOR_VERSION='v1.2.3' \
    INSTALL_TEST_ARCHIVE_NAME='mitoriq-collector_1.2.3_darwin_arm64.tar.gz' \
    INSTALL_TEST_DOWNLOAD_DIR="$darwin_download_dir" \
    INSTALL_TEST_MACOS_VERIFY_DIR="$darwin_verify_dir" \
    INSTALL_TEST_MOVED_DOWNLOAD_DIR="$darwin_moved_download_dir" \
    INSTALL_TEST_UNAME_M='arm64' \
    INSTALL_TEST_UNAME_S='Darwin' \
    sh "${script_dir}/install.sh" 2>&1
)"
darwin_status=$?
set -e

if [ "$darwin_status" -ne 0 ]; then
  printf 'macOS installer exited with status %s:\n%s\n' "$darwin_status" "$darwin_output" >&2
  exit 1
fi
if [ ! -x "${darwin_install_dir}/mitoriq-collector" ]; then
  printf '%s\n' 'macOS collector binary was not installed' >&2
  exit 1
fi
if [ ! -e "${darwin_verify_dir}/codesign" ] || [ ! -e "${darwin_verify_dir}/spctl" ]; then
  printf '%s\n' 'macOS signature or Gatekeeper verification was not reached' >&2
  exit 1
fi
if [ -e "$darwin_download_dir" ]; then
  printf '%s\n' 'macOS installer temp directory still exists' >&2
  exit 1
fi

for tar_mode in \
  traversal \
  unexpected \
  missing-signature \
  duplicate-license \
  missing-license \
  missing-notice \
  missing-third-party-notices \
  missing-binary \
  missing-third-party; do
  rejected_install_dir="${test_root}/install-${tar_mode}"
  set +e
  rejected_output="$(
    LC_ALL=C \
      PATH="${fake_bin}:$PATH" \
      MITORIQ_COLLECTOR_INSTALL_DIR="$rejected_install_dir" \
      MITORIQ_COLLECTOR_PUBLIC_KEY_PATH="$public_key_path" \
      MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256='fixture-sha256' \
      MITORIQ_COLLECTOR_VERSION='v1.2.3' \
      INSTALL_TEST_DOWNLOAD_DIR="$download_dir" \
      INSTALL_TEST_MOVED_DOWNLOAD_DIR="$moved_download_dir" \
      INSTALL_TEST_TAR_MODE="$tar_mode" \
      sh "${script_dir}/install.sh" 2>&1
  )"
  rejected_status=$?
  set -e

  if [ "$rejected_status" -eq 0 ]; then
    printf 'installer accepted invalid archive mode: %s\n' "$tar_mode" >&2
    exit 1
  fi
  if ! printf '%s\n' "$rejected_output" | grep -q 'release archive contains unexpected entries'; then
    printf 'installer returned an unexpected error for %s:\n%s\n' "$tar_mode" "$rejected_output" >&2
    exit 1
  fi
  if [ -e "${rejected_install_dir}/mitoriq-collector" ]; then
    printf 'installer wrote a binary for invalid archive mode: %s\n' "$tar_mode" >&2
    exit 1
  fi
done

rejected_darwin_install_dir="${test_root}/install-darwin-extra-signature"
set +e
rejected_darwin_output="$(
  LC_ALL=C \
    PATH="${fake_bin}:$PATH" \
    MITORIQ_COLLECTOR_INSTALL_DIR="$rejected_darwin_install_dir" \
    MITORIQ_COLLECTOR_PUBLIC_KEY_PATH="$public_key_path" \
    MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256='fixture-sha256' \
    MITORIQ_COLLECTOR_MACOS_TEAM_ID='TEAMID1234' \
    MITORIQ_COLLECTOR_VERSION='v1.2.3' \
    INSTALL_TEST_ARCHIVE_NAME='mitoriq-collector_1.2.3_darwin_arm64.tar.gz' \
    INSTALL_TEST_DOWNLOAD_DIR="$darwin_download_dir" \
    INSTALL_TEST_MACOS_VERIFY_DIR="$darwin_verify_dir" \
    INSTALL_TEST_MOVED_DOWNLOAD_DIR="$darwin_moved_download_dir" \
    INSTALL_TEST_TAR_MODE='extra-signature' \
    INSTALL_TEST_UNAME_M='arm64' \
    INSTALL_TEST_UNAME_S='Darwin' \
    sh "${script_dir}/install.sh" 2>&1
)"
rejected_darwin_status=$?
set -e

if [ "$rejected_darwin_status" -eq 0 ]; then
  printf '%s\n' 'macOS installer accepted an archive with a Linux signature' >&2
  exit 1
fi
if ! printf '%s\n' "$rejected_darwin_output" | grep -q 'release archive contains unexpected entries'; then
  printf 'macOS installer returned an unexpected error:\n%s\n' "$rejected_darwin_output" >&2
  exit 1
fi
if [ -e "${rejected_darwin_install_dir}/mitoriq-collector" ]; then
  printf '%s\n' 'macOS installer wrote a binary from an invalid archive' >&2
  exit 1
fi
