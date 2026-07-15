#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

fake_bin="${test_root}/bin"
download_dir="${test_root}/download"
moved_download_dir="${test_root}/download-moved"
install_dir="${test_root}/install"
public_key_path="${test_root}/cosign.pub"

mkdir -p "$fake_bin"
printf '%s\n' 'fixture public key' > "$public_key_path"

cat > "${fake_bin}/fixture-command" <<'EOF'
#!/usr/bin/env sh
set -eu

command_name="$(basename -- "$0")"

case "$command_name" in
  cosign|jq)
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
          'mitoriq-collector_1.2.3_linux_amd64.tar.gz' > "$output"
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
      printf '%s\n' 'LICENSE' 'mitoriq-collector' 'mitoriq-collector.sig'
    else
      : > "$3"
    fi
    ;;
  uname)
    case "${1:-}" in
      -s) printf '%s\n' 'Linux' ;;
      -m) printf '%s\n' 'x86_64' ;;
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

for command_name in cosign curl install jq mktemp openssl tar uname; do
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
