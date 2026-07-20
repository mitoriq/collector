#!/usr/bin/env sh
set -eu

repo="mitoriq/collector"
requested_version="${MITORIQ_COLLECTOR_VERSION:-latest}"
install_dir="${MITORIQ_COLLECTOR_INSTALL_DIR:-$HOME/.local/bin}"
public_key_path="${MITORIQ_COLLECTOR_PUBLIC_KEY_PATH:-}"
public_key_sha256="${MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256:-}"
macos_team_id="${MITORIQ_COLLECTOR_MACOS_TEAM_ID:-}"

if [ -z "$public_key_path" ]; then
  echo "MITORIQ_COLLECTOR_PUBLIC_KEY_PATH is required" >&2
  exit 1
fi

if [ ! -r "$public_key_path" ]; then
  echo "trusted collector public key is not readable: $public_key_path" >&2
  exit 1
fi
case "$public_key_path" in
  /*) ;;
  *) public_key_path="$(pwd)/$public_key_path" ;;
esac

if [ -z "$public_key_sha256" ]; then
  echo "MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256 is required" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to verify the collector release" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to verify the collector public key" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to resolve the collector release" >&2
  exit 1
fi

actual_public_key_sha256="$(openssl pkey -pubin -in "$public_key_path" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
if ! openssl pkey -pubin -in "$public_key_path" -text -noout | grep -q "ASN1 OID: prime256v1"; then
  echo "trusted collector public key must be ECDSA P-256" >&2
  exit 1
fi
if [ "$actual_public_key_sha256" != "$public_key_sha256" ]; then
  echo "trusted collector public key fingerprint does not match" >&2
  exit 1
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  darwin|linux) ;;
  *) echo "unsupported operating system: $os" >&2; exit 1 ;;
esac

if [ "$os" = "darwin" ] && [ -z "$macos_team_id" ]; then
  echo "MITORIQ_COLLECTOR_MACOS_TEAM_ID is required on macOS" >&2
  exit 1
fi
if [ "$os" = "darwin" ] && ! printf '%s' "$macos_team_id" | grep -Eq '^[A-Z0-9]{10}$'; then
  echo "MITORIQ_COLLECTOR_MACOS_TEAM_ID must be a 10-character Apple Team ID" >&2
  exit 1
fi

case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

binary_signature="mitoriq-collector_${os}_${arch}.sig"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

download() {
  url="$1"
  max_bytes="$2"
  output="$3"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-time 60 --max-filesize "$max_bytes" \
    "$url" -o "$output"
}

validate_archive_entries() {
  archive_os="$1"
  expected_signature="$2"
  awk -v archive_os="$archive_os" -v expected_signature="$expected_signature" '
    {
      if ($0 == "" || seen[$0]++) {
        exit 1
      }
      if ($0 == "LICENSE") {
        license_count++
        next
      }
      if ($0 == "NOTICE") {
        notice_count++
        next
      }
      if ($0 == "THIRD_PARTY_NOTICES.md") {
        notices_count++
        next
      }
      if ($0 == "mitoriq-collector") {
        binary_count++
        next
      }
      if ($0 == expected_signature) {
        signature_count++
        next
      }
      if (index($0, "THIRD_PARTY_LICENSES/") == 1) {
        path = substr($0, length("THIRD_PARTY_LICENSES/") + 1)
        if (path == "" || path ~ /(^|\/)\.\.?($|\/)/ || path ~ /\/\// || path ~ /\/$/) {
          exit 1
        }
        third_party_license_count++
        next
      }
      exit 1
    }
    END {
      expected_signature_count = archive_os == "linux" ? 1 : 0
      if (license_count != 1 || notice_count != 1 || notices_count != 1 ||
          binary_count != 1 || signature_count != expected_signature_count ||
          third_party_license_count < 1) {
        exit 1
      }
    }
  '
}

if [ "$requested_version" = "latest" ]; then
  download "https://api.github.com/repos/${repo}/releases/latest" 1048576 "${tmp_dir}/release.json"
  tag="$(jq -er '.tag_name' "${tmp_dir}/release.json")"
elif [ "${requested_version#v}" != "$requested_version" ]; then
  tag="$requested_version"
else
  tag="v${requested_version}"
fi

if ! printf '%s' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "release tag must be a stable semantic version" >&2
  exit 1
fi

artifact_version="${tag#v}"
archive="mitoriq-collector_${artifact_version}_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${tag}"

download "${base_url}/checksums.txt" 4194304 "${tmp_dir}/checksums.txt"
download "${base_url}/checksums.txt.sig" 16384 "${tmp_dir}/checksums.txt.sig"

cosign verify-blob \
  --key "$public_key_path" \
  --signature "${tmp_dir}/checksums.txt.sig" \
  "${tmp_dir}/checksums.txt"

checksum_line="$(awk -v name="$archive" '$2 == name { print }' "${tmp_dir}/checksums.txt")"
if [ -z "$checksum_line" ] || [ "$(printf '%s\n' "$checksum_line" | wc -l | tr -d ' ')" != "1" ]; then
  echo "release checksum entry is missing or duplicated: $archive" >&2
  exit 1
fi

download "${base_url}/${archive}" 134217728 "${tmp_dir}/${archive}"

(
  cd "$tmp_dir"
  expected_checksum="$(printf '%s\n' "$checksum_line" | awk '{print $1}')"
  actual_checksum="$(openssl dgst -sha256 "$archive" | awk '{print $NF}')"
  if [ "$actual_checksum" != "$expected_checksum" ]; then
    echo "release archive checksum does not match: $archive" >&2
    exit 1
  fi

  entries="$(tar -tzf "$archive" | LC_ALL=C sort)"
  if ! printf '%s\n' "$entries" | validate_archive_entries "$os" "$binary_signature"; then
    echo "release archive contains unexpected entries" >&2
    exit 1
  fi

  tar -xzf "$archive" mitoriq-collector
  if [ "$os" = "linux" ]; then
    tar -xzf "$archive" "$binary_signature"
    cosign verify-blob \
      --key "$public_key_path" \
      --signature "$binary_signature" \
      mitoriq-collector
  else
    codesign --verify --strict --verbose=2 mitoriq-collector
    actual_team_id="$(codesign -dv --verbose=4 mitoriq-collector 2>&1 | sed -n 's/^TeamIdentifier=//p')"
    if [ "$actual_team_id" != "$macos_team_id" ]; then
      echo "collector Developer ID Team ID does not match" >&2
      exit 1
    fi
    spctl --assess --type execute --verbose=4 mitoriq-collector
  fi
)

mkdir -p "$install_dir"
install -m 0755 "${tmp_dir}/mitoriq-collector" "${install_dir}/mitoriq-collector"

echo "installed ${install_dir}/mitoriq-collector"
