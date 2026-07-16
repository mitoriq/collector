#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: sign-release-binary.sh <artifact> <target-signature>" >&2
  exit 1
fi

artifact="$1"
target_signature="$2"

if [ -z "${COSIGN_KEY_PATH:-}" ] || [ ! -r "$COSIGN_KEY_PATH" ]; then
  echo "COSIGN_KEY_PATH must reference a readable signing key" >&2
  exit 1
fi
if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
  echo "release artifact must be a regular file" >&2
  exit 1
fi

case "$(basename -- "$target_signature")" in
  mitoriq-collector_linux_amd64.sig)
    goos='linux'
    goarch='amd64'
    ;;
  mitoriq-collector_linux_arm64.sig)
    goos='linux'
    goarch='arm64'
    ;;
  *)
    echo "unsupported release signature target" >&2
    exit 1
    ;;
esac

artifact_dir="$(CDPATH='' cd -- "$(dirname -- "$artifact")" && pwd)"
signature_dir="$(CDPATH='' cd -- "$(dirname -- "$target_signature")" && pwd)"
if [ "$signature_dir" != "$artifact_dir" ]; then
  echo "target signature must be written beside the release artifact" >&2
  exit 1
fi
if [ "$(basename -- "$artifact")" != "mitoriq-collector" ]; then
  echo "unsupported release artifact name" >&2
  exit 1
fi

case "$(basename -- "$artifact_dir")" in
  "mitoriq-collector-linux_linux_${goarch}_"*) ;;
  *)
    echo "release artifact directory does not match its signature target" >&2
    exit 1
    ;;
esac

dist_dir="$(CDPATH='' cd -- "${artifact_dir}/.." && pwd)"
if [ "$(basename -- "$dist_dir")" != 'dist' ]; then
  echo "release artifact must be built directly under the dist directory" >&2
  exit 1
fi

build_info="$(go version -m "$artifact" 2>/dev/null)" || {
  echo "release artifact does not contain readable Go build metadata" >&2
  exit 1
}
if ! printf '%s\n' "$build_info" | grep -Eq "^[[:space:]]*build[[:space:]]+GOOS=${goos}$" || \
  ! printf '%s\n' "$build_info" | grep -Eq "^[[:space:]]*build[[:space:]]+GOARCH=${goarch}$"; then
  echo "release artifact build target does not match its signature target" >&2
  exit 1
fi

archive_root="${dist_dir}/archive-signatures"
archive_signature_dir="${archive_root}/${goos}_${goarch}"
archive_signature="${archive_signature_dir}/mitoriq-collector.sig"

if [ -e "$target_signature" ] || [ -L "$target_signature" ]; then
  echo "target signature already exists" >&2
  exit 1
fi
if [ -e "$archive_signature" ] || [ -L "$archive_signature" ]; then
  echo "archive signature already exists" >&2
  exit 1
fi

for directory in "$archive_root" "$archive_signature_dir"; do
  if [ -L "$directory" ]; then
    echo "archive signature directory must not be a symbolic link" >&2
    exit 1
  fi
  if [ -e "$directory" ]; then
    if [ ! -d "$directory" ]; then
      echo "archive signature directory path must be a directory" >&2
      exit 1
    fi
  else
    mkdir "$directory"
  fi
done

temporary_signature="$(mktemp "${artifact_dir}/.mitoriq-collector-signature.XXXXXX")"
target_published=false
archive_published=false
completed=false
cleanup() {
  status=$?
  rm -f "$temporary_signature"
  if [ "$completed" != "true" ]; then
    if [ "$target_published" = "true" ]; then
      rm -f "$target_signature"
    fi
    if [ "$archive_published" = "true" ]; then
      rm -f "$archive_signature"
    fi
  fi
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

cosign sign-blob \
  --key="$COSIGN_KEY_PATH" \
  --output-signature="$temporary_signature" \
  "$artifact" \
  --yes

if [ ! -s "$temporary_signature" ] || [ -L "$temporary_signature" ]; then
  echo "cosign did not create a regular target signature" >&2
  exit 1
fi
chmod 0644 "$temporary_signature"

ln "$temporary_signature" "$target_signature"
target_published=true
ln "$temporary_signature" "$archive_signature"
archive_published=true

if [ ! -s "$target_signature" ] || [ -L "$target_signature" ] || \
  [ ! -s "$archive_signature" ] || [ -L "$archive_signature" ] || \
  ! cmp -s "$target_signature" "$archive_signature"; then
  echo "failed to publish matching regular release signatures" >&2
  exit 1
fi

completed=true
