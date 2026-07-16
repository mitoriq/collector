#!/usr/bin/env sh
set -eu

collector_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
publish_runbook="${collector_root}/../../docs/collector-oss-publish.md"
release_workflow="${collector_root}/.github/workflows/release.yml"
expected_homepage='    homepage: https://mitoriq.vercel.app/collector'
expected_verified='      verified: github.com/mitoriq/collector/'
expected_skip_upload='    skip_upload: auto'
homebrew_install='brew install --cask mitoriq/tap/mitoriq-collector'
paid_domain='mitoriq.com'
distribution_page='https://mitoriq.vercel.app/collector'
manifest_endpoint='https://mitoriq.vercel.app/.well-known/collector-release.json'
key_endpoint='https://mitoriq.vercel.app/.well-known/collector-release-key.pem'
versioned_key_endpoint='https://mitoriq.vercel.app/.well-known/collector-release-keys/4bfa1f0245bc7a0f735e10503773f8c8a0fe2f4d61b00a919f66e952dab6b36b.pem'
key_fingerprint='4bfa1f0245bc7a0f735e10503773f8c8a0fe2f4d61b00a919f66e952dab6b36b'
macos_team_id='7FY7MQ69N4'
unsigned_installer_warning='The official handoff does not download and execute `scripts/install.sh`.'

if ! grep -Fqx "$expected_homepage" "${collector_root}/.goreleaser.yaml"; then
  echo "Homebrew Cask homepage must use the official collector distribution page" >&2
  exit 1
fi

if ! grep -Fqx "$expected_verified" "${collector_root}/.goreleaser.yaml"; then
  echo "Homebrew Cask must verify the GitHub download domain when homepage differs" >&2
  exit 1
fi

if ! grep -Fqx "$expected_skip_upload" "${collector_root}/.goreleaser.yaml"; then
  echo "Homebrew Cask must skip prerelease uploads" >&2
  exit 1
fi

for required_value in \
  "$homebrew_install" \
  "$distribution_page" \
  "$manifest_endpoint" \
  "$key_endpoint" \
  "$versioned_key_endpoint" \
  "$key_fingerprint" \
  "$macos_team_id" \
  "$unsigned_installer_warning"
do
  if ! grep -Fq "$required_value" "${collector_root}/README.md"; then
    echo "README is missing the official distribution contract: $required_value" >&2
    exit 1
  fi
done

if grep -Fq "$paid_domain" "${collector_root}/README.md"; then
  echo "README must not require a paid custom domain for distribution" >&2
  exit 1
fi

if ! grep -Fq 'latest stable signed artifacts' "${collector_root}/README.md"; then
  echo "README must describe the release without pinning a stale version" >&2
  exit 1
fi

node "${collector_root}/scripts/check-readme-installer-safety.test.mjs"
node "${collector_root}/scripts/check-readme-installer-safety.mjs" "${collector_root}/README.md"
node "${collector_root}/scripts/validate-release-manifest.test.mjs"
node "${collector_root}/scripts/validate-release-manifest.mjs" \
  "${collector_root}/scripts/fixtures/collector-release-v0.1.1.json"

legacy_pkcs12_reads="$(grep -Fc 'openssl pkcs12 -legacy' "$release_workflow" || true)"
if [ "$legacy_pkcs12_reads" -ne 2 ]; then
  echo "release workflow must enable OpenSSL legacy mode for both PKCS#12 reads" >&2
  exit 1
fi

if [ -f "$publish_runbook" ]; then
  if grep -Fq "$paid_domain" "$publish_runbook"; then
    echo "publish runbook must not require a paid custom domain for distribution" >&2
    exit 1
  fi

  for required_value in "$distribution_page" "$manifest_endpoint" "$key_endpoint"; do
    if ! grep -Fq "$required_value" "$publish_runbook"; then
      echo "publish runbook is missing the official distribution contract: $required_value" >&2
      exit 1
    fi
  done
fi

echo "collector release distribution contract is current"
