#!/usr/bin/env sh
set -eu

collector_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
publish_runbook="${collector_root}/../../docs/collector-oss-publish.md"
release_workflow="${collector_root}/.github/workflows/release.yml"
expected_homepage='    homepage: https://github.com/mitoriq/collector'
homebrew_install='brew install --cask mitoriq/tap/mitoriq-collector'
paid_domain='mitoriq.com'
legacy_key_endpoint='/.well-known/collector-release-key.pem'

if ! grep -Fqx "$expected_homepage" "${collector_root}/.goreleaser.yaml"; then
  echo "Homebrew Cask homepage must use the public collector repository" >&2
  exit 1
fi

if ! grep -Fq "$homebrew_install" "${collector_root}/README.md"; then
  echo "README must document the supported Homebrew installation command" >&2
  exit 1
fi

if grep -Fq "$paid_domain" "${collector_root}/README.md"; then
  echo "README must not require a paid custom domain for distribution" >&2
  exit 1
fi

if grep -Fq "$legacy_key_endpoint" "${collector_root}/README.md"; then
  echo "README must not require a well-known release-key endpoint" >&2
  exit 1
fi

if ! grep -Fq 'The macOS private beta does not require a custom domain.' "${collector_root}/README.md"; then
  echo "README must document the domain-free macOS private beta contract" >&2
  exit 1
fi

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

  if grep -Fq "$legacy_key_endpoint" "$publish_runbook"; then
    echo "publish runbook must not require a well-known release-key endpoint" >&2
    exit 1
  fi

  if ! grep -Fq 'macOS private beta の release blocker ではない' "$publish_runbook"; then
    echo "publish runbook must record that a custom domain is not a macOS private beta blocker" >&2
    exit 1
  fi
fi

echo "collector release distribution contract is current"
