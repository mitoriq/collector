# Mitoriq Collector

Mitoriq Collector is a local, outbound-only collector for Claude Code, Codex, and Cursor metadata. It normalizes local tool events, redacts source-specific payloads, adds read-only git metadata, and uploads metadata to the Mitoriq API.

Mitoriq keeps the collector open source so the metadata-only claim can be inspected in code.

> **Release status:** the source is available for review, but signed v0.1.0 artifacts and the Homebrew tap are not published yet. Installation commands become available after the signed release passes the documented release gates.

## Quickstart After Release

The macOS private beta does not require a custom domain. Signed artifacts are published through GitHub Releases, and Homebrew verifies the release archive checksum before installing the Apple Developer ID signed and notarized binary.

Open the Collector setup guide in Mitoriq `/now` or `/machines`, choose macOS, and copy the generated command. The command includes the supported package install and a short-lived, Organization-scoped enrollment code. The package-install portion is:

```sh
brew install --cask mitoriq/tap/mitoriq-collector
```

After the generated command completes, verify the local service:

```sh
mitoriq-collector doctor
```

After enrollment, open Mitoriq web and check `/machines`, `/now`, and `/sessions`.

Linux and the standalone curl installer are not part of the supported private-beta onboarding path. `scripts/install.sh` remains available for maintainer-assisted verification and requires a local cosign public key plus its DER/SPKI fingerprint. Obtain the key and fingerprint through separately authenticated maintainer channels; do not obtain either trust input from the GitHub Release being installed.

From a clone of this repository, copy the separately provided public key into an owner-readable local path before running the installer:

```sh
mkdir -p "$HOME/.config/mitoriq"
install -m 0600 \
  "/trusted/path/from-maintainer/collector-release.pub" \
  "$HOME/.config/mitoriq/collector-release.pub"

MITORIQ_COLLECTOR_PUBLIC_KEY_PATH="$HOME/.config/mitoriq/collector-release.pub" \
MITORIQ_COLLECTOR_PUBLIC_KEY_SHA256="REPLACE_WITH_ONBOARDING_FINGERPRINT" \
MITORIQ_COLLECTOR_MACOS_TEAM_ID="REPLACE_WITH_APPLE_TEAM_ID" \
  sh ./scripts/install.sh
```

`MITORIQ_COLLECTOR_MACOS_TEAM_ID` is required only on macOS. This manual installer path does not introduce a public Linux onboarding command. The installer fails before installation when trust inputs or verification tools are missing, the key fingerprint/signature/checksum is invalid, the archive has unexpected entries, or macOS Developer ID/notarization checks fail.

## What Is Sent

| Privacy level | Sent in v0.1                                                           |
| ------------- | ---------------------------------------------------------------------- |
| L0            | heartbeat, machine liveness, collector version                         |
| L1            | session metadata, state, tool, model/token counts, timestamps          |
| L2            | git metadata limited to repo display/hash, branch, worktree, diff stat |

## What Is Not Sent

v0.1 does not send raw prompts, raw assistant output, tool input bodies, code content, raw local transcript content, or local absolute paths.

## Commands

```sh
mitoriq-collector version
mitoriq-collector doctor
mitoriq-collector enroll --api-url "$MITORIQ_API_URL" --bootstrap-code "$MITORIQ_BOOTSTRAP_CODE"
mitoriq-collector install --tools claude,codex --dry-run
mitoriq-collector install --tools claude --print-settings-json
mitoriq-collector uninstall --dry-run
mitoriq-collector update
mitoriq-collector update --set-channel stable
mitoriq-collector audit-log --limit 100
```

`enroll` stores the enrollment token in macOS Keychain when available, otherwise in `~/.config/mitoriq/enrollment-token` with `0600` permissions. Non-secret IDs and API URL are stored in `~/.config/mitoriq/collector.json`.

## Local Deny Rules

Users can define local deny rules in `~/.config/mitoriq/collector.json`. Deny rules are evaluated before upload and remove L2+ metadata from matching repos or paths while preserving L0/L1 machine liveness and session state.

```json
{
  "deny": {
    "repos": [
      {
        "alias": "private-sandbox",
        "remoteUrlHash": "REPLACE_WITH_REPO_REMOTE_URL_HASH"
      }
    ],
    "pathGlobs": ["secrets/**", "*.pem"],
    "pathRegexes": ["(^|/)private/"]
  }
}
```

- `deny.repos[].remoteUrlHash` matches the privacy-safe remote URL hash shown by repo discovery or existing allowlist entries.
- `deny.pathGlobs` supports repo-relative glob patterns. Patterns without `/`, such as `*.pem`, match any path segment.
- `deny.pathRegexes` matches normalized repo-relative paths with Go regular expressions.
- Invalid deny patterns fail closed: L2+ metadata is removed until the config is fixed.
- `mitoriq-collector doctor` prints deny counts, invalid pattern reasons, and the `fail_closed` state.

## Claude, Codex, And Cursor Hooks

The collector does not overwrite existing tool configuration. Generate one complete, valid hook configuration at a time, then merge its top-level `hooks` object into the existing file instead of replacing unrelated settings:

```sh
HOOKS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mitoriq-hooks.XXXXXX")" &&
mitoriq-collector install --tools claude --print-settings-json > "$HOOKS_DIR/claude-hooks.json" &&
mitoriq-collector install --tools codex --print-settings-json > "$HOOKS_DIR/codex-hooks.json" &&
mitoriq-collector install --tools cursor --print-settings-json > "$HOOKS_DIR/cursor-hooks.json" &&
printf 'hook_settings_dir=%s\n' "$HOOKS_DIR"
```

`mktemp -d` creates an unpredictable owner-only directory so another local process cannot redirect these files through a pre-existing symlink. `--print-settings-json` only prints JSON. It does not install the collector service or write a tool configuration file. Use the generated block for the matching user-level configuration, then delete the generated directory:

| Tool        | Configuration file        | Generated lifecycle events                                                                                                                              |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Claude Code | `~/.claude/settings.json` | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `Notification`, `Elicitation`, `SessionEnd` |
| Codex       | `~/.codex/hooks.json`     | `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Stop`                                                                            |
| Cursor      | `~/.cursor/hooks.json`    | `sessionStart`, `beforeSubmitPrompt`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `sessionEnd`                                                   |

For Codex, open `/hooks` after editing the file and review/trust the generated command hook. For all tools, keep any existing matcher groups and append the Mitoriq groups for the same event instead of replacing them.

`mitoriq-collector uninstall` stops the collector-owned launchd or systemd service before removing its plist or unit. Because install never edits tool configuration, remove the Mitoriq command groups from the corresponding hook file manually when disconnecting the collector.

Cursor usage counters are supported independently of session state. `mitoriq-collector install --tools cursor --dry-run` prints a `cursor-hook --cursor-hooks-beta` command for opt-in lifecycle collection. Cursor lifecycle state is best-effort: running activity and explicit session end can be inferred, but permission and user-input waiting are not currently reliable signals.

## Service Installation

- macOS writes `~/Library/LaunchAgents/com.mitoriq.collector.plist` and immediately bootstraps it in the current user's launchd domain. Re-running install reloads the owned service so an updated plist takes effect; if activation fails, the previous plist and loaded service are restored.
- macOS uninstall inspects the current user's launchd domain, boots out the loaded collector service, and only then removes the owned plist. Inspection or bootout failure leaves the plist in place and returns an error.
- Linux writes `~/.config/systemd/user/mitoriq-collector.service` with `Restart=always`, reloads the user manager, enables linger for the current user, and runs `systemctl --user enable --now mitoriq-collector.service`. This allows a stable-channel update to exit the old daemon and have systemd start the verified replacement.
- Linux uninstall runs `systemctl --user disable --now mitoriq-collector.service`, removes only the owned unit path, and reloads the user manager.
- `--dry-run` prints the platform file and hook snippets without writing files or invoking service-manager commands. Other operating systems return an explicit unsupported error.

## Troubleshooting

- Enrollment fails: check that the bootstrap code is current and has not already been consumed.
- Keychain unavailable: the collector falls back to `~/.config/mitoriq/enrollment-token`.
- Daemon not running: run `mitoriq-collector daemon --once`, then inspect the launchd plist or systemd user unit printed by `install --dry-run`. On Linux, also check `systemctl --user status mitoriq-collector.service` and the linger state.
- Hook not firing: confirm the hook command uses the same binary returned by `which mitoriq-collector`, the generated block was merged into the correct file, and the event matcher still includes the current action. In Codex, also open `/hooks` and confirm the command is trusted.
- API unreachable: verify the API URL and local network access.

## Windows Notes

On Windows, enrollment tokens are stored in Windows Credential Manager when available. If Credential Manager is unavailable, the collector falls back to a local token file and warns the operator to verify Windows file ACLs.

`mitoriq-collector doctor` prints Codex and Claude Code discovery candidates, including `%USERPROFILE%\.codex`, explicit `CODEX_HOME`, the WSL shared Codex home under `/mnt/<drive>/Users/<windows-user>/.codex`, and `%USERPROFILE%\.claude\projects`.

## Signed Updates

Linux release binaries and `checksums.txt` have detached cosign signatures. macOS binaries use Developer ID signing/notarization and a cosign-signed checksum manifest for archive integrity. Release builds embed the HTTPS release API URL and the ECDSA public key used by the updater. An update is applied only after the checksum signature and archive SHA-256 verify (plus the inner binary signature on Linux); a failed replacement or `version` self-check restores the previous binary.

`updateChannel` in `~/.config/mitoriq/collector.json` accepts:

- `manual` (default): never update without an explicit user action.
- `stable`: check stable GitHub Releases; drafts and pre-releases are excluded.

Use `mitoriq-collector update --set-channel manual` to disable automatic checks. Package-manager installations are never self-modified; update them with `brew upgrade --cask mitoriq-collector`.

Local verification of downloaded release metadata:

```sh
cosign verify-blob --key cosign.pub --signature checksums.txt.sig checksums.txt
expected_checksum="$(awk '$2 == "<archive-name>" { print $1 }' checksums.txt)"
actual_checksum="$(openssl dgst -sha256 "<archive-name>" | awk '{ print $NF }')"
test "$actual_checksum" = "$expected_checksum"
```

## Local Audit Log

The local audit log records metadata-only summaries such as privacy level, event type, count, update version, and trusted key fingerprint. It does not record raw prompts, code, tokens, absolute paths, or event payload bodies. `mitoriq-collector doctor` also prints the embedded release-key fingerprint. Configure a custom path with `auditLogPath` in `~/.config/mitoriq/collector.json`.

## Limitations

Cursor permission/user-input waiting state, Windows service installation, and L3 redacted summaries remain outside the reliable support boundary. Signed auto-update is a v1 capability and is not enabled by default.

## Release

Unsigned local release structure is checked with GoReleaser:

```sh
goreleaser release --snapshot --clean --skip=sign,notarize
```

The repository workflow dispatch generates a signed snapshot with an ephemeral cosign key. Published releases run only from `v*` tags and require the `mitoriq/collector` repository, the `mitoriq/homebrew-tap` repository, the production cosign and Apple signing material, and maintainer confirmation before tag push. Missing or mismatched release inputs fail before publish.

## License

Apache-2.0.
