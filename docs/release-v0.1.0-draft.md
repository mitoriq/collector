# Mitoriq Collector v0.1.0 Draft Release Notes

## Summary

Mitoriq Collector v0.1.0 prepares the local collector for private beta distribution through GitHub Releases and Homebrew.

## Highlights

- Metadata-only local collector for Claude Code and Codex.
- Enrollment token storage via macOS Keychain or `0600` fallback file.
- Non-secret collector config saved under `~/.config/mitoriq/collector.json`.
- `version`, `doctor`, `install`, and `uninstall` commands for release diagnostics and setup.
- GoReleaser snapshot/release scaffolding for darwin and linux on amd64/arm64.
- SHA-256 `checksums.txt` plus detached cosign signatures for checksums and Linux release binaries.
- Developer ID signing and Apple notarization for macOS release binaries.
- launchd on macOS and a `Restart=always` systemd user service with linger on Linux, so a verified stable update can hand off to the replacement daemon.

## Trust Boundary

v0.1 does not send raw prompts, raw assistant output, tool input bodies, source code content, raw transcript content, or local absolute paths.

## v1 Supply-chain Follow-up

The v1 release path embeds the release API URL and ECDSA update public key, verifies signed checksums before applying an update, and restores the previous binary when replacement or the `version` self-check fails. The default update channel is `manual`; `stable` is explicit opt-in. Metadata-only send summaries and update results are available in the local audit log without recording payload bodies or credentials.

## Announcement Draft

Mitoriq Collector is the open-source local collector behind Mitoriq's metadata-only developer workflow map. It helps beta users see Claude Code and Codex activity in Mitoriq without sending raw prompts or code. The code is inspectable, and the v0.1 install path is designed around Homebrew, enrollment, and explicit local setup.

Avoid unverified claims such as "first", "only", or "secure by default" in launch copy.
