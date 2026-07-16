# Contributing

Mitoriq Collector is a small Go binary. Keep changes focused on local collection, normalization, redaction, offline queueing, and outbound upload.

## Development

```sh
go test ./...
sh scripts/install.test.sh
sh scripts/sign-release-binary.test.sh
sh scripts/check-release-distribution-contract.sh
mkdir -p bin
go build -o bin/mitoriq-collector ./cmd/mitoriq-collector
```

## Rules

- Do not add collection of raw prompts, raw assistant output, tool input bodies, source code content, raw transcript content, or local absolute paths.
- Keep token values out of logs, errors, examples, tests, and documentation.
- Add tests for privacy boundaries and config/token storage behavior.
- Prefer explicit allowlists for public export.

## Release

Release publication is maintainer-only. Use `goreleaser release --snapshot --clean --skip=sign,notarize` for an unsigned local build check. Use the GitHub Actions `release` workflow dispatch for an ephemeral-key signed snapshot.
