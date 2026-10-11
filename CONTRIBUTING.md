# Contributing

Thank you for helping with ZoneAudit Community Edition. Bug reports, fixes and documentation improvements are welcome.

## Before you start

- For a bug or an idea, [open an issue](https://github.com/ZoneAudit/zoneaudit-cli/issues) first, so we can agree the approach before you write code.
- For a security vulnerability, do not open an issue; follow [SECURITY.md](SECURITY.md).
- The CLI stays a one-off, read-only snapshot. Changes that add port scanning, login attempts, heavier probing or stored history will not be accepted.

## Development

You need Go 1.22 or later.

```bash
go build ./cmd/zoneaudit
go test ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
gofmt -l .   # must print nothing
```

Tests never use the network. The scanner takes an injectable DNS resolver, HTTP client and TLS certificate fetcher; `internal/scannertest` provides fakes backed by fixtures in `internal/scannertest/testdata`. Add a fixture and a test for every new check or behaviour.

If you change the JSON report on purpose, update [docs/json-output.md](docs/json-output.md), follow its versioning rules, and refresh the golden file:

```bash
go test ./internal/scanner -run Golden -update
```

User-facing text lives in `internal/i18n`; please add English, French and German strings together. Write in British English.

## Pull requests

1. Fork the repository and create a branch, for example `fix/mx-sorting`.
2. Keep each pull request to one change, with tests.
3. Make sure CI passes: tests on Linux, macOS and Windows (amd64 and arm64), `go vet`, staticcheck, a release dry run and the installer checks.
4. Add a line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).

## Releases

Maintainers release by pushing a `vX.Y.Z` tag. The release workflow runs the tests, builds the archives with GoReleaser, generates SBOMs, signs `checksums.txt` with cosign keyless signing and publishes the GitHub release.
