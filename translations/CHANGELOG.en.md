# Changelog

> **Languages:** [English](CHANGELOG.en.md) | [Français](CHANGELOG.fr.md) | [Deutsch](CHANGELOG.de.md)

All notable changes to the ZoneAudit™ Community Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-09

### Added
- **Tests for every check**, run against recorded fixtures with no network: RDAP expiry, subdomain discovery, A/AAAA, CNAME, TXT and MX records, the dangling CNAME flag, SPF and DMARC (including the `p=none` warning), certificate expiry and issuer, and the HTTP banner.
- **CI on every pull request**: tests on Linux, macOS and Windows, on amd64 and arm64, plus `go vet`, staticcheck, a release dry run and checks of the one-line installers (macOS, Windows PowerShell 5.1, PowerShell 7 and ARM).
- **Polite scanning**: `-rate` caps requests per second across DNS, TLS, HTTP and RDAP (default 25, maximum 100) and `-timeout` bounds each request (default 5s). Requests identify themselves with a `zoneaudit-cli/<version>` User-Agent.
- **Signed releases**: `checksums.txt` is signed with cosign keyless signing (GitHub OIDC, no stored keys) and each archive has an SPDX SBOM.
- **Packages**: the release workflow generates a Homebrew cask and a Scoop manifest, and publishes them once the tap and bucket repositories exist.
- **Stable JSON output** with a `schema_version` field (`"1.0"`), documented in `docs/json-output.md`; the report also records the time, duration, limits used and number of requests.
- `SECURITY.md`, `CONTRIBUTING.md` and an example report in the README.
- `-version` flag.

### Changed
- `--help` starts with the responsible-use notice.
- The text report ends with one line on requesting access to the full ZoneAudit review.
- Results are sorted (the domain first, then by name), as are the records within each host, so reports are repeatable.
- The domain argument is normalised (case, trailing dot, a pasted URL) and rejected if it is not a domain name.
- Errors and the progress bar go to standard error; JSON output is indented.
- The README's architecture section is replaced by a one-line description, and the roadmap no longer lists protocol handshake probing or local history storage.

### Fixed
- The release workflow now sets up Go with `actions/setup-go` (it ran `actions/checkout` twice).
- RDAP queries verify the server's certificate.
- A `v=spf1`-like prefix such as `v=spf10` is no longer counted as SPF.

## [0.2.0] - 2026-06-03

### Added
- **RDAP Integration**: Automated fetching of domain expiration dates to identify critical renewal risks.
- **Service Fingerprinting**: HTTP banner and page title extraction for active web services.
- **Progress Bar**: Real-time terminal progress indicator for subdomain discovery.
- **Email Security Baseline**: SPF and DMARC reported separately for the root domain, with the DMARC policy; a missing DMARC record is flagged.
- **Dangling DNS Detection**: Proactive flagging of CNAME records pointing to non-existent targets.
- **Fail-Fast Resolution**: Immediate validation of root domain connectivity before scanning.
- **Multilingual Support**: Full terminal output and documentation support for French (`fr`) and German (`de`).

### Changed
- Expanded the wordlist to 143 common infrastructure hostnames.
- Refactored terminal output for "Engineering Precision": prioritising operational clarity over raw data dumps.
- Upgraded architecture documentation to use vertical Mermaid flows.

## [0.1.1] - 2026-06-03

### Added
- Extended DNS probing to include MX and TXT records.
- Initial support for localised string tables in `internal/i18n`.

### Changed
- Improved SSL validation timeout handling.

## [0.1.0] - 2026-03-31

### Added
- Initial release of ZoneAudit™ Community Edition.
- Concurrent subdomain discovery engine in Go.
- Basic SSL/TLS certificate validation.
- JSON output support for pipeline integration.
