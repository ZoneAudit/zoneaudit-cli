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
- **Stable JSON output** with a `schema_version` field (`"1.1"`), documented in `docs/json-output.md`; the report also records the time, duration, limits used and number of requests.
- `SECURITY.md`, `CONTRIBUTING.md` and an example report in the README.
- `-version` flag.
- An interrupted scan (Ctrl+C) still writes the partial report, then exits with status 130.
- A failed DNS lookup is reported as such: SPF and DMARC show `unavailable` (not missing, with no "spoofable" warning), and a CNAME whose target could not be looked up is marked `UNCHECKED` rather than dangling.

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
- Days left on an expired certificate or domain round down, so an expiry less than a day ago shows -1, not 0.
- The per-request HTTP timeout starts after the rate limiter's wait, so requests queued at a low `-rate` no longer time out before they are sent.
- A `v=spf1`-like prefix such as `v=spf10` is no longer counted as SPF.
- Values from DNS and web servers (records, `Server` headers, page titles, the DMARC policy) are escaped in the text report, so they cannot inject terminal control sequences. JSON output is unchanged.
- HTTP redirects are followed only within the scanned domain and its subdomains, on the scheme's standard port (443 for https, 80 for http), at most twice, and never to an IP address; otherwise the redirect response is reported.
- TLS handshakes, HTTP requests and RDAP queries (redirects included) connect only to globally reachable addresses, never to loopback, private, link-local (such as a cloud metadata service), documentation, benchmarking or other special-purpose ranges. The address is checked when connecting, so a DNS answer that changes between lookups (DNS rebinding) cannot get round it. These connections are therefore made directly, without an HTTP proxy. The lookups made to connect are rate limited and counted in `requests`, and IPv6 and IPv4 addresses are tried in parallel after a short delay, so an unreachable address does not use up the timeout.
- Ctrl+C during the initial root-domain check writes the partial report and exits with 130, rather than reporting a resolution failure.
- The scan duration includes the root-domain check, whose lookups were already counted in `requests`.
- The page title is no longer read from tags that merely start with "title", such as `<titlefake>`.
- `requests` counts only requests that were allowed to start, not ones cancelled while waiting for the rate limiter.
- `total_scanned` counts the wordlist names actually tried, so an interrupted scan's report matches docs/json-output.md.
- `--help` follows `-lang` (English, French or German): the responsible-use notice, usage line, option descriptions and defaults. So do error messages, the progress bar and the interruption notice; the language is chosen before the arguments are checked.
- `v=spf1` counts as SPF only when followed by a space or the end of the record, so `v=spf1;x` is not SPF.
- The README and the release notes give native commands to verify a download on Linux, macOS and Windows.
- The one-line installers (vendored from the website) refuse to install when `checksums.txt` is missing or cannot be downloaded, and CI checks this; the shell installer no longer claims BSD support.

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
