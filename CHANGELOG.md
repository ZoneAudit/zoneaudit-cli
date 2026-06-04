# Changelog

> **Languages:** [English](translations/CHANGELOG.en.md) | [Français](translations/CHANGELOG.fr.md) | [Deutsch](translations/CHANGELOG.de.md)

All notable changes to the ZoneAudit™ Community Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-03

### Added
- **RDAP Integration**: Automated fetching of domain expiration dates to identify critical renewal risks.
- **Service Fingerprinting**: HTTP banner and page title extraction for active web services.
- **Tactical Progress Bar**: Real-time terminal progress indicator for subdomain discovery.
- **Email Security Baseline**: Presence checks for SPF and DMARC records.
- **Dangling DNS Detection**: Proactive flagging of CNAME records pointing to non-existent targets.
- **Fail-Fast Resolution**: Immediate validation of root domain connectivity before scanning.
- **Multilingual Support**: Full terminal output and documentation support for French (`fr`) and German (`de`).

### Changed
- Expanded tactical wordlist to 143 high-value infrastructure hotspots.
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
