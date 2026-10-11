# ZoneAudit™ Community Edition

[![ci](https://github.com/ZoneAudit/zoneaudit-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ZoneAudit/zoneaudit-cli/actions/workflows/ci.yml?query=branch%3Amain)
[![MIT licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

> **Languages:** [English](translations/README.en.md) | [Français](translations/README.fr.md) | [Deutsch](translations/README.de.md)

**Read-only discovery of a domain's public footprint: subdomains, DNS, certificates, domain expiry and email security.**

ZoneAudit Community Edition checks a domain and 143 common hostnames under it. For each host that exists it reports the DNS records, flags a CNAME whose target no longer resolves (a dangling CNAME), reads the certificate's expiry date and issuer, and records the web server's banner and page title. For the domain itself it reads the registration expiry date from RDAP and checks SPF and DMARC, warning when DMARC is set to `p=none`.

The CLI shows raw, read-only findings; the ZoneAudit service turns them into a prioritised, evidenced report.

---

## Responsible use

**Only scan domains you own or are authorised to assess.**

For each host it finds, ZoneAudit resolves DNS records, makes one TLS handshake and one light HTTP(S) request (plain HTTP only if HTTPS does not answer, following at most 2 redirects). It also makes one RDAP query for the domain's expiry date. It does not scan ports or attempt access.

Every request (each DNS lookup, TLS handshake, HTTP request and the RDAP query) goes through one rate limit, 25 requests per second by default (`-rate`, at most 100), and each has its own timeout, 5 seconds by default (`-timeout`). The same notice is at the top of `zoneaudit --help`.

## Install

With [Go](https://go.dev/dl/) 1.22 or later:

```bash
go install github.com/ZoneAudit/zoneaudit-cli/cmd/zoneaudit@latest
```

Or download an archive for Linux, macOS or Windows (amd64 or arm64) from the [releases page](https://github.com/ZoneAudit/zoneaudit-cli/releases).

### Verify a release

From v0.3.0, `checksums.txt` is signed with [cosign](https://docs.sigstore.dev/) keyless signing by this repository's release workflow, and each archive has an SPDX software bill of materials (`*.sbom.json`). To check a download:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ZoneAudit/zoneaudit-cli/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

## Usage

```bash
zoneaudit -d example.com
```

| Flag | Default | Meaning |
| :--- | :--- | :--- |
| `-d` | | Domain to scan |
| `-c` | 10 | Concurrent workers (1 to 50) |
| `-rate` | 25 | Maximum requests per second across DNS, TLS, HTTP and RDAP (1 to 100) |
| `-timeout` | 5s | Timeout for each request (1s to 60s) |
| `-json` | off | Write a JSON report instead of text |
| `-lang` | `LANG` | Output language: `en`, `fr` or `de` |
| `-version` | | Print the version |

### Example report

```text
$ zoneaudit -d example.com
Starting ZoneAudit scan for: example.com
Workers: 10 | Wordlist: 143 common hostnames
Note: Alternative languages available via -lang [fr|de]

[*] Domain Expiring in 307 days (2027-08-13)

[+] example.com               | A/AAAA: 23.192.228.80   | HTTP:200 (ECS (nyd/D10E)) [Example Domain & Co] | TXT: google-site-verification=abc123 | MX: mx1.example.com (10) | SSL: OK (60 days left)
[+] mail.example.com          | TXT: v=spf1 -all     | MX: mx1.example.com (10)
[+] old.example.com           | CNAME: example-old.herokudns.example.org | RISK: DANGLING-CNAME
[+] shop.example.com          | A/AAAA: 192.0.2.10      | HTTP:403 (AmazonS3) | CNAME: shop.provider.example.net
[+] www.example.com           | A/AAAA: 23.192.228.84   | HTTP:200 (ECS (nyd/D10E)) [Example Domain & Co] | SSL: EXPIRING SOON (10 days left)

[*] Email security: SPF present | DMARC present (p=none)
[!] DMARC policy is 'none' (monitoring only): spoofed email is not blocked.

------------------------------------------------------------
ZoneAudit Community Edition v0.3.0
Scan complete for example.com
Duration: 0s | Active assets: 5
------------------------------------------------------------
For the full ZoneAudit review, request access at https://zoneaudit.com/?utm_source=cli
```

This is the CLI's output against its test fixtures: the RDAP data for `example.com` is a recorded response, while the other hosts, records and certificates are invented to show each kind of finding, and the clock is fixed (hence `Duration: 0s`). A real scan of 143 hostnames at the default rate takes about 30 seconds.

### JSON output

```bash
zoneaudit -d example.com -json
```

The JSON report has a `schema_version` field (currently `"1.1"`). Within major version 1, fields are never removed, renamed or given a new meaning; new optional fields may be added, which raises the minor number. The format is described in [docs/json-output.md](docs/json-output.md).

An abridged report from the same fixtures:

```json
{
  "schema_version": "1.1",
  "tool": { "name": "zoneaudit-cli", "version": "0.3.0" },
  "domain": "example.com",
  "generated_at": "2026-10-09T12:00:00Z",
  "duration_ms": 0,
  "settings": { "concurrency": 10, "rate_per_second": 25, "timeout_seconds": 5 },
  "requests": 590,
  "domain_expiry": { "expiry_date": "2027-08-13T04:00:00Z", "days_left": 307, "is_critical": false },
  "email_security": { "spf": true, "dmarc": true, "dmarc_policy": "none", "dmarc_weak": true, "spf_status": "present", "dmarc_status": "present" },
  "active": [
    {
      "subdomain": "old.example.com",
      "records": [
        { "type": "CNAME", "value": ["example-old.herokudns.example.org"] },
        { "type": "RISK", "value": ["DANGLING-CNAME"] }
      ],
      "is_active": true
    },
    {
      "subdomain": "www.example.com",
      "records": [{ "type": "A/AAAA", "value": ["23.192.228.84"] }],
      "is_active": true,
      "ssl": { "issuer": "Let's Encrypt", "expiry": "2026-10-19T13:00:00Z", "days_left": 10, "is_critical": true },
      "http": { "server": "ECS (nyd/D10E)", "title": "Example Domain & Co", "status": 200 }
    }
  ],
  "total_scanned": 143,
  "version": "0.3.0"
}
```

### Languages

| Language | Code | Activation | Documentation |
| :--- | :--- | :--- | :--- |
| English | `en` | Default | [README.en.md](translations/README.en.md) |
| Français | `fr` | `-lang fr` or `LANG=fr` | [README.fr.md](translations/README.fr.md) |
| Deutsch | `de` | `-lang de` or `LANG=de` | [README.de.md](translations/README.de.md) |

Translations are provided as a convenience and may vary in technical nuance.

```bash
LANG=fr zoneaudit -d example.com
zoneaudit -d example.com -lang de
```

See the [CHANGELOG](CHANGELOG.md) for the changes in each release.

---

## Roadmap

We are considering passive inspection of security headers (HSTS, CSP, X-Frame-Options) in the HTTP(S) request the CLI already makes. Feedback on what would help your work is welcome in the [issues](https://github.com/ZoneAudit/zoneaudit-cli/issues).

---

## From findings to a report

This CLI collects the raw findings. The ZoneAudit service turns them into a prioritised, evidenced report, including DCC Level 0 readiness for suppliers to the Ministry of Defence.

[Request access at zoneaudit.com](https://zoneaudit.com/?utm_source=github&utm_medium=readme&utm_campaign=community_edition)

---

## Community

- **Bugs and questions:** [open a GitHub issue](https://github.com/ZoneAudit/zoneaudit-cli/issues).
- **Security vulnerabilities:** please do not open a public issue; see [SECURITY.md](SECURITY.md).
- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md).

### Licence

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for the full text.

Made in the UK by [CobraSphere](https://cobrasphere.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition).
