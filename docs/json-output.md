# JSON output (schema version 1.0)

`zoneaudit -d <domain> -json` writes one JSON object to standard output. Progress and errors go to standard error, so the output can be piped straight into `jq` or another program.

## Versioning

`schema_version` is a string `"MAJOR.MINOR"`.

- Within a major version, fields are never removed or renamed and never change meaning or type.
- New optional fields may be added; that raises the minor number. Consumers should ignore fields they do not know.
- A change that breaks either rule raises the major number and is listed in the [CHANGELOG](../CHANGELOG.md).

Check the major number before reading a report, for example `jq -e '.schema_version | startswith("1.")'`.

## Top-level fields

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `schema_version` | string | Format version, currently `"1.0"` |
| `tool.name` | string | Always `"zoneaudit-cli"` |
| `tool.version` | string | CLI version, for example `"0.3.0"` |
| `domain` | string | The domain scanned, lower-cased |
| `generated_at` | string | Start of the scan, RFC 3339 in UTC |
| `duration_ms` | integer | Scan duration in milliseconds |
| `settings.concurrency` | integer | Workers used (`-c`) |
| `settings.rate_per_second` | integer | Request cap used (`-rate`) |
| `settings.timeout_seconds` | number | Per-request timeout used (`-timeout`) |
| `requests` | integer | Outbound requests made (DNS lookups, TLS handshakes, HTTP requests and the RDAP query) |
| `domain_expiry` | object or null | From RDAP; `null` if RDAP gave no answer |
| `domain_expiry.expiry_date` | string | RFC 3339, UTC |
| `domain_expiry.days_left` | integer | Whole days until expiry; negative once expired |
| `domain_expiry.is_critical` | boolean | `days_left` is below 30 |
| `email_security.spf` | boolean | The domain has a TXT record starting `v=spf1` |
| `email_security.dmarc` | boolean | `_dmarc.<domain>` has a TXT record starting `v=DMARC1` |
| `email_security.dmarc_policy` | string, optional | The DMARC `p=` value, lower-cased (`none`, `quarantine` or `reject`) |
| `email_security.dmarc_weak` | boolean | DMARC exists but `p=none`, so spoofed email is not blocked |
| `active` | array | One entry per host that has any record; the domain first, then sorted by name |
| `total_scanned` | integer | Number of wordlist names tried under the domain (the domain itself is checked as well) |
| `version` | string | Same as `tool.version`; kept for reports made by v0.2 |

## Host entries (`active[]`)

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `subdomain` | string | Fully qualified host name |
| `is_active` | boolean | Always `true` in `active` |
| `records` | array, optional | DNS records and risk flags, see below |
| `ssl` | object, optional | Present when a TLS handshake on port 443 returned a certificate |
| `ssl.issuer` | string | Issuer common name, or organisation if there is no common name |
| `ssl.expiry` | string | Leaf certificate expiry, RFC 3339, UTC |
| `ssl.days_left` | integer | Whole days until expiry; negative once expired |
| `ssl.is_critical` | boolean | `days_left` is below 30 |
| `http` | object, optional | Present when an HTTP(S) request got a response |
| `http.status` | integer | Final status code (after at most 2 redirects) |
| `http.server` | string, optional | `Server` response header |
| `http.title` | string, optional | Page title, HTML entities decoded |

### Record types (`records[].type`)

Each record has a `type` and a `value` array of strings.

| Type | Value |
| :--- | :--- |
| `A/AAAA` | IPv4 and IPv6 addresses, sorted |
| `CNAME` | The CNAME target, without the trailing dot |
| `TXT` | TXT strings, sorted |
| `MX` | `"<host> (<preference>)"`, sorted by preference |
| `RISK` | `["DANGLING-CNAME"]`: the CNAME target does not resolve; whoever can claim that name may be able to serve content on this host |

New record types or risk flags may be added in a minor version.

## Example

See the [README](../README.md#json-output) for an example. The test `TestJSONReportGolden` in `internal/scanner` pins the format against `internal/scanner/testdata/report.golden.json`.
