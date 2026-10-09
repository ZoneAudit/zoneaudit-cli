# Security policy

## Reporting a vulnerability

Please report security vulnerabilities in ZoneAudit Community Edition by email to **security@cobrasphere.com**. Do not open a public GitHub issue for a vulnerability.

Please include:

- the version (`zoneaudit -version`) and your operating system;
- what you found and how to reproduce it;
- the impact you think it has.

## What to expect

- We acknowledge your report within **3 working days** (UK).
- We send an initial assessment, and a fix timeline if we accept it, within **10 working days**.
- We keep you informed until it is resolved, and we credit you in the release notes unless you prefer not to be named.

Please give us reasonable time to release a fix before you disclose the issue publicly.

## Supported versions

Security fixes are made in the latest release only.

| Version | Supported |
| :--- | :--- |
| 0.3.x | Yes |
| Earlier | No |

## Verifying releases

From v0.3.0, release checksums are signed with cosign keyless signing and each archive has an SBOM. See [Verify a release](README.md#verify-a-release).

## Scope

The CLI is read-only by design: it resolves DNS, makes one TLS handshake and a light HTTP(S) request per host, and one RDAP query. A way to make it do more than that, for example to send other requests or write files, is a vulnerability we want to hear about.
