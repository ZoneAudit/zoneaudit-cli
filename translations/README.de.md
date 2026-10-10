# ZoneAudit™ Community Edition

[![ci](https://github.com/ZoneAudit/zoneaudit-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ZoneAudit/zoneaudit-cli/actions/workflows/ci.yml?query=branch%3Amain)
[![MIT licence](https://img.shields.io/badge/licence-MIT-blue.svg)](../LICENSE)

> **Sprachen:** [English](README.en.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

**Lesende Erfassung der öffentlichen Präsenz einer Domain: Subdomains, DNS, Zertifikate, Domain-Ablauf und E-Mail-Sicherheit.**

ZoneAudit Community Edition prüft eine Domain und 143 gängige Hostnamen darunter. Für jeden vorhandenen Host zeigt sie die DNS-Einträge, kennzeichnet einen CNAME, dessen Ziel nicht mehr auflöst (hängender CNAME), liest Ablaufdatum und Aussteller des Zertifikats und erfasst Server-Banner und Seitentitel des Webservers. Für die Domain selbst liest sie das Ablaufdatum der Registrierung per RDAP und prüft SPF und DMARC, mit einer Warnung, wenn DMARC auf `p=none` steht.

Das CLI zeigt rohe, rein lesend erhobene Ergebnisse; der ZoneAudit-Dienst macht daraus einen priorisierten, belegten Bericht.

---

## Verantwortungsvolle Nutzung

**Scannen Sie nur Domains, die Ihnen gehören oder für deren Prüfung Sie autorisiert sind.**

Für jeden gefundenen Host löst ZoneAudit DNS-Einträge auf, führt einen TLS-Handshake und eine leichte HTTP(S)-Anfrage aus (einfaches HTTP nur, wenn HTTPS nicht antwortet, mit höchstens 2 Weiterleitungen). Außerdem stellt es eine RDAP-Anfrage zum Ablaufdatum der Domain. Es scannt keine Ports und versucht keinen Zugriff.

Jede Anfrage (jede DNS-Abfrage, jeder TLS-Handshake, jede HTTP-Anfrage und die RDAP-Anfrage) unterliegt einer gemeinsamen Ratenbegrenzung, standardmäßig 25 Anfragen pro Sekunde (`-rate`, höchstens 100), und hat ein eigenes Zeitlimit, standardmäßig 5 Sekunden (`-timeout`). Derselbe Hinweis steht am Anfang von `zoneaudit --help`.

## Installation

Mit [Go](https://go.dev/dl/) 1.22 oder neuer:

```bash
go install github.com/ZoneAudit/zoneaudit-cli/cmd/zoneaudit@latest
```

Oder laden Sie ein Archiv für Linux, macOS oder Windows (amd64 oder arm64) von der [Release-Seite](https://github.com/ZoneAudit/zoneaudit-cli/releases) herunter.

### Ein Release prüfen

Ab v0.3.0 wird `checksums.txt` vom Release-Workflow dieses Repositorys mit der schlüssellosen Signatur von [cosign](https://docs.sigstore.dev/) signiert, und zu jedem Archiv gibt es eine SPDX-Softwarestückliste (`*.sbom.json`). So prüfen Sie einen Download:

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ZoneAudit/zoneaudit-cli/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

## Nutzung

```bash
zoneaudit -d example.com
```

| Option | Standard | Bedeutung |
| :--- | :--- | :--- |
| `-d` | | Zu scannende Domain |
| `-c` | 10 | Parallele Worker (1 bis 50) |
| `-rate` | 25 | Höchstzahl Anfragen pro Sekunde über DNS, TLS, HTTP und RDAP (1 bis 100) |
| `-timeout` | 5s | Zeitlimit je Anfrage (1s bis 60s) |
| `-json` | aus | JSON-Bericht statt Text |
| `-lang` | `LANG` | Ausgabesprache: `en`, `fr` oder `de` |
| `-version` | | Version anzeigen |

### Beispielbericht

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

Dies ist die Ausgabe des CLI mit seinen Testdaten: Die RDAP-Daten für `example.com` sind eine aufgezeichnete Antwort, die übrigen Hosts, Einträge und Zertifikate sind erfunden, um jede Art von Befund zu zeigen, und die Uhr ist fest eingestellt (daher `Duration: 0s`). Ein echter Scan von 143 Hostnamen dauert mit der Standardrate etwa 30 Sekunden. Mit `-lang de` erfolgt die Ausgabe auf Deutsch.

### JSON-Ausgabe

```bash
zoneaudit -d example.com -json
```

Der JSON-Bericht enthält ein Feld `schema_version` (derzeit `"1.1"`). Innerhalb der Hauptversion 1 werden Felder nie entfernt, umbenannt oder in ihrer Bedeutung geändert; neue optionale Felder können hinzukommen, wodurch die Nebenversion steigt. Das Format ist in [docs/json-output.md](../docs/json-output.md) (auf Englisch) beschrieben.

Ein gekürzter Bericht aus denselben Testdaten:

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

### Sprachen

| Sprache | Code | Aktivierung | Dokumentation |
| :--- | :--- | :--- | :--- |
| English | `en` | Standard | [README.en.md](README.en.md) |
| Français | `fr` | `-lang fr` oder `LANG=fr` | [README.fr.md](README.fr.md) |
| Deutsch | `de` | `-lang de` oder `LANG=de` | [README.de.md](README.de.md) |

Übersetzungen werden zur Erleichterung bereitgestellt und können in technischen Nuancen abweichen.

```bash
LANG=fr zoneaudit -d example.com
zoneaudit -d example.com -lang de
```

Die Änderungen jeder Version finden Sie im [CHANGELOG.de.md](CHANGELOG.de.md).

---

## Roadmap

Wir erwägen eine passive Prüfung der Security-Header (HSTS, CSP, X-Frame-Options) in der HTTP(S)-Anfrage, die das CLI bereits stellt. Rückmeldungen dazu, was Ihnen helfen würde, sind in den [Issues](https://github.com/ZoneAudit/zoneaudit-cli/issues) willkommen.

---

## Von Ergebnissen zum Bericht

Dieses CLI sammelt die Rohergebnisse. Der ZoneAudit-Dienst macht daraus einen priorisierten, belegten Bericht, einschließlich DCC Level 0 für Zulieferer des britischen Verteidigungsministeriums.

[Zugang auf zoneaudit.com anfragen](https://zoneaudit.com/?utm_source=github&utm_medium=readme&utm_campaign=community_edition_de)

---

## Community

- **Fehler und Fragen:** [öffnen Sie ein GitHub-Issue](https://github.com/ZoneAudit/zoneaudit-cli/issues).
- **Sicherheitslücken:** bitte kein öffentliches Issue; siehe [SECURITY.md](../SECURITY.md).
- **Beitragen:** siehe [CONTRIBUTING.md](../CONTRIBUTING.md).

### Lizenz

Dieses Projekt steht unter der **MIT-Lizenz**. Den vollständigen Text finden Sie in der Datei [LICENSE](../LICENSE).

Entwickelt im Vereinigten Königreich von [CobraSphere](https://cobrasphere.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition_de).
