# Changelog

> **Sprachen:** [English](CHANGELOG.en.md) | [Français](CHANGELOG.fr.md) | [Deutsch](CHANGELOG.de.md)

Alle nennenswerten Änderungen an der ZoneAudit™ Community Edition werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
und dieses Projekt hält sich an [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unveröffentlicht]

## [0.3.0] - 2026-10-09

### Hinzugefügt
- **Tests für jede Prüfung**, ausgeführt mit aufgezeichneten Daten ohne Netzwerk: RDAP-Ablauf, Subdomain-Erkennung, A/AAAA-, CNAME-, TXT- und MX-Einträge, Kennzeichnung hängender CNAMEs, SPF und DMARC (einschließlich der Warnung bei `p=none`), Ablauf und Aussteller von Zertifikaten sowie das HTTP-Banner.
- **CI für jeden Pull-Request**: Tests unter Linux, macOS und Windows, auf amd64 und arm64, dazu `go vet`, staticcheck, ein Release-Probelauf und Prüfungen der Einzeiler-Installer (macOS, Windows PowerShell 5.1, PowerShell 7 und ARM).
- **Rücksichtsvolles Scannen**: `-rate` begrenzt die Anfragen pro Sekunde über DNS, TLS, HTTP und RDAP (Standard 25, höchstens 100), und `-timeout` begrenzt jede Anfrage (Standard 5 s). Anfragen weisen sich mit dem User-Agent `zoneaudit-cli/<version>` aus.
- **Signierte Releases**: `checksums.txt` wird mit der schlüssellosen Signatur von cosign signiert (GitHub OIDC, keine gespeicherten Schlüssel), und zu jedem Archiv gibt es eine SPDX-Stückliste.
- **Pakete**: Der Release-Workflow erzeugt einen Homebrew-Cask und ein Scoop-Manifest und veröffentlicht sie, sobald die Tap- und Bucket-Repositorys existieren.
- **Stabile JSON-Ausgabe** mit dem Feld `schema_version` (`"1.0"`), beschrieben in `docs/json-output.md`; der Bericht enthält außerdem Zeitpunkt, Dauer, verwendete Grenzen und Anzahl der Anfragen.
- `SECURITY.md`, `CONTRIBUTING.md` und ein Beispielbericht im README.
- Option `-version`.

### Geändert
- `--help` beginnt mit dem Hinweis zur verantwortungsvollen Nutzung.
- Der Textbericht endet mit einer Zeile zur Zugangsanfrage für die vollständige ZoneAudit-Prüfung.
- Ergebnisse werden sortiert (zuerst die Domain, dann nach Namen), ebenso die Einträge je Host, damit Berichte reproduzierbar sind.
- Das Domain-Argument wird normalisiert (Groß- und Kleinschreibung, abschließender Punkt, eingefügte URL) und abgelehnt, wenn es kein Domainname ist.
- Fehler und Fortschrittsbalken gehen auf die Standardfehlerausgabe; die JSON-Ausgabe ist eingerückt.
- Der Architekturabschnitt im README ist durch eine einzeilige Beschreibung ersetzt, und die Roadmap nennt weder Protokoll-Handshake-Probing noch lokale Verlaufsspeicherung.

### Behoben
- Der Release-Workflow richtet Go mit `actions/setup-go` ein (zuvor lief `actions/checkout` zweimal).
- RDAP-Anfragen prüfen das Zertifikat des Servers.
- Ein `v=spf1`-ähnliches Präfix wie `v=spf10` zählt nicht mehr als SPF.

## [0.2.0] - 2026-06-03

### Hinzugefügt
- **RDAP-Integration**: Automatisches Abrufen von Domain-Ablaufdaten zur Identifizierung kritischer Erneuerungsrisiken.
- **Service-Fingerprinting**: Extraktion von HTTP-Bannern und Seitentiteln für aktive Webdienste.
- **Fortschrittsbalken**: Echtzeit-Terminal-Fortschrittsanzeige für die Subdomain-Entdeckung.
- **E-Mail-Sicherheitsbasis**: Vorhandenseinsprüfugen für SPF- und DMARC-Einträge.
- **Erkennung hängender DNS**: Proaktive Kennzeichnung von CNAME-Einträgen, die auf nicht existierende Ziele verweisen.
- **Fail-Fast-Auflösung**: Sofortige Validierung der Root-Domain-Konnektivität vor dem Scannen.
- **Mehrsprachige Unterstützung**: Volle Unterstützung für Terminalausgabe und Dokumentation in Französisch (`fr`) und Deutsch (`de`).

### Geändert
- Wortliste auf 143 gängige Infrastruktur-Hostnamen erweitert.
- Terminal-Ausgabe für „Engineering Precision“ überarbeitet – operative Klarheit hat Vorrang vor rohen Daten-Dumps.
- Architektur-Dokumentation auf vertikale Mermaid-Flows aktualisiert.

## [0.1.1] - 2026-06-03

### Hinzugefügt
- DNS-Probing um MX- und TXT-Einträge erweitert.
- Initiale Unterstützung für lokalisierte String-Tabellen in `internal/i18n`.

### Geändert
- Timeout-Handling bei der SSL-Validierung verbessert.

## [0.1.0] - 2026-03-31

### Hinzugefügt
- Erstveröffentlichung der ZoneAudit™ Community Edition.
- Engine zur gleichzeitigen Entdeckung von Subdomains in Go.
- Grundlegende SSL/TLS-Zertifikatsvalidierung.
- Unterstützung der JSON-Ausgabe für die Pipeline-Integration.
