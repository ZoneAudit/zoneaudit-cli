# Changelog

> **Sprachen:** [English](CHANGELOG.en.md) | [Français](CHANGELOG.fr.md) | [Deutsch](CHANGELOG.de.md)

Alle nennenswerten Änderungen an der ZoneAudit™ Community Edition werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
und dieses Projekt hält sich an [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-03

### Hinzugefügt
- **RDAP-Integration**: Automatisches Abrufen von Domain-Ablaufdaten zur Identifizierung kritischer Erneuerungsrisiken.
- **Service-Fingerprinting**: Extraktion von HTTP-Bannern und Seitentiteln für aktive Webdienste.
- **Taktischer Fortschrittsbalken**: Echtzeit-Terminal-Fortschrittsanzeige für die Subdomain-Entdeckung.
- **E-Mail-Sicherheitsbasis**: Vorhandenseinsprüfugen für SPF- und DMARC-Einträge.
- **Erkennung hängender DNS**: Proaktive Kennzeichnung von CNAME-Einträgen, die auf nicht existierende Ziele verweisen.
- **Fail-Fast-Auflösung**: Sofortige Validierung der Root-Domain-Konnektivität vor dem Scannen.
- **Mehrsprachige Unterstützung**: Volle Unterstützung für Terminalausgabe und Dokumentation in Französisch (`fr`) und Deutsch (`de`).

### Geändert
- Taktische Wortliste auf 143 hochwertige Infrastruktur-Hotspots erweitert.
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
