# ZoneAudit Community Edition (Deutsch)

ZoneAudit Community Edition ist ein in Go geschriebener, hochperformanter, paralleler Telemetrie-Kollektor, der für die tiefgehende Entdeckung von Subdomänen und die aktive Validierung des Perimeter-Footprints entwickelt wurde.

Er übernimmt die aufwändige Arbeit des Netzwerk-Probing durch das Mapping von Subdomänen, Validierung der aktiven DNS-Auflösung und Ausführung gezielter Heuristiken um kritische Risiken wie hängende CNAMEs, verwaiste Infrastrukturen und falsch konfigurierte Einträge zu erkennen, bevor Angreifer es tun.

---

## Die Architektur: Von roher Telemetrie zu intelligenten Einblicken

Dieses Utility ist als eigenständiger Worker für die ZoneAudit-Datenpipeline konzipiert.

1. **Die Community Edition (Dieses Repo):** Führt hochgeschwindigkeits-parallele Scans durch und liefert rohe Telemetrie im Text- oder JSON-Format.
2. **Die ZoneAudit-Plattform:** Verarbeitet Telemetrie durch eine asynchrone KI-Engine um **Intelligente Insight-Berichte** zu erstellen, die entwickelt wurden, um den „3-Uhr-Morgens-Test“ für Führungskräfte in 3 Sekunden zu bestehen.

---

## Erste Schritte

### Unterstützte Sprachen

| Sprache | Code | Aktivierung |
| :--- | :--- | :--- |
| Englisch | `en` | Standard |
| Französisch | `fr` | `-lang fr` oder `LANG=fr` |
| Deutsch | `de` | `-lang de` oder `LANG=de` |

### Installation

Stellen Sie sicher, dass [Go](https://go.dev/dl/) auf Ihrem System installiert ist.

```bash
go install github.com/ZoneAudit/zoneaudit-cli/cmd/zoneaudit@latest
```

---

## Holen Sie sich die vollständige KI-gestützte Suite

Während dieses CLI-Tool die rohe Datenerfassung übernimmt, bietet die vollständige Enterprise-Lösung automatisierte Zeitplanung, ein zentralisiertes Ingestion-Backend und KI-gesteuerte Triage-Berichte.

[Melden Sie sich auf der Warteliste von ZoneAudit.com an](https://zoneaudit.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition_de), um frühen Zugang zur Plattform zu erhalten.

---

## Roadmap und Community-Zukunft

Die **ZoneAudit Community Edition** ist der leichtgewichtige Open-Source-Einstiegspunkt in unser Ökosystem. Während der aktuelle Fokus auf Hochgeschwindigkeits-Subdomain- und SSL/TLS-Telemetrie liegt, we evaluieren die folgenden Funktionen für zukünftige Versionen:

- **Erweitertes Protokoll-Probing:** Native SMTP-, FTP- und SSH-Handshake-Heuristiken zur Identifizierung exponierter Legacy-Dienste.
- **Header-Analyse:** Passive Inspektion von Security-Headern (HSTS, CSP, X-Frame-Options) während der HTTP(S)-Validierung.
- **Port-Erkennung:** Integration gezielter Port-Scans für standardmäßige Hochrisiko-Industrie- und Datenbank-Ports.
- **Lokale Persistenz:** Unterstützung für lokale SQLite-Speicherung zur Verfolgung historischer Änderungen einer Angriffsoberfläche.

Wir freuen uns über Feedback dazu, welche dieser oder anderer Funktionen Ihre Security-Workflows am besten unterstützen würden.

---

### Lizenz

Dieses Projekt lizenziert unter der **MIT-Lizenz**. Siehe die Datei [LICENSE](LICENSE) für den vollständigen Text.

### 🇬🇧 Entwickelt im Vereinigten Königreich von [CobraSphere](https://cobrasphere.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition_de)
