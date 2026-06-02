# ZoneAudit Community Edition

The ZoneAudit Community Edition is a high-performance, concurrent telemetry collector written in Go, designed for deep subdomain discovery and active perimeter footprint validation. 

It handles the noisy, heavy lifting of network probing by mapping subdomains, validating active DNS resolution, and executing targeted heuristics to spot critical edge risks like dangling CNAMEs, orphaned infrastructure, and misconfigured records before attackers do.

---

## The architecture: from raw telemetry to intelligent insight

This utility is built to function as a decoupled, standalone worker for the ZoneAudit data pipeline. 

1. **The Community Edition (This repo):** Executes high-velocity concurrent scans and provides raw telemetry in text or JSON format.
2. **The ZoneAudit platform:** Processes telemetry through an asynchronous AI engine to generate **Intelligent insight reports** that are designed to pass the "3 am wake-up test" for business executives within 3 seconds.

---

## Getting started

### Supported languages

The CLI supports the following languages. Note that translations are provided as a convenience and may vary in technical nuance.

| Language | Code | Activation | Documentation |
| :--- | :--- | :--- | :--- |
| English | `en` | Default | [README.md](README.md) |
| Français | `fr` | `-lang fr` or `LANG=fr` | [README.fr.md](README.fr.md) |
| Deutsch | `de` | `-lang de` or `LANG=de` | [README.de.md](README.de.md) |

#### Setting the language environment variable

You can set the `LANG` environment variable in your terminal session to change the output language. On Linux or macOS, you can do this for a single command:

```bash
LANG=fr zoneaudit -d example.com
```

Alternatively, you can use the built-in flag:

```bash
zoneaudit -d example.com -lang fr
```

Ensure you have [Go](https://go.dev/dl/) installed on your system.

```bash
go install github.com/ZoneAudit/zoneaudit-cli/cmd/zoneaudit@latest
```

### Usage

Scan any domain to reveal active subdomains and DNS exposure:

```bash
zoneaudit -d example.com
```

Output as JSON for pipeline integration:

```bash
zoneaudit -d example.com -json
```

---

## Roadmap and Community Future

The **ZoneAudit Community Edition** is the lightweight, open-source entry point to our ecosystem. While the current focus is high-velocity subdomain and SSL/TLS telemetry, we are evaluating the following capabilities for future releases:

- **Enhanced Protocol Probing:** Native SMTP, FTP, and SSH handshake heuristics to identify exposed legacy services.
- **Header Analysis:** Passive inspection of security headers (HSTS, CSP, X-Frame-Options) during HTTP(S) validation.
- **Port Discovery:** Integration of targeted port scanning for standard high-risk industrial and database ports.
- **Local Persistence:** Support for local SQLite storage to track historical changes in an attack surface over time.

We welcome feedback on which of these (or other features) would most help your security workflows.

---

## Get the full AI-enriched suite

While this CLI utility handles raw data collection, the full enterprise experience provides automated scheduling, a centralised ingestion backend, and AI-driven triage reporting.

[Join the Waitlist at ZoneAudit.com](https://zoneaudit.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition) to get early access to the Intelligent Attack Surface platform.

---

## Community and governance

### Raising bugs and questions

If you have an idea, find a bug, or just have a question about the tool, please [open a GitHub issue](https://github.com/ZoneAudit/zoneaudit-cli/issues). We’ll do our best to jump in and help.

### Contributing

We’re happy to see contributions from the community. If you want to help out:

1. Fork the repo.
2. Create your branch (`git checkout -b feature/your-feature`).
3. Commit your changes.
4. Open a pull request.

Keep an eye on the existing style and make sure any new logic is tested.

### License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for the full text.

### 🇬🇧 Built in the UK by [CobraSphere](https://cobrasphere.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition)
