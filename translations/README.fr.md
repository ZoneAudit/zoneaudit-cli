# ZoneAudit™ Community Edition

[![ci](https://github.com/ZoneAudit/zoneaudit-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ZoneAudit/zoneaudit-cli/actions/workflows/ci.yml?query=branch%3Amain)
[![MIT licence](https://img.shields.io/badge/licence-MIT-blue.svg)](../LICENSE)

> **Langues :** [English](README.en.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

**Découverte en lecture seule de l'empreinte publique d'un domaine : sous-domaines, DNS, certificats, expiration du domaine et sécurité e-mail.**

ZoneAudit Community Edition vérifie un domaine et 143 noms d'hôtes courants sous ce domaine. Pour chaque hôte existant, elle indique les enregistrements DNS, signale un CNAME dont la cible ne se résout plus (CNAME pendant), lit la date d'expiration et l'émetteur du certificat, et relève la bannière du serveur web et le titre de la page. Pour le domaine lui-même, elle lit la date d'expiration de l'enregistrement via RDAP et vérifie SPF et DMARC, avec un avertissement lorsque DMARC est en `p=none`.

Le CLI affiche des résultats bruts, en lecture seule ; le service ZoneAudit en fait un rapport hiérarchisé et étayé de preuves.

---

## Utilisation responsable

**Analysez uniquement les domaines dont vous êtes propriétaire ou que vous êtes autorisé à évaluer.**

Pour chaque hôte trouvé, ZoneAudit résout les enregistrements DNS, effectue une négociation TLS et une requête HTTP(S) légère (en HTTP simple uniquement si HTTPS ne répond pas, avec au plus 2 redirections). Il effectue aussi une requête RDAP pour la date d'expiration du domaine. Il ne scanne pas les ports et ne tente aucun accès.

Chaque requête (chaque résolution DNS, négociation TLS, requête HTTP et la requête RDAP) passe par une même limite de débit, 25 requêtes par seconde par défaut (`-rate`, 100 au maximum), et a son propre délai d'attente, 5 secondes par défaut (`-timeout`). Le même avertissement figure en tête de `zoneaudit --help`.

## Installation

Avec [Go](https://go.dev/dl/) 1.22 ou ultérieur :

```bash
go install github.com/ZoneAudit/zoneaudit-cli/cmd/zoneaudit@latest
```

Ou téléchargez une archive pour Linux, macOS ou Windows (amd64 ou arm64) depuis la [page des versions](https://github.com/ZoneAudit/zoneaudit-cli/releases).

### Vérifier une version

À partir de la v0.3.0, `checksums.txt` est signé avec la signature sans clé de [cosign](https://docs.sigstore.dev/) par le workflow de publication de ce dépôt, et chaque archive est accompagnée d'une nomenclature logicielle SPDX (`*.sbom.json`). Pour vérifier un téléchargement :

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ZoneAudit/zoneaudit-cli/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

## Utilisation

```bash
zoneaudit -d example.com
```

| Option | Défaut | Signification |
| :--- | :--- | :--- |
| `-d` | | Domaine à analyser |
| `-c` | 10 | Tâches parallèles (1 à 50) |
| `-rate` | 25 | Nombre maximal de requêtes par seconde, DNS, TLS, HTTP et RDAP confondus (1 à 100) |
| `-timeout` | 5s | Délai d'attente de chaque requête (1s à 60s) |
| `-json` | non | Rapport JSON au lieu du texte |
| `-lang` | `LANG` | Langue de sortie : `en`, `fr` ou `de` |
| `-version` | | Affiche la version |

### Exemple de rapport

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

Voici la sortie du CLI sur ses données de test : les données RDAP de `example.com` sont une réponse enregistrée, tandis que les autres hôtes, enregistrements et certificats sont inventés pour montrer chaque type de résultat, et l'horloge est figée (d'où `Duration: 0s`). Une analyse réelle de 143 noms d'hôtes au débit par défaut prend environ 30 secondes. Avec `-lang fr`, la sortie est en français.

### Sortie JSON

```bash
zoneaudit -d example.com -json
```

Le rapport JSON comporte un champ `schema_version` (actuellement `"1.1"`). Au sein de la version majeure 1, aucun champ n'est supprimé, renommé ni ne change de sens ; de nouveaux champs facultatifs peuvent être ajoutés, ce qui augmente le numéro mineur. Le format est décrit dans [docs/json-output.md](../docs/json-output.md) (en anglais).

Un rapport abrégé issu des mêmes données de test :

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

### Langues

| Langue | Code | Activation | Documentation |
| :--- | :--- | :--- | :--- |
| English | `en` | Par défaut | [README.en.md](README.en.md) |
| Français | `fr` | `-lang fr` ou `LANG=fr` | [README.fr.md](README.fr.md) |
| Deutsch | `de` | `-lang de` ou `LANG=de` | [README.de.md](README.de.md) |

Les traductions sont fournies à titre de commodité et peuvent varier en nuance technique.

```bash
LANG=fr zoneaudit -d example.com
zoneaudit -d example.com -lang de
```

Consultez le [CHANGELOG.fr.md](CHANGELOG.fr.md) pour les changements de chaque version.

---

## Feuille de route

Nous envisageons une inspection passive des en-têtes de sécurité (HSTS, CSP, X-Frame-Options) lors de la requête HTTP(S) que le CLI effectue déjà. Vos retours sur ce qui vous aiderait sont les bienvenus dans les [issues](https://github.com/ZoneAudit/zoneaudit-cli/issues).

---

## Des résultats au rapport

Ce CLI collecte les résultats bruts. Le service ZoneAudit en fait un rapport hiérarchisé et étayé de preuves, y compris le niveau 0 du DCC pour les fournisseurs du ministère britannique de la Défense.

[Demander un accès sur zoneaudit.com](https://zoneaudit.com/?utm_source=github&utm_medium=readme&utm_campaign=community_edition_fr)

---

## Communauté

- **Bogues et questions :** [ouvrez une issue GitHub](https://github.com/ZoneAudit/zoneaudit-cli/issues).
- **Vulnérabilités de sécurité :** n'ouvrez pas d'issue publique ; consultez [SECURITY.md](../SECURITY.md).
- **Contribuer :** consultez [CONTRIBUTING.md](../CONTRIBUTING.md).

### Licence

Ce projet est sous **licence MIT**. Consultez le fichier [LICENSE](../LICENSE) pour le texte complet.

Conçu au Royaume-Uni par [CobraSphere](https://cobrasphere.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition_fr).
