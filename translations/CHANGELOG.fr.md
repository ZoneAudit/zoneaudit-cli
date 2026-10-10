# Journal des modifications

> **Langues :** [English](CHANGELOG.en.md) | [Français](CHANGELOG.fr.md) | [Deutsch](CHANGELOG.de.md)

Toutes les modifications notables de la ZoneAudit™ Community Edition seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhère au [Versionnement Sémantique](https://semver.org/spec/v2.0.0.html).

## [Non publié]

## [0.3.0] - 2026-10-09

### Ajouté
- **Tests pour chaque vérification**, exécutés sur des données enregistrées, sans réseau : expiration RDAP, découverte de sous-domaines, enregistrements A/AAAA, CNAME, TXT et MX, signalement des CNAME pendants, SPF et DMARC (y compris l'avertissement `p=none`), expiration et émetteur des certificats, et bannière HTTP.
- **CI sur chaque pull request** : tests sous Linux, macOS et Windows, en amd64 et arm64, avec `go vet`, staticcheck, une publication à blanc et des vérifications des installateurs en une ligne (macOS, Windows PowerShell 5.1, PowerShell 7 et ARM).
- **Analyse courtoise** : `-rate` plafonne les requêtes par seconde, DNS, TLS, HTTP et RDAP confondus (25 par défaut, 100 au maximum), et `-timeout` borne chaque requête (5 s par défaut). Les requêtes s'identifient avec un User-Agent `zoneaudit-cli/<version>`.
- **Versions signées** : `checksums.txt` est signé avec la signature sans clé de cosign (OIDC GitHub, aucune clé stockée) et chaque archive a une nomenclature SPDX.
- **Paquets** : le workflow de publication génère un cask Homebrew et un manifeste Scoop, et les publie dès que les dépôts du tap et du bucket existent.
- **Sortie JSON stable** avec un champ `schema_version` (`"1.1"`), documentée dans `docs/json-output.md` ; le rapport indique aussi l'heure, la durée, les limites utilisées et le nombre de requêtes.
- `SECURITY.md`, `CONTRIBUTING.md` et un exemple de rapport dans le README.
- Option `-version`.
- Une analyse interrompue (Ctrl+C) écrit tout de même le rapport partiel, puis se termine avec le code 130.
- Un échec de requête DNS est signalé comme tel : SPF et DMARC indiquent `unavailable` (et non absent, sans avertissement d'usurpation), et un CNAME dont la cible n'a pas pu être résolue est marqué `UNCHECKED` plutôt que pendant.

### Changé
- `--help` commence par l'avertissement d'utilisation responsable.
- Le rapport texte se termine par une ligne sur la demande d'accès à la revue ZoneAudit complète.
- Les résultats sont triés (le domaine d'abord, puis par nom), ainsi que les enregistrements de chaque hôte, pour des rapports reproductibles.
- L'argument de domaine est normalisé (casse, point final, URL collée) et refusé s'il ne s'agit pas d'un nom de domaine.
- Les erreurs et la barre de progression vont sur la sortie d'erreur ; la sortie JSON est indentée.
- La section d'architecture du README est remplacée par une description d'une ligne, et la feuille de route ne mentionne plus le sondage de protocoles ni le stockage local de l'historique.

### Corrigé
- Le workflow de publication installe Go avec `actions/setup-go` (il exécutait `actions/checkout` deux fois).
- Les requêtes RDAP vérifient le certificat du serveur.
- Les jours restants d'un certificat ou d'un domaine expiré sont arrondis vers le bas : une expiration de moins d'un jour donne -1, et non 0.
- Le délai d'attente HTTP par requête démarre après l'attente du limiteur de débit, de sorte que les requêtes en file à faible `-rate` n'expirent plus avant d'être envoyées.
- Un préfixe proche de `v=spf1`, comme `v=spf10`, n'est plus compté comme SPF.

## [0.2.0] - 2026-06-03

### Ajouté
- **Intégration RDAP** : Récupération automatisée des dates d'expiration des domaines pour identifier les risques critiques de renouvellement.
- **Empreinte de service** : Extraction des bannières HTTP et des titres de page pour les services web actifs.
- **Barre de progression** : Indicateur de progression en temps réel pour la découverte de sous-domaines.
- **Base de sécurité des e-mails** : Vérification de la présence des enregistrements SPF et DMARC.
- **Détection DNS pendante** : Signalisation proactive des enregistrements CNAME pointant vers des cibles inexistantes.
- **Résolution "Fail-Fast"** : Validation immédiate de la connectivité du domaine racine avant le scan.
- **Support multilingue** : Prise en charge complète de la sortie terminal et de la documentation pour le français (`fr`) et l'allemand (`de`).

### Changé
- Liste de mots étendue à 143 noms d'hôtes d'infrastructure courants.
- Refonte de la sortie terminal pour une "Engineering Precision" : donnant la priorité à la clarté opérationnelle sur les vidages de données brutes.
- Mise à jour de la documentation d'architecture pour utiliser des flux Mermaid verticaux.

## [0.1.1] - 2026-06-03

### Ajouté
- Extension des sondages DNS pour inclure les enregistrements MX et TXT.
- Support initial pour les tables de chaînes localisées dans `internal/i18n`.

### Changé
- Amélioration de la gestion des délais d'attente de validation SSL.

## [0.1.0] - 2026-03-31

### Ajouté
- Sortie initiale de ZoneAudit™ Community Edition.
- Moteur de découverte de sous-domaines concurrent en Go.
- Validation de base des certificats SSL/TLS.
- Support de sortie JSON pour l'intégration de pipeline.
