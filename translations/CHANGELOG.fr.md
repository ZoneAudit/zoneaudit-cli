# Journal des modifications

> **Langues :** [English](CHANGELOG.en.md) | [Français](CHANGELOG.fr.md) | [Deutsch](CHANGELOG.de.md)

Toutes les modifications notables de la ZoneAudit™ Community Edition seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhère au [Versionnement Sémantique](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-03

### Ajouté
- **Intégration RDAP** : Récupération automatisée des dates d'expiration des domaines pour identifier les risques critiques de renouvellement.
- **Empreinte de service** : Extraction des bannières HTTP et des titres de page pour les services web actifs.
- **Barre de progression tactique** : Indicateur de progression en temps réel pour la découverte de sous-domaines.
- **Base de sécurité des e-mails** : Vérification de la présence des enregistrements SPF et DMARC.
- **Détection DNS pendante** : Signalisation proactive des enregistrements CNAME pointant vers des cibles inexistantes.
- **Résolution "Fail-Fast"** : Validation immédiate de la connectivité du domaine racine avant le scan.
- **Support multilingue** : Prise en charge complète de la sortie terminal et de la documentation pour le français (`fr`) et l'allemand (`de`).

### Changé
- Liste de mots tactiques étendue à 143 points chauds d'infrastructure à haute valeur.
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
