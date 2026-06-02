# ZoneAudit Community Edition (Français)

ZoneAudit Community Edition est un collecteur de télémétrie concurrent à haute performance écrit en Go, conçu pour la découverte approfondie de sous-domaines et la validation active de l'empreinte du périmètre.

Il gère le travail de sondage réseau par la cartographie des sous-domaines, la validation de la résolution DNS active et l'exécution d'heuristiques ciblées pour repérer les risques critiques tels que les CNAME pendants, les infrastructures orphelines et les enregistrements mal configurés avant que les attaquants ne le fassent.

---

## L'architecture : de la télémétrie brute à l'insight intelligent

Cet utilitaire est conçu pour fonctionner comme un agent indépendant pour le pipeline de données ZoneAudit.

1. **L'édition communautaire (Ce repo) :** Exécute des scans concurrents à haute vélocité et fournit de la télémétrie brute au format texte ou JSON.
2. **La plateforme ZoneAudit :** Traite la télémétrie via un moteur d'IA asynchrone pour générer des **rapports d'insights intelligents**, conçus pour passer le « test du réveil à 3h du matin » pour les dirigeants d'entreprise en moins de 3 secondes.

---

## Mise en route

### Langues supportées

| Langue | Code | Activation |
| :--- | :--- | :--- |
| English | `en` | Par défaut |
| Français | `fr` | `-lang fr` ou `LANG=fr` |
| Deutsch | `de` | `-lang de` ou `LANG=de` |

### Installation

Assurez-vous d'avoir [Go](https://go.dev/dl/) installé sur votre système.

```bash
go install github.com/ZoneAudit/zoneaudit-cli/cmd/zoneaudit@latest
```

---

## Obtenez la suite complète enrichie par l'IA

Alors que cet utilitaire CLI gère la collecte de données brutes, l'expérience d'entreprise complète offre une planification automatisée, un backend d'ingestion centralisé et des rapports de triage pilotés par l'IA.

[Rejoignez la liste d'attente sur ZoneAudit.com](https://zoneaudit.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition_fr) pour obtenir un accès anticipé à la plateforme.

---

## Feuille de route et futur de la communauté

**ZoneAudit Community Edition** est le point d'entrée léger et open-source de notre écosystème. Bien que l'accent actuel soit mis sur la télémétrie haute vélocité des sous-domaines et SSL/TLS, nous évaluons les capacités suivantes pour les versions futures :

- **Sondage protocolaire amélioré :** Heuristiques natives SMTP, FTP et SSH pour identifier les services hérités exposés.
- **Analyse des en-têtes :** Inspection passive des en-têtes de sécurité (HSTS, CSP, X-Frame-Options) lors de la validation HTTP(S).
- **Découverte de ports :** Intégration de scans de ports ciblés pour les ports industriels et de bases de données à haut risque.
- **Persistance locale :** Prise en charge du stockage SQLite local pour suivre l'évolution historique d'une surface d'attaque.

Nous apprécions vos retours sur les fonctionnalités qui aideraient le plus vos flux de travail de sécurité.

---

### Licence

Ce projet est sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) file pour le texte complet.

### 🇬🇧 Conçu au Royaume-Uni par [CobraSphere](https://cobrasphere.com?utm_source=github&utm_medium=readme&utm_campaign=community_edition_fr)
