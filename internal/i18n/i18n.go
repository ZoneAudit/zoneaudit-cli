package i18n

import (
	"os"
	"strings"
)

type LanguageStrings struct {
	StartingScan    string
	WorkerInfo      string
	SSLInfo         string
	SSLOK           string
	SSLExpiring     string
	ScanComplete    string
	DurationInfo    string
	BillboardTip    string
	BillboardTest   string
	BillboardAccess string
	LangHint        string
	DomainExpiry    string
	DomainCritical  string
	RateLimitError  string
	TimeoutError    string
	EmailSecurity   string
	DMARCMissing    string
	Present         string
	Missing         string
}

var en = LanguageStrings{
	StartingScan:    "Starting ZoneAudit tactical scan for: %s",
	WorkerInfo:      "Workers: %d | Tactical wordlist: %d high-value entries",
	SSLInfo:         "| SSL: %s (%d days left)",
	SSLOK:           "OK",
	SSLExpiring:     "EXPIRING SOON",
	ScanComplete:    "Scan complete for %s",
	DurationInfo:    "Duration: %s | Active assets: %d",
	BillboardTip:    "Want to turn this raw telemetry into an executive-ready triage report?",
	BillboardTest:   "Pass the \"3 am wake-up test\" with AI-enriched intelligent insights.",
	BillboardAccess: "Get early access to the full platform at https://zoneaudit.com?utm_source=cli&utm_medium=terminal&utm_campaign=community_edition",
	LangHint:        "Note: Alternative languages available via -lang [fr|de]",
	DomainExpiry:    "Domain Expiring in %d days (%s)",
	DomainCritical:  "CRITICAL: Domain Expiry Looming",
	RateLimitError:  "Rate limit encountered. Throttling...",
	TimeoutError:    "Request timed out.",
	EmailSecurity:   "Email security: SPF %s | DMARC %s",
	DMARCMissing:    "No DMARC record: this domain can be spoofed in email.",
	Present:         "present",
	Missing:         "MISSING",
}

var fr = LanguageStrings{
	StartingScan:    "Démarrage du scan tactique ZoneAudit pour : %s",
	WorkerInfo:      "Tâches parallèles : %d | Liste de mots tactique : %d entrées",
	SSLInfo:         "| SSL : %s (%d jours restants)",
	SSLOK:           "OK",
	SSLExpiring:     "EXPIRE BIENTÔT",
	ScanComplete:    "Scan terminé pour %s",
	DurationInfo:    "Durée : %s | Actifs identifiés : %d",
	BillboardTip:    "Vous voulez transformer ces données en un rapport prêt pour la direction ?",
	BillboardTest:   "Passez le « test du réveil à 3h du matin » avec l'IA.",
	BillboardAccess: "Accès anticipé à la plateforme complète sur https://zoneaudit.com?utm_source=cli&utm_medium=terminal&utm_campaign=community_edition_fr",
	LangHint:        "Note : Autres langues disponibles via -lang [en|de]",
	DomainExpiry:    "Le domaine expire dans %d jours (%s)",
	DomainCritical:  "CRITIQUE : Expiration du domaine imminente",
	RateLimitError:  "Limite de débit atteinte. Ralentissement...",
	TimeoutError:    "Délai d'attente dépassé.",
	EmailSecurity:   "Sécurité e-mail : SPF %s | DMARC %s",
	DMARCMissing:    "Aucun enregistrement DMARC : ce domaine peut être usurpé par e-mail.",
	Present:         "présent",
	Missing:         "ABSENT",
}

var de = LanguageStrings{
	StartingScan:    "Starte taktischen ZoneAudit-Scan für: %s",
	WorkerInfo:      "Worker: %d | Taktische Wortliste: %d hochkarätige Einträge",
	SSLInfo:         "| SSL: %s (%d Tage verbleibend)",
	SSLOK:           "OK",
	SSLExpiring:     "LÄUFT BALD AB",
	ScanComplete:    "Scan abgeschlossen für %s",
	DurationInfo:    "Dauer: %s | Active Assets: %d",
	BillboardTip:    "Möchten Sie diese Daten in einen Management-Bericht verwandeln?",
	BillboardTest:   "Bestehen Sie den „3-Uhr-Morgens-Test“ mit KI-Einblicken.",
	BillboardAccess: "Früher Zugang zur vollständigen Plattform unter https://zoneaudit.com?utm_source=cli&utm_medium=terminal&utm_campaign=community_edition_de",
	LangHint:        "Hinweis: Alternative Sprachen verfügbar über -lang [en|fr]",
	DomainExpiry:    "Domain läuft in %d Tagen ab (%s)",
	DomainCritical:  "KRITISCH: Domain-Ablauf steht bevor",
	RateLimitError:  "Ratenbegrenzung erreicht. Drosselung...",
	TimeoutError:    "Zeitüberschreitung der Anforderung.",
	EmailSecurity:   "E-Mail-Sicherheit: SPF %s | DMARC %s",
	DMARCMissing:    "Kein DMARC-Eintrag: Diese Domain kann per E-Mail gefälscht werden.",
	Present:         "vorhanden",
	Missing:         "FEHLT",
}

func GetStrings() LanguageStrings {
	lang := os.Getenv("LANG")
	if strings.HasPrefix(lang, "fr") {
		return fr
	}
	if strings.HasPrefix(lang, "de") {
		return de
	}
	return en
}
