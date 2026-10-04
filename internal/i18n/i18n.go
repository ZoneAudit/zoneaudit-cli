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
	DMARCNone       string
	Present         string
	Missing         string
}

var en = LanguageStrings{
	StartingScan:    "Starting ZoneAudit scan for: %s",
	WorkerInfo:      "Workers: %d | Wordlist: %d common hostnames",
	SSLInfo:         "| SSL: %s (%d days left)",
	SSLOK:           "OK",
	SSLExpiring:     "EXPIRING SOON",
	ScanComplete:    "Scan complete for %s",
	DurationInfo:    "Duration: %s | Active assets: %d",
	BillboardTip:    "Need these findings turned into a prioritised report with fixes, including DCC Level 0 readiness?",
	BillboardTest:   "A ZoneAudit readiness review covers it.",
	BillboardAccess: "Arrange one at https://zoneaudit.com?utm_source=cli&utm_medium=terminal&utm_campaign=community_edition",
	LangHint:        "Note: Alternative languages available via -lang [fr|de]",
	DomainExpiry:    "Domain Expiring in %d days (%s)",
	DomainCritical:  "CRITICAL: Domain Expiry Looming",
	RateLimitError:  "Rate limit encountered. Throttling...",
	TimeoutError:    "Request timed out.",
	EmailSecurity:   "Email security: SPF %s | DMARC %s",
	DMARCMissing:    "No DMARC record: this domain can be spoofed in email.",
	DMARCNone:       "DMARC policy is 'none' (monitoring only): spoofed email is not blocked.",
	Present:         "present",
	Missing:         "MISSING",
}

var fr = LanguageStrings{
	StartingScan:    "Démarrage du scan ZoneAudit pour : %s",
	WorkerInfo:      "Tâches parallèles : %d | Liste de mots : %d noms d'hôtes courants",
	SSLInfo:         "| SSL : %s (%d jours restants)",
	SSLOK:           "OK",
	SSLExpiring:     "EXPIRE BIENTÔT",
	ScanComplete:    "Scan terminé pour %s",
	DurationInfo:    "Durée : %s | Actifs identifiés : %d",
	BillboardTip:    "Besoin d'un rapport hiérarchisé avec les corrections, y compris le niveau 0 du DCC ?",
	BillboardTest:   "Une revue ZoneAudit le couvre.",
	BillboardAccess: "Demandez-la sur https://zoneaudit.com?utm_source=cli&utm_medium=terminal&utm_campaign=community_edition_fr",
	LangHint:        "Note : Autres langues disponibles via -lang [en|de]",
	DomainExpiry:    "Le domaine expire dans %d jours (%s)",
	DomainCritical:  "CRITIQUE : Expiration du domaine imminente",
	RateLimitError:  "Limite de débit atteinte. Ralentissement...",
	TimeoutError:    "Délai d'attente dépassé.",
	EmailSecurity:   "Sécurité e-mail : SPF %s | DMARC %s",
	DMARCMissing:    "Aucun enregistrement DMARC : ce domaine peut être usurpé par e-mail.",
	DMARCNone:       "Politique DMARC « none » (surveillance seule) : les e-mails usurpés ne sont pas bloqués.",
	Present:         "présent",
	Missing:         "ABSENT",
}

var de = LanguageStrings{
	StartingScan:    "Starte ZoneAudit-Scan für: %s",
	WorkerInfo:      "Worker: %d | Wortliste: %d gängige Hostnamen",
	SSLInfo:         "| SSL: %s (%d Tage verbleibend)",
	SSLOK:           "OK",
	SSLExpiring:     "LÄUFT BALD AB",
	ScanComplete:    "Scan abgeschlossen für %s",
	DurationInfo:    "Dauer: %s | Aktive Hosts: %d",
	BillboardTip:    "Brauchen Sie einen priorisierten Bericht mit Maßnahmen, einschließlich DCC Level 0?",
	BillboardTest:   "Eine ZoneAudit-Readiness-Prüfung deckt das ab.",
	BillboardAccess: "Anfragen unter https://zoneaudit.com?utm_source=cli&utm_medium=terminal&utm_campaign=community_edition_de",
	LangHint:        "Hinweis: Alternative Sprachen verfügbar über -lang [en|fr]",
	DomainExpiry:    "Domain läuft in %d Tagen ab (%s)",
	DomainCritical:  "KRITISCH: Domain-Ablauf steht bevor",
	RateLimitError:  "Ratenbegrenzung erreicht. Drosselung...",
	TimeoutError:    "Zeitüberschreitung der Anforderung.",
	EmailSecurity:   "E-Mail-Sicherheit: SPF %s | DMARC %s",
	DMARCMissing:    "Kein DMARC-Eintrag: Diese Domain kann per E-Mail gefälscht werden.",
	DMARCNone:       "DMARC-Richtlinie 'none' (nur Überwachung): gefälschte E-Mails werden nicht blockiert.",
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
