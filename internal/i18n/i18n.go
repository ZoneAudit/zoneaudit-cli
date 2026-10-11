// Package i18n holds the English, French and German terminal strings.
package i18n

import (
	"os"
	"strings"
)

// LanguageStrings holds the terminal output strings for one language.
type LanguageStrings struct {
	StartingScan   string
	WorkerInfo     string
	SSLInfo        string
	SSLOK          string
	SSLExpiring    string
	ScanComplete   string
	DurationInfo   string
	RequestAccess  string
	LangHint       string
	DomainExpiry   string
	DomainCritical string
	EmailSecurity  string
	DMARCMissing   string
	DMARCNone      string
	Present        string
	Missing        string
}

var en = LanguageStrings{
	StartingScan:   "Starting ZoneAudit scan for: %s",
	WorkerInfo:     "Workers: %d | Wordlist: %d common hostnames",
	SSLInfo:        "| SSL: %s (%d days left)",
	SSLOK:          "OK",
	SSLExpiring:    "EXPIRING SOON",
	ScanComplete:   "Scan complete for %s",
	DurationInfo:   "Duration: %s | Active assets: %d",
	RequestAccess:  "For the full ZoneAudit review, request access at https://zoneaudit.com/?utm_source=cli",
	LangHint:       "Note: Alternative languages available via -lang [fr|de]",
	DomainExpiry:   "Domain Expiring in %d days (%s)",
	DomainCritical: "CRITICAL: Domain Expiry Looming",
	EmailSecurity:  "Email security: SPF %s | DMARC %s",
	DMARCMissing:   "No DMARC record: this domain can be spoofed in email.",
	DMARCNone:      "DMARC policy is 'none' (monitoring only): spoofed email is not blocked.",
	Present:        "present",
	Missing:        "MISSING",
}

var fr = LanguageStrings{
	StartingScan:   "Démarrage du scan ZoneAudit pour : %s",
	WorkerInfo:     "Tâches parallèles : %d | Liste de mots : %d noms d'hôtes courants",
	SSLInfo:        "| SSL : %s (%d jours restants)",
	SSLOK:          "OK",
	SSLExpiring:    "EXPIRE BIENTÔT",
	ScanComplete:   "Scan terminé pour %s",
	DurationInfo:   "Durée : %s | Actifs identifiés : %d",
	RequestAccess:  "Pour la revue ZoneAudit complète, demandez un accès sur https://zoneaudit.com/?utm_source=cli",
	LangHint:       "Note : Autres langues disponibles via -lang [en|de]",
	DomainExpiry:   "Le domaine expire dans %d jours (%s)",
	DomainCritical: "CRITIQUE : Expiration du domaine imminente",
	EmailSecurity:  "Sécurité e-mail : SPF %s | DMARC %s",
	DMARCMissing:   "Aucun enregistrement DMARC : ce domaine peut être usurpé par e-mail.",
	DMARCNone:      "Politique DMARC « none » (surveillance seule) : les e-mails usurpés ne sont pas bloqués.",
	Present:        "présent",
	Missing:        "ABSENT",
}

var de = LanguageStrings{
	StartingScan:   "Starte ZoneAudit-Scan für: %s",
	WorkerInfo:     "Worker: %d | Wortliste: %d gängige Hostnamen",
	SSLInfo:        "| SSL: %s (%d Tage verbleibend)",
	SSLOK:          "OK",
	SSLExpiring:    "LÄUFT BALD AB",
	ScanComplete:   "Scan abgeschlossen für %s",
	DurationInfo:   "Dauer: %s | Aktive Hosts: %d",
	RequestAccess:  "Für die vollständige ZoneAudit-Prüfung fordern Sie Zugang an: https://zoneaudit.com/?utm_source=cli",
	LangHint:       "Hinweis: Alternative Sprachen verfügbar über -lang [en|fr]",
	DomainExpiry:   "Domain läuft in %d Tagen ab (%s)",
	DomainCritical: "KRITISCH: Domain-Ablauf steht bevor",
	EmailSecurity:  "E-Mail-Sicherheit: SPF %s | DMARC %s",
	DMARCMissing:   "Kein DMARC-Eintrag: Diese Domain kann per E-Mail gefälscht werden.",
	DMARCNone:      "DMARC-Richtlinie 'none' (nur Überwachung): gefälschte E-Mails werden nicht blockiert.",
	Present:        "vorhanden",
	Missing:        "FEHLT",
}

// GetStrings returns the strings for the language in the LANG environment variable.
func GetStrings() LanguageStrings {
	return For(os.Getenv("LANG"))
}

// For returns the strings for a language code such as "fr" or "de_DE.UTF-8".
// Anything else gets English.
func For(lang string) LanguageStrings {
	lang = strings.ToLower(lang)
	if strings.HasPrefix(lang, "fr") {
		return fr
	}
	if strings.HasPrefix(lang, "de") {
		return de
	}
	return en
}

// Supported reports whether code is one of the languages the CLI ships.
func Supported(code string) bool {
	switch strings.ToLower(code) {
	case "en", "fr", "de":
		return true
	}
	return false
}
