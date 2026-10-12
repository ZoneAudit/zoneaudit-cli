// Package i18n holds the English, French and German terminal strings.
package i18n

import (
	"os"
	"strings"
)

// LanguageStrings holds the terminal output strings for one language.
type LanguageStrings struct {
	StartingScan     string
	WorkerInfo       string
	SSLInfo          string
	SSLOK            string
	SSLExpiring      string
	ScanComplete     string
	DurationInfo     string
	RequestAccess    string
	LangHint         string
	DomainExpiry     string
	DomainCritical   string
	EmailSecurity    string
	DMARCMissing     string
	DMARCNone        string
	Present          string
	Missing          string
	Unavailable      string
	DMARCUnavailable string
	SPFUnavailable   string
	CouldNotCheck    string
	// ResponsibleUse is printed at the top of --help and when no domain is given.
	ResponsibleUse string

	// Help text. In the flag descriptions, the word in backquotes is the
	// value's placeholder in the help (as with the flag package).
	HelpUsage       string
	HelpOptions     string
	HelpDefault     string // %s is the default value
	FlagDomain      string
	FlagConcurrency string // %d is the maximum
	FlagRate        string // %d is the maximum
	FlagTimeout     string // %s, %s are the minimum and maximum
	FlagJSON        string // %s is the schema version
	FlagLang        string
	FlagVersion     string

	// Messages on standard error.
	Discovery          string // progress bar label
	Interrupted        string
	ErrUnsupportedLang string // %q is the code given
	ErrInvalidDomain   string // %q is the argument given
	ErrConcurrency     string // %d is the maximum
	ErrRate            string // %d is the maximum
	ErrTimeout         string // %s, %s are the minimum and maximum
	ErrRootResolution  string // %s is the domain
	ErrGeneric         string // %v is the error
}

var en = LanguageStrings{
	StartingScan:     "Starting ZoneAudit scan for: %s",
	WorkerInfo:       "Workers: %d | Wordlist: %d common hostnames",
	SSLInfo:          "| SSL: %s (%d days left)",
	SSLOK:            "OK",
	SSLExpiring:      "EXPIRING SOON",
	ScanComplete:     "Scan complete for %s",
	DurationInfo:     "Duration: %s | Active assets: %d",
	RequestAccess:    "For the full ZoneAudit review, request access at https://zoneaudit.com/?utm_source=cli",
	LangHint:         "Note: Alternative languages available via -lang [fr|de]",
	DomainExpiry:     "Domain Expiring in %d days (%s)",
	DomainCritical:   "CRITICAL: Domain Expiry Looming",
	EmailSecurity:    "Email security: SPF %s | DMARC %s",
	DMARCMissing:     "No DMARC record: this domain can be spoofed in email.",
	DMARCNone:        "DMARC policy is 'none' (monitoring only): spoofed email is not blocked.",
	Present:          "present",
	Missing:          "MISSING",
	Unavailable:      "could not check (lookup failed)",
	DMARCUnavailable: "DMARC could not be checked: the DNS lookup failed. Run the scan again.",
	SPFUnavailable:   "SPF could not be checked: the DNS lookup failed.",
	CouldNotCheck:    "could not check (lookup failed)",
	ResponsibleUse: `RESPONSIBLE USE: only scan domains you own or are authorised to assess.
For each host it finds, ZoneAudit resolves DNS records and, if the host has a
public address, makes one TLS handshake and one light HTTP(S) request (plain
HTTP only if HTTPS does not answer, following at most 2 redirects within the
scanned domain). It also makes one RDAP query for the domain's expiry date.
It does not scan ports or attempt access. All requests are capped by -rate
and each one is bounded by -timeout.`,
	HelpUsage:          "Usage: zoneaudit -d <domain> [-c n] [-rate n] [-timeout duration] [-json] [-lang en|fr|de]",
	HelpOptions:        "Options:",
	HelpDefault:        "(default %s)",
	FlagDomain:         "Target `domain` to scan (e.g. example.com)",
	FlagConcurrency:    "Number of concurrent workers, `n` from 1 to %d",
	FlagRate:           "Maximum requests per second across DNS, TLS, HTTP and RDAP, `n` from 1 to %d",
	FlagTimeout:        "Timeout for each request, a `duration` from %s to %s",
	FlagJSON:           "Output results as JSON (schema version %s)",
	FlagLang:           "Language `code` (en, fr or de); defaults to the LANG environment variable",
	FlagVersion:        "Print the version and exit",
	Discovery:          "Discovery",
	Interrupted:        "interrupted: results are incomplete",
	ErrUnsupportedLang: "error: unsupported language %q (use en, fr or de)",
	ErrInvalidDomain:   "error: %q is not a valid domain name",
	ErrConcurrency:     "error: -c must be between 1 and %d",
	ErrRate:            "error: -rate must be between 1 and %d requests per second",
	ErrTimeout:         "error: -timeout must be between %s and %s",
	ErrRootResolution:  "[CRITICAL] Root domain resolution failed for '%s'. Check connectivity or spelling.",
	ErrGeneric:         "error: %v",
}

var fr = LanguageStrings{
	StartingScan:     "Démarrage du scan ZoneAudit pour : %s",
	WorkerInfo:       "Tâches parallèles : %d | Liste de mots : %d noms d'hôtes courants",
	SSLInfo:          "| SSL : %s (%d jours restants)",
	SSLOK:            "OK",
	SSLExpiring:      "EXPIRE BIENTÔT",
	ScanComplete:     "Scan terminé pour %s",
	DurationInfo:     "Durée : %s | Actifs identifiés : %d",
	RequestAccess:    "Pour la revue ZoneAudit complète, demandez un accès sur https://zoneaudit.com/?utm_source=cli",
	LangHint:         "Note : Autres langues disponibles via -lang [en|de]",
	DomainExpiry:     "Le domaine expire dans %d jours (%s)",
	DomainCritical:   "CRITIQUE : Expiration du domaine imminente",
	EmailSecurity:    "Sécurité e-mail : SPF %s | DMARC %s",
	DMARCMissing:     "Aucun enregistrement DMARC : ce domaine peut être usurpé par e-mail.",
	DMARCNone:        "Politique DMARC « none » (surveillance seule) : les e-mails usurpés ne sont pas bloqués.",
	Present:          "présent",
	Missing:          "ABSENT",
	Unavailable:      "vérification impossible (échec de la requête)",
	DMARCUnavailable: "DMARC n'a pas pu être vérifié : la requête DNS a échoué. Relancez l'analyse.",
	SPFUnavailable:   "SPF n'a pas pu être vérifié : la requête DNS a échoué.",
	CouldNotCheck:    "vérification impossible (échec de la requête)",
	ResponsibleUse: `UTILISATION RESPONSABLE : n'analysez que les domaines qui vous appartiennent
ou que vous êtes autorisé à évaluer.
Pour chaque hôte trouvé, ZoneAudit résout les enregistrements DNS et, si l'hôte
a une adresse publique, effectue une négociation TLS et une requête HTTP(S)
légère (en HTTP simple uniquement si HTTPS ne répond pas, avec au plus
2 redirections au sein du domaine analysé). Il effectue aussi une requête RDAP
pour la date d'expiration du domaine. Il ne scanne pas les ports et ne tente
aucun accès. Toutes les requêtes sont limitées par -rate et chacune est bornée
par -timeout.`,
	HelpUsage:          "Utilisation : zoneaudit -d <domaine> [-c n] [-rate n] [-timeout durée] [-json] [-lang en|fr|de]",
	HelpOptions:        "Options :",
	HelpDefault:        "(par défaut : %s)",
	FlagDomain:         "Nom de `domaine` à analyser (par ex. example.com)",
	FlagConcurrency:    "Nombre de tâches parallèles, `n` de 1 à %d",
	FlagRate:           "Nombre maximal de requêtes par seconde, DNS, TLS, HTTP et RDAP confondus, `n` de 1 à %d",
	FlagTimeout:        "Délai d'attente de chaque requête, une `durée` de %s à %s",
	FlagJSON:           "Résultats au format JSON (version de schéma %s)",
	FlagLang:           "Langue, par son `code` (en, fr ou de) ; par défaut, celle de la variable d'environnement LANG",
	FlagVersion:        "Affiche la version et quitte",
	Discovery:          "Découverte",
	Interrupted:        "interrompu : les résultats sont incomplets",
	ErrUnsupportedLang: "erreur : langue non prise en charge %q (utilisez en, fr ou de)",
	ErrInvalidDomain:   "erreur : %q n'est pas un nom de domaine valide",
	ErrConcurrency:     "erreur : -c doit être compris entre 1 et %d",
	ErrRate:            "erreur : -rate doit être compris entre 1 et %d requêtes par seconde",
	ErrTimeout:         "erreur : -timeout doit être compris entre %s et %s",
	ErrRootResolution:  "[CRITIQUE] La résolution du domaine racine a échoué pour « %s ». Vérifiez la connexion ou l'orthographe.",
	ErrGeneric:         "erreur : %v",
}

var de = LanguageStrings{
	StartingScan:     "Starte ZoneAudit-Scan für: %s",
	WorkerInfo:       "Worker: %d | Wortliste: %d gängige Hostnamen",
	SSLInfo:          "| SSL: %s (%d Tage verbleibend)",
	SSLOK:            "OK",
	SSLExpiring:      "LÄUFT BALD AB",
	ScanComplete:     "Scan abgeschlossen für %s",
	DurationInfo:     "Dauer: %s | Aktive Hosts: %d",
	RequestAccess:    "Für die vollständige ZoneAudit-Prüfung fordern Sie Zugang an: https://zoneaudit.com/?utm_source=cli",
	LangHint:         "Hinweis: Alternative Sprachen verfügbar über -lang [en|fr]",
	DomainExpiry:     "Domain läuft in %d Tagen ab (%s)",
	DomainCritical:   "KRITISCH: Domain-Ablauf steht bevor",
	EmailSecurity:    "E-Mail-Sicherheit: SPF %s | DMARC %s",
	DMARCMissing:     "Kein DMARC-Eintrag: Diese Domain kann per E-Mail gefälscht werden.",
	DMARCNone:        "DMARC-Richtlinie 'none' (nur Überwachung): gefälschte E-Mails werden nicht blockiert.",
	Present:          "vorhanden",
	Missing:          "FEHLT",
	Unavailable:      "nicht prüfbar (Abfrage fehlgeschlagen)",
	DMARCUnavailable: "DMARC konnte nicht geprüft werden: Die DNS-Abfrage ist fehlgeschlagen. Führen Sie den Scan erneut aus.",
	SPFUnavailable:   "SPF konnte nicht geprüft werden: Die DNS-Abfrage ist fehlgeschlagen.",
	CouldNotCheck:    "nicht prüfbar (Abfrage fehlgeschlagen)",
	ResponsibleUse: `VERANTWORTUNGSVOLLE NUTZUNG: Scannen Sie nur Domains, die Ihnen gehören oder
für deren Prüfung Sie autorisiert sind.
Für jeden gefundenen Host löst ZoneAudit DNS-Einträge auf und führt, wenn der
Host eine öffentliche Adresse hat, einen TLS-Handshake und eine leichte
HTTP(S)-Anfrage aus (einfaches HTTP nur, wenn HTTPS nicht antwortet, mit
höchstens 2 Weiterleitungen innerhalb der gescannten Domain). Außerdem stellt
es eine RDAP-Anfrage zum Ablaufdatum der Domain. Es scannt keine Ports und
versucht keinen Zugriff. Alle Anfragen sind durch -rate begrenzt und jede
einzelne durch -timeout.`,
	HelpUsage:          "Verwendung: zoneaudit -d <Domain> [-c n] [-rate n] [-timeout Dauer] [-json] [-lang en|fr|de]",
	HelpOptions:        "Optionen:",
	HelpDefault:        "(Standard: %s)",
	FlagDomain:         "Zu scannende `Domain` (z. B. example.com)",
	FlagConcurrency:    "Anzahl paralleler Worker, `n` von 1 bis %d",
	FlagRate:           "Höchstzahl an Anfragen pro Sekunde über DNS, TLS, HTTP und RDAP, `n` von 1 bis %d",
	FlagTimeout:        "Zeitlimit je Anfrage, eine `Dauer` von %s bis %s",
	FlagJSON:           "Ergebnisse als JSON ausgeben (Schemaversion %s)",
	FlagLang:           "Sprache als `Code` (en, fr oder de); Standard ist die Umgebungsvariable LANG",
	FlagVersion:        "Version anzeigen und beenden",
	Discovery:          "Erkennung",
	Interrupted:        "abgebrochen: Die Ergebnisse sind unvollständig",
	ErrUnsupportedLang: "Fehler: nicht unterstützte Sprache %q (verwenden Sie en, fr oder de)",
	ErrInvalidDomain:   "Fehler: %q ist kein gültiger Domainname",
	ErrConcurrency:     "Fehler: -c muss zwischen 1 und %d liegen",
	ErrRate:            "Fehler: -rate muss zwischen 1 und %d Anfragen pro Sekunde liegen",
	ErrTimeout:         "Fehler: -timeout muss zwischen %s und %s liegen",
	ErrRootResolution:  "[KRITISCH] Die Auflösung der Stammdomain „%s“ ist fehlgeschlagen. Prüfen Sie die Verbindung oder die Schreibweise.",
	ErrGeneric:         "Fehler: %v",
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
