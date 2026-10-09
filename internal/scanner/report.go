package scanner

import "time"

// SchemaVersion is the version of the JSON report format. Within major
// version 1, fields are never removed, renamed or given a new meaning; new
// optional fields may be added, which raises the minor number. See
// docs/json-output.md.
const SchemaVersion = "1.0"

// ToolName is the name reported in the JSON output.
const ToolName = "zoneaudit-cli"

// Tool identifies the program that produced a report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Settings records the polite-scanning limits a report was produced with.
type Settings struct {
	Concurrency    int     `json:"concurrency"`
	RatePerSecond  int     `json:"rate_per_second"`
	TimeoutSeconds float64 `json:"timeout_seconds"`
}

// Record represents a simplified DNS record, or a RISK flag, for one host.
type Record struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

// Result represents the findings for one host.
type Result struct {
	Subdomain string    `json:"subdomain"`
	Records   []Record  `json:"records,omitempty"`
	IsActive  bool      `json:"is_active"`
	SSL       *SSLInfo  `json:"ssl,omitempty"`
	HTTP      *HTTPInfo `json:"http,omitempty"`
}

// ScanResults is the report written by -json.
type ScanResults struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          Tool           `json:"tool"`
	Domain        string         `json:"domain"`
	GeneratedAt   time.Time      `json:"generated_at"`
	DurationMS    int64          `json:"duration_ms"`
	Settings      Settings       `json:"settings"`
	Requests      int64          `json:"requests"`
	DomainExpiry  *DomainExpiry  `json:"domain_expiry"`
	EmailSecurity *EmailSecurity `json:"email_security"`
	Active        []Result       `json:"active"`
	Total         int            `json:"total_scanned"`

	// Version duplicates Tool.Version and is kept for v0.2 consumers.
	Version string `json:"version"`
}
