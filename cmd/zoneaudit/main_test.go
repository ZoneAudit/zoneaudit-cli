package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/i18n"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

func fixtureConfig() scanner.Config {
	tr := &scannertest.Transport{Routes: map[string][]byte{
		"https://rdap.test/domain/example.com": scannertest.RawResponse(200, nil, string(scannertest.Fixture("rdap/example.com.json"))),
	}}
	return scanner.Config{
		Resolver:    scannertest.LoadResolver("example.com"),
		HTTPClient:  &http.Client{Transport: tr},
		CertFetcher: scannertest.DefaultCerts(),
		RDAPBaseURL: "https://rdap.test/domain/",
		Wordlist:    []string{"www", "mail", "shop", "old", "vpn"},
		Now:         func() time.Time { return scannertest.Now },
	}
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut, fixtureConfig())
	return code, out.String(), errOut.String()
}

func TestTextReport(t *testing.T) {
	code, out, _ := runCLI(t, "-d", "example.com", "-rate", "100", "-lang", "en")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"Starting ZoneAudit scan for: example.com",
		"Domain Expiring in 307 days (2027-08-13)",
		"[+] example.com",
		"HTTP:200 (ECS (nyd/D10E)) [Example Domain & Co]",
		"| SSL: OK (60 days left)",
		"| SSL: EXPIRING SOON (10 days left)",
		"old.example.com",
		"| RISK: DANGLING-CNAME",
		"| CNAME: shop.provider.example.net",
		"Email security: SPF present | DMARC present (p=none)",
		"[!] DMARC policy is 'none' (monitoring only)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output is missing %q\n%s", want, out)
		}
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last := lines[len(lines)-1]
	if last != i18n.For("en").RequestAccess {
		t.Errorf("last line = %q, want the request-access line", last)
	}
}

func TestRequestAccessLine(t *testing.T) {
	for _, lang := range []string{"en", "fr", "de"} {
		line := i18n.For(lang).RequestAccess
		if !strings.Contains(line, "https://zoneaudit.com/") {
			t.Errorf("%s: request-access line has no zoneaudit.com link: %q", lang, line)
		}
		lower := strings.ToLower(line)
		for _, banned := range []string{"free", "gratuit", "kostenlos", "gratis"} {
			if strings.Contains(lower, banned) {
				t.Errorf("%s: request-access line must not say %q", lang, banned)
			}
		}
		if len(line) > 110 {
			t.Errorf("%s: request-access line is %d characters; keep it short", lang, len(line))
		}
		_, out, _ := runCLI(t, "-d", "example.com", "-rate", "100", "-lang", lang)
		if !strings.HasSuffix(strings.TrimRight(out, "\n"), line) {
			t.Errorf("%s: text output does not end with the request-access line", lang)
		}
	}
}

func TestJSONReport(t *testing.T) {
	code, out, _ := runCLI(t, "-d", "https://Example.com/", "-json", "-rate", "100", "-timeout", "3s", "-c", "4")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var rep scanner.ScanResults
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if rep.SchemaVersion != scanner.SchemaVersion || rep.Domain != "example.com" {
		t.Errorf("schema %q domain %q", rep.SchemaVersion, rep.Domain)
	}
	if rep.Settings != (scanner.Settings{Concurrency: 4, RatePerSecond: 100, TimeoutSeconds: 3}) {
		t.Errorf("settings = %+v", rep.Settings)
	}
	if rep.DomainExpiry == nil || rep.EmailSecurity == nil || !rep.EmailSecurity.DMARCWeak {
		t.Errorf("expiry or email security missing: %+v %+v", rep.DomainExpiry, rep.EmailSecurity)
	}
	if rep.Requests == 0 {
		t.Error("request count should be reported")
	}
	if strings.Contains(out, "zoneaudit.com") {
		t.Error("JSON output must not contain the request-access line")
	}
}

func TestHelpShowsResponsibleUse(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		code, out, errOut := runCLI(t, arg)
		if code != 0 {
			t.Errorf("%s: exit %d, want 0", arg, code)
		}
		help := out + errOut
		if !strings.Contains(help, "RESPONSIBLE USE: only scan domains you own or are authorised to assess.") {
			t.Errorf("%s: help does not lead with the responsible-use notice:\n%s", arg, help)
		}
		if idx := strings.Index(help, "RESPONSIBLE USE"); idx > 100 {
			t.Errorf("%s: responsible-use notice should be near the top of the help", arg)
		}
		for _, flag := range []string{"-rate", "-timeout", "-json", "-lang"} {
			if !strings.Contains(help, flag) {
				t.Errorf("%s: help does not document %s", arg, flag)
			}
		}
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},                                    // no domain
		{"-d", "example.com", "-rate", "0"},   // zero is not allowed
		{"-d", "example.com", "-rate", "500"}, // above the cap
		{"-d", "example.com", "-timeout", "100ms"},
		{"-d", "example.com", "-lang", "es"},
		{"-d", "not a domain"},
		{"-unknown"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestRootDomainMustResolve(t *testing.T) {
	code, out, errOut := runCLI(t, "-d", "nonexistent.example")
	if code != 1 || !strings.Contains(errOut, "Root domain resolution failed") || out != "" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestVersionFlag(t *testing.T) {
	code, out, _ := runCLI(t, "-version")
	if code != 0 || strings.TrimSpace(out) != "zoneaudit "+scanner.Version {
		t.Errorf("exit %d, output %q", code, out)
	}
}
