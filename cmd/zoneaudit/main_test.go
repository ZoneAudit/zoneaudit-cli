package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
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
	t.Setenv("LANG", "en_GB.UTF-8")
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
	t.Setenv("LANG", "en_GB.UTF-8")
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

// cancellingResolver cancels the scan on its first TXT lookup, which comes
// after the root domain check, to simulate Ctrl+C part-way through.
type cancellingResolver struct {
	*scannertest.Resolver
	cancel context.CancelFunc
}

func (r cancellingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.cancel()
	return r.Resolver.LookupTXT(ctx, name)
}

func TestInterruptedScanExits130WithPartialReport(t *testing.T) {
	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := fixtureConfig()
			cfg.Resolver = cancellingResolver{Resolver: scannertest.LoadResolver("example.com"), cancel: cancel}
			args := []string{"-d", "example.com", "-rate", "100", "-lang", "en"}
			if mode == "json" {
				args = append(args, "-json")
			}
			var out, errOut bytes.Buffer
			code := run(ctx, args, &out, &errOut, cfg)
			if code != 130 {
				t.Errorf("exit %d, want 130", code)
			}
			if !strings.Contains(errOut.String(), "interrupted") {
				t.Errorf("stderr should say the scan was interrupted: %q", errOut.String())
			}
			if mode == "json" {
				var rep scanner.ScanResults
				if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Domain != "example.com" {
					t.Errorf("partial JSON report not written: %v\n%s", err, out.String())
				}
			} else if !strings.HasSuffix(strings.TrimRight(out.String(), "\n"), i18n.For("en").RequestAccess) {
				t.Errorf("partial text report not written:\n%s", out.String())
			}
		})
	}
}

func TestLookupFailuresAreNotReportedAsMissing(t *testing.T) {
	cfg := fixtureConfig()
	r := scannertest.LoadResolver("example.com")
	r.Errors = map[string]error{
		"txt _dmarc.example.com":                 scannertest.ServFail("_dmarc.example.com"),
		"host example-old.herokudns.example.org": scannertest.Timeout("example-old.herokudns.example.org"),
	}
	cfg.Resolver = r
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-d", "example.com", "-rate", "100", "-lang", "en"}, &out, &errOut, cfg); code != 0 {
		t.Fatalf("exit %d", code)
	}
	text := out.String()
	for _, want := range []string{
		"DMARC could not check (lookup failed)",
		"[?] DMARC could not be checked",
		"| DANGLING-CNAME: could not check (lookup failed)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"No DMARC record", "RISK: DANGLING-CNAME"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a failed lookup must not produce %q:\n%s", unwanted, text)
		}
	}
}

func TestHelpFollowsLang(t *testing.T) {
	t.Setenv("LANG", "en_GB.UTF-8")
	want := map[string]string{
		"en": "RESPONSIBLE USE:",
		"fr": "UTILISATION RESPONSABLE :",
		"de": "VERANTWORTUNGSVOLLE NUTZUNG:",
	}
	for lang, heading := range want {
		notice := i18n.For(lang).ResponsibleUse
		if !strings.HasPrefix(notice, heading) || !strings.Contains(notice, "-rate") || !strings.Contains(notice, "-timeout") {
			t.Errorf("%s: notice is incomplete: %q", lang, notice)
		}
		for _, args := range [][]string{
			{"-lang", lang, "-h"},
			{"-h", "-lang", lang}, // -lang after -h still applies
			{"--lang=" + lang, "--help"},
		} {
			code, out, errOut := runCLI(t, args...)
			help := out + errOut
			if code != 0 || !strings.Contains(help, notice) {
				t.Errorf("%v: exit %d, help does not contain the %s notice:\n%s", args, code, lang, help)
			}
			for _, want := range localisedHelp(lang) {
				if !strings.Contains(help, want) {
					t.Errorf("%v: help is missing %q:\n%s", args, want, help)
				}
			}
			if lang != "en" {
				for _, english := range []string{"Usage:", "(default ", "Number of concurrent workers", "Print the version and exit"} {
					if strings.Contains(help, english) {
						t.Errorf("%v: %s help still contains English %q", args, lang, english)
					}
				}
			}
		}
	}
	// With no -lang, LANG chooses.
	t.Setenv("LANG", "de_DE.UTF-8")
	if _, _, errOut := runCLI(t, "-h"); !strings.Contains(errOut, i18n.For("de").ResponsibleUse) {
		t.Errorf("LANG=de_DE: help is not in German:\n%s", errOut)
	}
}

// localisedHelp returns the headings, option descriptions and default
// notes the help must show in lang.
func localisedHelp(lang string) []string {
	T := i18n.For(lang)
	unquote := func(s string) string { return strings.ReplaceAll(s, "`", "") }
	return []string{
		T.HelpUsage,
		T.HelpOptions,
		unquote(T.FlagDomain),
		unquote(fmt.Sprintf(T.FlagConcurrency, scanner.MaxConcurrency)) + " " + fmt.Sprintf(T.HelpDefault, "10"),
		unquote(fmt.Sprintf(T.FlagRate, scanner.MaxRate)) + " " + fmt.Sprintf(T.HelpDefault, "25"),
		unquote(fmt.Sprintf(T.FlagTimeout, scanner.MinTimeout, scanner.MaxTimeout)) + " " + fmt.Sprintf(T.HelpDefault, "5s"),
		fmt.Sprintf(T.FlagJSON, scanner.SchemaVersion),
		unquote(T.FlagLang),
		T.FlagVersion,
	}
}

// hostileResolver adds TXT records carrying terminal escape sequences.
func hostileResolver() *scannertest.Resolver {
	r := scannertest.LoadResolver("example.com")
	// A TXT-only host, so the TXT value is the first record printed.
	r.TXT["vpn.example.com"] = []string{"\x1b]0;owned\x07\x1b[2Jfirst"}
	// A host whose TXT value is printed after its CNAME.
	r.TXT["old.example.com"] = []string{"later\x1b[31m\u202e"}
	return r
}

func TestTextReportEscapesControlSequences(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Resolver = hostileResolver()
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-d", "example.com", "-rate", "100", "-lang", "en"}, &out, &errOut, cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	text := out.String()
	if strings.ContainsAny(text, "\x1b\x07\u202e") {
		t.Errorf("text report contains raw control characters:\n%q", text)
	}
	for _, want := range []string{
		`TXT: \x1b]0;owned\x07\x1b[2Jfirst`,
		`| TXT: later\x1b[31m\u202e`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text report is missing the escaped value %q:\n%s", want, text)
		}
	}
}

func TestJSONReportKeepsRawValues(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Resolver = hostileResolver()
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-d", "example.com", "-rate", "100", "-json"}, &out, &errOut, cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var rep scanner.ScanResults
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rep.Active {
		for _, rec := range r.Records {
			for _, v := range rec.Value {
				if v == "\x1b]0;owned\x07\x1b[2Jfirst" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("JSON report should keep the DNS value unchanged")
	}
}

// rootHook runs fn on the first lookup of the root domain.
type rootHook struct {
	*scannertest.Resolver
	once sync.Once
	fn   func()
}

func (r *rootHook) LookupHost(ctx context.Context, host string) ([]string, error) {
	if host == "example.com" {
		r.once.Do(r.fn)
	}
	return r.Resolver.LookupHost(ctx, host)
}

func TestInterruptDuringRootCheckExits130(t *testing.T) {
	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := fixtureConfig()
			cfg.Resolver = &rootHook{Resolver: scannertest.LoadResolver("example.com"), fn: cancel}
			args := []string{"-d", "example.com", "-rate", "100", "-lang", "en"}
			if mode == "json" {
				args = append(args, "-json")
			}
			var out, errOut bytes.Buffer
			code := run(ctx, args, &out, &errOut, cfg)
			if code != 130 {
				t.Errorf("exit %d, want 130", code)
			}
			if strings.Contains(errOut.String(), "Root domain resolution failed") || !strings.Contains(errOut.String(), "interrupted") {
				t.Errorf("stderr should report an interruption, not a resolution failure: %q", errOut.String())
			}
			if mode == "json" {
				var rep scanner.ScanResults
				if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Domain != "example.com" || rep.Total != 0 {
					t.Errorf("partial JSON report: %v %+v", err, rep)
				}
			} else if !strings.HasSuffix(strings.TrimRight(out.String(), "\n"), i18n.For("en").RequestAccess) {
				t.Errorf("partial text report not written:\n%s", out.String())
			}
		})
	}
}

func TestDurationIncludesRootCheck(t *testing.T) {
	var mu sync.Mutex
	now := scannertest.Now
	cfg := fixtureConfig()
	cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	// The root check takes 10 seconds on the fake clock.
	cfg.Resolver = &rootHook{Resolver: scannertest.LoadResolver("example.com"), fn: func() {
		mu.Lock()
		now = now.Add(10 * time.Second)
		mu.Unlock()
	}}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-d", "example.com", "-rate", "100", "-json"}, &out, &errOut, cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var rep scanner.ScanResults
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.DurationMS < 10000 {
		t.Errorf("duration_ms = %d, want at least 10000 (the root check is part of the scan)", rep.DurationMS)
	}
	if !rep.GeneratedAt.Equal(scannertest.Now) {
		t.Errorf("generated_at = %s, want the time before the root check", rep.GeneratedAt)
	}
}

func TestSafe(t *testing.T) {
	cases := map[string]string{
		"plain text, café":  "plain text, café",
		"\x1b[2J":           `\x1b[2J`,
		"bell\x07":          `bell\x07`,
		"\u009b31m":         `\x9b31m`,
		"rtl\u202eoverride": `rtl\u202eoverride`,
		"bad\xffutf8":       `bad\xffutf8`,
		"tab\tand\nnewline": `tab\x09and\x0anewline`,
	}
	for in, want := range cases {
		if got := safe(in); got != want {
			t.Errorf("safe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryStringIsTranslated(t *testing.T) {
	for _, lang := range []string{"en", "fr", "de"} {
		v := reflect.ValueOf(i18n.For(lang))
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).String() == "" {
				t.Errorf("%s: %s is empty", lang, v.Type().Field(i).Name)
			}
		}
	}
}

func TestMessagesFollowLang(t *testing.T) {
	t.Setenv("LANG", "en_GB.UTF-8")
	for _, lang := range []string{"en", "fr", "de"} {
		T := i18n.For(lang)
		cases := []struct {
			args []string
			want string
		}{
			{[]string{"-d", "not a domain"}, fmt.Sprintf(T.ErrInvalidDomain, "not a domain")},
			{[]string{"-d", "example.com", "-c", "0"}, fmt.Sprintf(T.ErrConcurrency, scanner.MaxConcurrency)},
			{[]string{"-d", "example.com", "-rate", "500"}, fmt.Sprintf(T.ErrRate, scanner.MaxRate)},
			{[]string{"-d", "example.com", "-timeout", "100ms"}, fmt.Sprintf(T.ErrTimeout, scanner.MinTimeout, scanner.MaxTimeout)},
			{[]string{"-d", "nonexistent.example"}, fmt.Sprintf(T.ErrRootResolution, "nonexistent.example")},
		}
		for _, c := range cases {
			// -lang after the bad value still applies.
			args := append(append([]string{}, c.args...), "-lang", lang)
			code, _, errOut := runCLI(t, args...)
			if code == 0 || strings.TrimSpace(errOut) != c.want {
				t.Errorf("%v: exit %d, stderr %q, want %q", args, code, errOut, c.want)
			}
		}
	}
	// An unsupported -lang is reported in the LANG language.
	t.Setenv("LANG", "fr_FR.UTF-8")
	if _, _, errOut := runCLI(t, "-d", "example.com", "-lang", "es"); strings.TrimSpace(errOut) != fmt.Sprintf(i18n.For("fr").ErrUnsupportedLang, "es") {
		t.Errorf("unsupported language: stderr %q", errOut)
	}
}

func TestInterruptedMessageFollowsLang(t *testing.T) {
	for _, lang := range []string{"en", "fr", "de"} {
		ctx, cancel := context.WithCancel(context.Background())
		cfg := fixtureConfig()
		cfg.Resolver = cancellingResolver{Resolver: scannertest.LoadResolver("example.com"), cancel: cancel}
		var out, errOut bytes.Buffer
		code := run(ctx, []string{"-d", "example.com", "-rate", "100", "-lang", lang}, &out, &errOut, cfg)
		cancel()
		if code != 130 || !strings.Contains(errOut.String(), i18n.For(lang).Interrupted) {
			t.Errorf("%s: exit %d, stderr %q", lang, code, errOut.String())
		}
		if lang != "en" && strings.Contains(errOut.String(), "interrupted:") {
			t.Errorf("%s: the interruption message is still in English", lang)
		}
	}
}
