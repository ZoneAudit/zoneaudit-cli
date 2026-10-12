// Command zoneaudit is the ZoneAudit Community Edition CLI: a read-only
// snapshot of a domain's public DNS, certificates, web banners, domain
// expiry and email security.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ZoneAudit/zoneaudit-cli/internal/i18n"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, scanner.Config{}))
}

type options struct {
	domain      string
	concurrency int
	rate        int
	timeout     time.Duration
	asJSON      bool
	lang        string
	version     bool
}

// stringsFor returns the terminal strings for lang, or for the LANG
// environment variable when lang is empty or not supported.
func stringsFor(lang string) i18n.LanguageStrings {
	if lang != "" && i18n.Supported(lang) {
		return i18n.For(lang)
	}
	return i18n.GetStrings()
}

// langArg finds the -lang value in args before they are parsed, so that
// --help, which the flag package handles during parsing, is printed in the
// requested language wherever -lang appears.
func langArg(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "lang" {
			continue
		}
		if hasValue {
			return value
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func newFlagSet(stderr io.Writer, o *options, T i18n.LanguageStrings) *flag.FlagSet {
	fs := flag.NewFlagSet("zoneaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.domain, "d", "", T.FlagDomain)
	fs.IntVar(&o.concurrency, "c", scanner.DefaultConcurrency, fmt.Sprintf(T.FlagConcurrency, scanner.MaxConcurrency))
	fs.IntVar(&o.rate, "rate", scanner.DefaultRate, fmt.Sprintf(T.FlagRate, scanner.MaxRate))
	fs.DurationVar(&o.timeout, "timeout", scanner.DefaultTimeout, fmt.Sprintf(T.FlagTimeout, scanner.MinTimeout, scanner.MaxTimeout))
	fs.BoolVar(&o.asJSON, "json", false, fmt.Sprintf(T.FlagJSON, scanner.SchemaVersion))
	fs.StringVar(&o.lang, "lang", "", T.FlagLang)
	fs.BoolVar(&o.version, "version", false, T.FlagVersion)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "ZoneAudit Community Edition v%s\n\n", scanner.Version)
		fmt.Fprintf(out, "%s\n\n", T.ResponsibleUse)
		fmt.Fprintf(out, "%s\n\n%s\n", T.HelpUsage, T.HelpOptions)
		printDefaults(out, fs, T)
	}
	return fs
}

// printDefaults lists the flags like flag.PrintDefaults, but with the
// "(default ...)" note taken from the language strings, so the whole help
// follows -lang.
func printDefaults(out io.Writer, fs *flag.FlagSet, T i18n.LanguageStrings) {
	fs.VisitAll(func(f *flag.Flag) {
		placeholder, usage := flag.UnquoteUsage(f)
		line := "  -" + f.Name
		if placeholder != "" {
			line += " " + placeholder
		}
		fmt.Fprintf(out, "%s\n    \t%s", line, usage)
		if f.DefValue != "" && f.DefValue != "false" {
			fmt.Fprintf(out, " "+T.HelpDefault, f.DefValue)
		}
		fmt.Fprintln(out)
	})
}

// run is the testable body of main. cfg supplies injectable resolvers and
// clients; the flags fill in the limits.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, cfg scanner.Config) int {
	var o options
	fs := newFlagSet(stderr, &o, stringsFor(langArg(args)))
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if o.version {
		fmt.Fprintf(stdout, "zoneaudit %s\n", scanner.Version)
		return 0
	}
	if o.domain == "" {
		fs.Usage()
		return 2
	}
	// Choose the language first, so every message below follows -lang.
	T := stringsFor(o.lang)
	if o.lang != "" && !i18n.Supported(o.lang) {
		fmt.Fprintf(stderr, T.ErrUnsupportedLang+"\n", o.lang)
		return 2
	}
	domain, err := scanner.NormaliseDomain(o.domain)
	if err != nil {
		fmt.Fprintf(stderr, T.ErrInvalidDomain+"\n", o.domain)
		return 2
	}

	// The limits are checked here, not left to scanner.New, so the
	// messages are localised. Zero would mean "use the default" to
	// scanner.New, so it is rejected too.
	switch {
	case o.concurrency < 1 || o.concurrency > scanner.MaxConcurrency:
		fmt.Fprintf(stderr, T.ErrConcurrency+"\n", scanner.MaxConcurrency)
		return 2
	case o.rate < 1 || o.rate > scanner.MaxRate:
		fmt.Fprintf(stderr, T.ErrRate+"\n", scanner.MaxRate)
		return 2
	case o.timeout < scanner.MinTimeout || o.timeout > scanner.MaxTimeout:
		fmt.Fprintf(stderr, T.ErrTimeout+"\n", scanner.MinTimeout, scanner.MaxTimeout)
		return 2
	}
	cfg.Concurrency, cfg.Rate, cfg.Timeout = o.concurrency, o.rate, o.timeout
	s, err := scanner.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, T.ErrGeneric+"\n", err)
		return 2
	}
	now := s.Config().Now

	// The clock starts before the root check, whose lookups are counted in
	// the report's requests.
	start := now()

	// Fail fast if the root domain does not resolve. If the check failed
	// because the scan was interrupted (Ctrl+C), carry on instead: every
	// later step stops at once without sending requests, and the partial
	// report is written with exit status 130.
	if !s.RootResolves(ctx, domain) && !errors.Is(ctx.Err(), context.Canceled) {
		fmt.Fprintf(stderr, T.ErrRootResolution+"\n", domain)
		return 1
	}
	if !o.asJSON {
		fmt.Fprintf(stdout, T.StartingScan+"\n", domain)
		fmt.Fprintf(stdout, T.WorkerInfo+"\n", s.Config().Concurrency, len(s.Wordlist()))
		fmt.Fprintf(stdout, "%s\n\n", T.LangHint)
	}

	expiry, _ := s.GetDomainExpiry(ctx, domain)
	if expiry != nil && !o.asJSON {
		if expiry.IsCritical {
			fmt.Fprintf(stdout, "[!] %s\n", T.DomainCritical)
		}
		fmt.Fprintf(stdout, "[*] "+T.DomainExpiry+"\n\n", expiry.DaysLeft, expiry.ExpiryDate.Format("2006-01-02"))
	}

	var progress chan int
	done := make(chan struct{})
	if o.asJSON {
		close(done)
	} else {
		total := len(s.Wordlist())
		progress = make(chan int, total)
		go func() {
			defer close(done)
			count := 0
			for p := range progress {
				count += p
				pct := float64(count) / float64(total) * 100
				fmt.Fprintf(stderr, "\r[*] %s: [%-20s] %3.0f%% ", T.Discovery, strings.Repeat("=", int(pct/5)), pct)
			}
			fmt.Fprint(stderr, "\r"+strings.Repeat(" ", 60)+"\r")
		}()
	}

	results := s.RunScan(ctx, domain, progress)
	if progress != nil {
		close(progress)
	}
	<-done

	es := s.CheckEmailSecurity(ctx, domain)
	results.DomainExpiry = expiry
	results.EmailSecurity = &es
	results.GeneratedAt = start.UTC().Truncate(time.Second)
	duration := now().Sub(start)
	results.DurationMS = duration.Milliseconds()
	results.Requests = s.RequestCount()

	// An interrupted scan still writes the partial report, then exits with
	// 130 (the conventional status for SIGINT) so callers can tell.
	code := 0
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, T.Interrupted)
		code = exitInterrupted
	}

	if o.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(stderr, T.ErrGeneric+"\n", err)
			return 1
		}
		return code
	}
	renderText(stdout, T, results, duration)
	return code
}

// exitInterrupted is returned when the scan was cancelled (Ctrl+C).
const exitInterrupted = 130

// safe makes a value from DNS or a web server safe to print on a terminal:
// control characters (including ESC, so no terminal escape sequences),
// Unicode format characters such as bidirectional overrides, and invalid
// UTF-8 are shown as escapes instead of being written raw. It is used for
// every scanned value in the text report; the JSON report keeps the data
// unchanged.
func safe(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "\\x%02x", v[i])
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			if r < 0x100 {
				fmt.Fprintf(&b, "\\x%02x", r)
			} else {
				fmt.Fprintf(&b, "\\u%04x", r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// renderText writes the terminal report. Its last line is the request-access line.
func renderText(w io.Writer, T i18n.LanguageStrings, results scanner.ScanResults, duration time.Duration) {
	for _, res := range results.Active {
		var line strings.Builder
		fmt.Fprintf(&line, "[+] %-25s | ", safe(res.Subdomain))

		if len(res.Records) > 0 && len(res.Records[0].Value) > 0 {
			rec := res.Records[0]
			fmt.Fprintf(&line, "%s: %-15s ", safe(rec.Type), safe(rec.Value[0]))
		}

		if res.HTTP != nil {
			meta := fmt.Sprintf("HTTP:%d", res.HTTP.Status)
			if res.HTTP.Server != "" {
				meta += " (" + safe(res.HTTP.Server) + ")"
			}
			if res.HTTP.Title != "" {
				meta += " [" + safe(res.HTTP.Title) + "]"
			}
			fmt.Fprintf(&line, "| %s ", meta)
		}

		for i, rec := range res.Records {
			if i == 0 || rec.Type == scanner.RecordAddress || len(rec.Value) == 0 {
				continue
			}
			if rec.Type == scanner.RecordUnchecked {
				fmt.Fprintf(&line, "| %s: %s ", safe(rec.Value[0]), T.CouldNotCheck)
				continue
			}
			fmt.Fprintf(&line, "| %s: %s ", safe(rec.Type), safe(rec.Value[0]))
		}

		if res.SSL != nil {
			status := T.SSLOK
			if res.SSL.IsCritical {
				status = T.SSLExpiring
			}
			fmt.Fprintf(&line, T.SSLInfo, status, res.SSL.DaysLeft)
		}
		fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
	}

	if es := results.EmailSecurity; es != nil {
		label := func(status string) string {
			switch status {
			case scanner.StatusPresent:
				return T.Present
			case scanner.StatusUnavailable:
				return T.Unavailable
			}
			return T.Missing
		}
		spf, dmarc := label(es.SPFStatus), label(es.DMARCStatus)
		if es.DMARC && es.DMARCPolicy != "" {
			dmarc += " (p=" + safe(es.DMARCPolicy) + ")"
		}
		fmt.Fprintf(w, "\n[*] "+T.EmailSecurity+"\n", spf, dmarc)
		switch {
		case es.DMARCStatus == scanner.StatusUnavailable:
			fmt.Fprintf(w, "[?] %s\n", T.DMARCUnavailable)
		case !es.DMARC:
			fmt.Fprintf(w, "[!] %s\n", T.DMARCMissing)
		case es.DMARCWeak:
			fmt.Fprintf(w, "[!] %s\n", T.DMARCNone)
		}
		if es.SPFStatus == scanner.StatusUnavailable {
			fmt.Fprintf(w, "[?] %s\n", T.SPFUnavailable)
		}
	}

	fmt.Fprintln(w, "\n"+strings.Repeat("-", 60))
	fmt.Fprintf(w, "ZoneAudit Community Edition v%s\n", scanner.Version)
	fmt.Fprintf(w, T.ScanComplete+"\n", safe(results.Domain))
	fmt.Fprintf(w, T.DurationInfo+"\n", duration.Round(time.Millisecond), len(results.Active))
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintln(w, T.RequestAccess)
}
