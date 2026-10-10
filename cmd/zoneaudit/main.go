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

	"github.com/ZoneAudit/zoneaudit-cli/internal/i18n"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
)

// responsibleUse is printed at the top of --help and when no domain is given.
const responsibleUse = `RESPONSIBLE USE: only scan domains you own or are authorised to assess.
For each host it finds, ZoneAudit resolves DNS records, makes one TLS
handshake and one light HTTP(S) request (plain HTTP only if HTTPS does not
answer, following at most 2 redirects). It also makes one RDAP query for the
domain's expiry date. It does not scan ports or attempt access. All requests
are capped by -rate and each one is bounded by -timeout.`

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

func newFlagSet(stderr io.Writer, o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("zoneaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.domain, "d", "", "Target domain to scan (e.g. example.com)")
	fs.IntVar(&o.concurrency, "c", scanner.DefaultConcurrency, fmt.Sprintf("Number of concurrent workers (1 to %d)", scanner.MaxConcurrency))
	fs.IntVar(&o.rate, "rate", scanner.DefaultRate, fmt.Sprintf("Maximum requests per second across DNS, TLS, HTTP and RDAP (1 to %d)", scanner.MaxRate))
	fs.DurationVar(&o.timeout, "timeout", scanner.DefaultTimeout, fmt.Sprintf("Timeout for each request (%s to %s)", scanner.MinTimeout, scanner.MaxTimeout))
	fs.BoolVar(&o.asJSON, "json", false, "Output results as JSON (schema version "+scanner.SchemaVersion+")")
	fs.StringVar(&o.lang, "lang", "", "Language override (en, fr, de); defaults to the LANG environment variable")
	fs.BoolVar(&o.version, "version", false, "Print the version and exit")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "ZoneAudit Community Edition v%s\n\n", scanner.Version)
		fmt.Fprintf(out, "%s\n\n", responsibleUse)
		fmt.Fprintf(out, "Usage: zoneaudit -d <domain> [-c N] [-rate N] [-timeout D] [-json] [-lang en|fr|de]\n\nOptions:\n")
		fs.PrintDefaults()
	}
	return fs
}

// run is the testable body of main. cfg supplies injectable resolvers and
// clients; the flags fill in the limits.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, cfg scanner.Config) int {
	var o options
	fs := newFlagSet(stderr, &o)
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
	if o.lang != "" && !i18n.Supported(o.lang) {
		fmt.Fprintf(stderr, "error: unsupported language %q (use en, fr or de)\n", o.lang)
		return 2
	}
	domain, err := scanner.NormaliseDomain(o.domain)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	// Zero would mean "use the default" to scanner.New, so reject it here.
	if o.concurrency < 1 || o.rate < 1 || o.timeout <= 0 {
		fmt.Fprintln(stderr, "error: -c, -rate and -timeout must be greater than zero")
		return 2
	}
	cfg.Concurrency, cfg.Rate, cfg.Timeout = o.concurrency, o.rate, o.timeout
	s, err := scanner.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	now := s.Config().Now

	T := i18n.GetStrings()
	if o.lang != "" {
		T = i18n.For(o.lang)
	}

	// Fail fast if the root domain does not resolve.
	if !s.RootResolves(ctx, domain) {
		fmt.Fprintf(stderr, "[CRITICAL] Root domain resolution failed for '%s'. Check connectivity or spelling.\n", domain)
		return 1
	}

	start := now()
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
				fmt.Fprintf(stderr, "\r[*] Discovery: [%-20s] %3.0f%% ", strings.Repeat("=", int(pct/5)), pct)
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
		fmt.Fprintln(stderr, "interrupted: results are incomplete")
		code = exitInterrupted
	}

	if o.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return code
	}
	renderText(stdout, T, results, duration)
	return code
}

// exitInterrupted is returned when the scan was cancelled (Ctrl+C).
const exitInterrupted = 130

// renderText writes the terminal report. Its last line is the request-access line.
func renderText(w io.Writer, T i18n.LanguageStrings, results scanner.ScanResults, duration time.Duration) {
	for _, res := range results.Active {
		var line strings.Builder
		fmt.Fprintf(&line, "[+] %-25s | ", res.Subdomain)

		if len(res.Records) > 0 && len(res.Records[0].Value) > 0 {
			rec := res.Records[0]
			fmt.Fprintf(&line, "%s: %-15s ", rec.Type, rec.Value[0])
		}

		if res.HTTP != nil {
			meta := fmt.Sprintf("HTTP:%d", res.HTTP.Status)
			if res.HTTP.Server != "" {
				meta += " (" + res.HTTP.Server + ")"
			}
			if res.HTTP.Title != "" {
				meta += " [" + res.HTTP.Title + "]"
			}
			fmt.Fprintf(&line, "| %s ", meta)
		}

		for i, rec := range res.Records {
			if i == 0 || rec.Type == scanner.RecordAddress || len(rec.Value) == 0 {
				continue
			}
			if rec.Type == scanner.RecordUnchecked {
				fmt.Fprintf(&line, "| %s: %s ", rec.Value[0], T.CouldNotCheck)
				continue
			}
			fmt.Fprintf(&line, "| %s: %v ", rec.Type, rec.Value[0])
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
			dmarc += " (p=" + es.DMARCPolicy + ")"
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
	fmt.Fprintf(w, T.ScanComplete+"\n", results.Domain)
	fmt.Fprintf(w, T.DurationInfo+"\n", duration.Round(time.Millisecond), len(results.Active))
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintln(w, T.RequestAccess)
}
