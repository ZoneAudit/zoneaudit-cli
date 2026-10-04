package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/i18n"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
)

func main() {
	domain := flag.String("d", "", "Target domain to scan (e.g., example.com)")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	asJSON := flag.Bool("json", false, "Output results in JSON format")
	langOverride := flag.String("lang", "", "Language override (en, fr, de)")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Usage: zoneaudit -d <domain> [-c <concurrency>] [-json] [-lang <en|fr|de>]")
		flag.PrintDefaults()
		fmt.Println("\nOnly scan domains you own or are authorised to assess. ZoneAudit resolves DNS and makes")
		fmt.Println("one light HTTP(S) request and TLS handshake to each discovered host.")
		os.Exit(1)
	}

	// Fail fast: Root domain resolution check
	// A domain may have no A record (e.g. mail-only), so NS records also count as resolving.
	_, hostErr := net.LookupHost(*domain)
	_, nsErr := net.LookupNS(*domain)
	if hostErr != nil && nsErr != nil {
		fmt.Printf("[CRITICAL] Root domain resolution failed for '%s'. Check connectivity or spelling.\n", *domain)
		os.Exit(1)
	}

	// Setup translations
	if *langOverride != "" {
		os.Setenv("LANG", *langOverride)
	}
	T := i18n.GetStrings()

	var domainExpiry *scanner.DomainExpiry
	if !*asJSON {
		fmt.Printf(T.StartingScan+"\n", *domain)
		fmt.Printf(T.WorkerInfo+"\n", *concurrency, len(scanner.CommonSubdomains))
		fmt.Printf(T.LangHint + "\n\n")

		// Check Domain Expiry (Pre-scan telemetry)
		if expiry, err := scanner.GetDomainExpiry(*domain); err == nil {
			domainExpiry = expiry
			status := fmt.Sprintf(T.DomainExpiry, expiry.DaysLeft, expiry.ExpiryDate.Format("2006-01-02"))
			if expiry.IsCritical {
				fmt.Printf("[!] %s\n\n", T.DomainCritical)
			}
			fmt.Printf("[*] %s\n\n", status)
		}
	} else {
		// Silent fetch for JSON output
		domainExpiry, _ = scanner.GetDomainExpiry(*domain)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	var results scanner.ScanResults
	if *asJSON {
		results = scanner.RunScan(ctx, *domain, *concurrency, nil)
	} else {
		progress := make(chan int, len(scanner.CommonSubdomains))
		total := len(scanner.CommonSubdomains)
		done := make(chan bool)

		go func() {
			count := 0
			for p := range progress {
				count += p
				pct := float64(count) / float64(total) * 100
				fmt.Printf("\r[*] Discovery: [%-20s] %3.0f%% ", strings.Repeat("=", int(pct/5)), pct)
			}
			fmt.Print("\r" + strings.Repeat(" ", 60) + "\r") // Clear progress line
			done <- true
		}()

		results = scanner.RunScan(ctx, *domain, *concurrency, progress)
		close(progress)
		<-done
	}
	duration := time.Since(start)

	results.DomainExpiry = domainExpiry
	es := scanner.CheckEmailSecurity(ctx, *domain)
	results.EmailSecurity = &es

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(results)
		return
	}

	// Terminal Output
	for _, res := range results.Active {
		fmt.Printf("[+] %-25s | ", res.Subdomain)

		// DNS summary
		if len(res.Records) > 0 {
			rec := res.Records[0]
			fmt.Printf("%s: %-15s ", rec.Type, rec.Value[0])
		}

		// HTTP metadata
		if res.HTTP != nil {
			meta := fmt.Sprintf("HTTP:%d", res.HTTP.Status)
			if res.HTTP.Server != "" {
				meta += " (" + res.HTTP.Server + ")"
			}
			if res.HTTP.Title != "" {
				meta += " [" + res.HTTP.Title + "]"
			}
			fmt.Printf("| %s ", meta)
		}

		// Additional discovery records (MX, TXT, etc.)
		for _, rec := range res.Records {
			if rec.Type == "A/AAAA" || rec.Type == "CNAME" {
				continue
			}
			fmt.Printf("| %s: %v ", rec.Type, rec.Value[0])
		}

		// SSL summary
		if res.SSL != nil {
			status := T.SSLOK
			if res.SSL.IsCritical {
				status = T.SSLExpiring
			}
			fmt.Printf(T.SSLInfo, status, res.SSL.DaysLeft)
		}
		fmt.Println()
	}

	// Email security summary for the root domain: SPF and DMARC reported separately
	spf, dmarc := T.Missing, T.Missing
	if es.SPF {
		spf = T.Present
	}
	if es.DMARC {
		dmarc = T.Present
		if es.DMARCPolicy != "" {
			dmarc += " (p=" + es.DMARCPolicy + ")"
		}
	}
	fmt.Printf("\n[*] "+T.EmailSecurity+"\n", spf, dmarc)
	if !es.DMARC {
		fmt.Printf("[!] %s\n", T.DMARCMissing)
	} else if es.DMARCPolicy == "none" {
		fmt.Printf("[!] %s\n", T.DMARCNone)
	}

	renderBillboard(T, *domain, len(results.Active), duration)
}

func renderBillboard(T i18n.LanguageStrings, domain string, activeCount int, duration time.Duration) {
	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Printf("ZoneAudit Community Edition v%s\n", scanner.Version)
	fmt.Printf(T.ScanComplete+"\n", domain)
	fmt.Printf(T.DurationInfo+"\n", duration.Round(time.Millisecond), activeCount)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println(T.BillboardTip)
	fmt.Println(T.BillboardTest)
	fmt.Println(T.BillboardAccess)
	fmt.Println()
}
