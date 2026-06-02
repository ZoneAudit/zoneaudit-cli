package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
		os.Exit(1)
	}

	// Setup translations
	if *langOverride != "" {
		os.Setenv("LANG", *langOverride)
	}
	T := i18n.GetStrings()

	if !*asJSON {
		fmt.Printf(T.StartingScan+"\n", *domain)
		fmt.Printf(T.WorkerInfo+"\n", *concurrency, len(scanner.CommonSubdomains))
		fmt.Printf(T.LangHint + "\n\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	results := scanner.RunScan(ctx, *domain, *concurrency)
	duration := time.Since(start)

	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(results)
		return
	}

	// Terminal Output
	for _, res := range results.Active {
		fmt.Printf("[+] %-25s | ", res.Subdomain)
		for _, rec := range res.Records {
			fmt.Printf("%s: %-15s ", rec.Type, rec.Value[0])
		}
		if res.SSL != nil {
			status := T.SSLOK
			if res.SSL.IsCritical {
				status = T.SSLExpiring
			}
			fmt.Printf(T.SSLInfo, status, res.SSL.DaysLeft)
		}
		fmt.Println()
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
