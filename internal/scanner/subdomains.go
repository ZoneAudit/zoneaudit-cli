package scanner

import (
	"context"
	"fmt"
	"sync"
)

// CommonSubdomains is a small, tactical list for the light version.
// In the full DeepScan agent, this is driven by massive wordlists and heuristics.
var CommonSubdomains = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "vpn", "m", "shop", "ftp", "dev", "staging", "api", "test",
	"portal", "admin", "support", "autis", "autodiscover", "exchange",
	"cpanel", "whm", "webdisk", "secure", "direct", "svn", "git", "pop",
	"pop3", "imap", "stats", "demo", "monitor", "beta", "alpha", "cms",
	"jenkins", "docker", "kube", "aws", "azure", "gcp", "staff", "internal",
}

// ScanResults contains the summary of a scan run.
type ScanResults struct {
	Domain  string   `json:"domain"`
	Version string   `json:"version"`
	Active  []Result `json:"active"`
	Total   int      `json:"total_scanned"`
}

// RunScan executes a concurrent scan against a domain using the common wordlist.
func RunScan(ctx context.Context, domain string, concurrency int) ScanResults {
	results := ScanResults{
		Domain:  domain,
		Version: Version,
		Active:  []Result{},
	}

	// Always check the root domain first
	rootRes := CheckSubdomain(ctx, domain)
	if rootRes.IsActive {
		results.Active = append(results.Active, rootRes)
	}

	tasks := make(chan string, len(CommonSubdomains))
	resChan := make(chan Result, len(CommonSubdomains))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					fqdn := fmt.Sprintf("%s.%s", sub, domain)
					res := CheckSubdomain(ctx, fqdn)
					if res.IsActive {
						resChan <- res
					}
				}
			}
		}()
	}

	// Feed tasks
	for _, sub := range CommonSubdomains {
		tasks <- sub
	}
	close(tasks)

	// Wait for workers in a separate routine
	go func() {
		wg.Wait()
		close(resChan)
	}()

	// Collect results
	for res := range resChan {
		results.Active = append(results.Active, res)
	}

	results.Total = len(CommonSubdomains)
	return results
}
