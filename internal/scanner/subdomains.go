package scanner

import (
	"context"
	"fmt"
	"sync"
)

// CommonSubdomains is a tactical list for the light version focusing on high-value infrastructure.
// In the full DeepScan™ enterprise engine, this is driven by massive wordlists, passive discovery, and heuristics.
var CommonSubdomains = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
	"smtp", "vpn", "m", "shop", "ftp", "dev", "staging", "api", "test",
	"portal", "admin", "support", "autis", "autodiscover", "exchange",
	"cpanel", "whm", "webdisk", "secure", "direct", "svn", "git", "pop",
	"pop3", "imap", "stats", "demo", "monitor", "beta", "alpha", "cms",
	"jenkins", "docker", "kube", "aws", "azure", "gcp", "staff", "internal",
	"cloud", "cdn", "status", "files", "download", "vpn2", "owa", "mail2",
	"app", "apps", "dev2", "api2", "db", "database", "sql", "mysql", "git2",
	"gitlab", "confluence", "jira", "wiki", "docs", "help", "chat", "mattermost",
	"slack", "zoom", "teams", "meet", "billing", "invoice", "payment", "pay",
	"store", "shop2", "cart", "account", "login", "auth", "sso", "identity",
	"mobile", "ios", "android", "assets", "static", "images", "img", "cdn2",
	"proxy", "lb", "balancer", "gateway", "border", "fw", "edge", "gw",
	"backup", "storage", "archive", "data", "reporting", "dash", "dashboard",
	"prometheus", "grafana", "logs", "elastic", "kibana", "search", "private",
	"legacy", "old", "new", "temp", "tmp", "sandbox", "lab", "lab2", "security",
	"vault", "secret", "vpn-gate", "connect", "access", "talent", "hr", "corp",
	"office", "remote2", "citrix", "rds", "vdi", "guest", "wifi", "network",
}

// ScanResults contains the summary of a scan run.
type ScanResults struct {
	Domain        string         `json:"domain"`
	Version       string         `json:"version"`
	DomainExpiry  *DomainExpiry  `json:"domain_expiry,omitempty"`
	EmailSecurity *EmailSecurity `json:"email_security,omitempty"`
	Active        []Result       `json:"active"`
	Total         int            `json:"total_scanned"`
}

// RunScan executes a concurrent scan against a domain using the common wordlist.
func RunScan(ctx context.Context, domain string, concurrency int, progress chan<- int) ScanResults {
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
					if progress != nil {
						progress <- 1
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
