package scanner

import (
	"context"
	"sort"
	"sync"
)

// CommonSubdomains is the fixed list of common infrastructure hostnames the
// Community Edition tries under the domain. It does not use certificate logs
// or any other discovery source.
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

// RunScan checks the root domain, then each wordlist name under it, using
// the configured number of workers. Every outbound request goes through the
// shared rate limiter. Results are sorted: the root domain first, then by name.
// progress, if not nil, receives 1 for each wordlist name checked.
func (s *Scanner) RunScan(ctx context.Context, domain string, progress chan<- int) ScanResults {
	results := ScanResults{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: ToolName, Version: Version},
		Domain:        domain,
		Version:       Version,
		Settings: Settings{
			Concurrency:    s.cfg.Concurrency,
			RatePerSecond:  s.cfg.Rate,
			TimeoutSeconds: s.cfg.Timeout.Seconds(),
		},
		Active: []Result{},
		Total:  len(s.cfg.Wordlist),
	}

	rootRes := s.CheckSubdomain(ctx, domain)
	if rootRes.IsActive {
		results.Active = append(results.Active, rootRes)
	}

	tasks := make(chan string)
	resChan := make(chan Result, len(s.cfg.Wordlist))
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range tasks {
				if ctx.Err() != nil {
					continue // drain without making requests
				}
				res := s.CheckSubdomain(ctx, sub+"."+domain)
				if res.IsActive {
					resChan <- res
				}
				if progress != nil {
					progress <- 1
				}
			}
		}()
	}

	go func() {
		defer close(tasks)
		for _, sub := range s.cfg.Wordlist {
			select {
			case tasks <- sub:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	close(resChan)

	var found []Result
	for res := range resChan {
		found = append(found, res)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Subdomain < found[j].Subdomain })
	results.Active = append(results.Active, found...)
	return results
}
