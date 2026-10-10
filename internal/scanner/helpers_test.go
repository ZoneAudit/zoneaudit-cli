package scanner_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

type fixture struct {
	s         *scanner.Scanner
	resolver  *scannertest.Resolver
	transport *scannertest.Transport
	certs     *scannertest.Certs
}

// newFixture builds a scanner over the example.com fixtures with the
// maximum rate, so tests stay fast while still going through the limiter.
func newFixture(t *testing.T, mutate func(*scanner.Config)) fixture {
	t.Helper()
	f := fixture{
		resolver:  scannertest.LoadResolver("example.com"),
		transport: &scannertest.Transport{Routes: map[string][]byte{}},
		certs:     scannertest.DefaultCerts(),
	}
	f.transport.Routes["https://rdap.test/domain/example.com"] = scannertest.RawResponse(200,
		map[string]string{"Content-Type": "application/rdap+json"}, string(scannertest.Fixture("rdap/example.com.json")))
	cfg := scanner.Config{
		Rate:        scanner.MaxRate,
		Timeout:     2 * time.Second,
		Resolver:    f.resolver,
		HTTPClient:  &http.Client{Transport: f.transport},
		CertFetcher: f.certs,
		RDAPBaseURL: "https://rdap.test/domain/",
		Wordlist:    []string{"www", "mail", "shop", "old", "vpn"},
		Now:         func() time.Time { return scannertest.Now },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	return f
}

func recordOf(res scanner.Result, typ string) *scanner.Record {
	for i := range res.Records {
		if res.Records[i].Type == typ {
			return &res.Records[i]
		}
	}
	return nil
}
