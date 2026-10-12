package scanner_test

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

// Addresses are checked when connecting, not here; see dial_internal_test.go.
func TestRedirectOutsideScopeIsNotFollowed(t *testing.T) {
	targets := []string{
		"https://attacker.example.net/",            // another domain
		"https://notexample.com/",                  // suffix, not a subdomain
		"http://localhost/",                        // loopback name
		"http://127.0.0.1/",                        // loopback address
		"http://169.254.169.254/latest/meta-data/", // cloud metadata (link-local)
		"http://[::1]/",                            // IPv6 loopback
		"https://example.com:8443/",                // another port
		"ftp://example.com/",                       // another scheme
		"https://example.com:80/",                  // http's port with https
		"http://example.com:443/",                  // https's port with http
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			f := newFixture(t, nil)
			f.transport.Routes["https://example.com"] = scannertest.RawResponse(302, map[string]string{"Location": target}, "")
			ctx := scanner.WithScope(context.Background(), "example.com")
			res := f.s.CheckSubdomain(ctx, "example.com")
			if res.HTTP == nil || res.HTTP.Status != 302 {
				t.Fatalf("got %+v, want the 302 response reported, not followed", res.HTTP)
			}
			if n := len(f.transport.Requests); n != 1 {
				t.Errorf("made %d HTTP requests, want 1 (the redirect must not be followed)", n)
			}
		})
	}
}

func TestCallerRedirectPolicyCannotExceedTheCap(t *testing.T) {
	calls := 0
	f := newFixture(t, func(c *scanner.Config) {
		c.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { calls++; return nil }
	})
	loop := scannertest.RawResponse(302, map[string]string{"Location": "https://example.com/"}, "")
	f.transport.Routes["https://example.com"] = loop
	f.transport.Routes["https://example.com/"] = loop
	res := f.s.CheckSubdomain(scanner.WithScope(context.Background(), "example.com"), "example.com")
	if res.HTTP == nil || res.HTTP.Status != 302 {
		t.Fatalf("got %+v, want the last 302 response", res.HTTP)
	}
	if n := len(f.transport.Requests); n != 3 {
		t.Errorf("made %d requests, want 3 (the first plus 2 redirects) even with a caller policy", n)
	}
	if calls != 2 {
		t.Errorf("caller policy consulted %d times, want 2", calls)
	}
}

func TestRedirectWithinScopeIsFollowed(t *testing.T) {
	f := newFixture(t, nil)
	f.resolver.Host["app.example.com"] = []string{"23.192.228.85"}
	f.transport.Routes["https://example.com"] = scannertest.RawResponse(302, map[string]string{"Location": "https://app.example.com/"}, "")
	f.transport.Routes["https://app.example.com/"] = scannertest.RawResponse(200, nil, "<title>App</title>")
	ctx := scanner.WithScope(context.Background(), "example.com")
	res := f.s.CheckSubdomain(ctx, "example.com")
	if res.HTTP == nil || res.HTTP.Status != 200 || res.HTTP.Title != "App" {
		t.Errorf("got %+v, want the subdomain's page", res.HTTP)
	}
}

func TestRunScanScopesRedirectsToTheDomain(t *testing.T) {
	// www.example.com redirects to example.com, which is inside the scan.
	f := newFixture(t, func(c *scanner.Config) { c.Wordlist = []string{"www"} })
	res := f.s.RunScan(context.Background(), "example.com", nil)
	for _, r := range res.Active {
		if r.Subdomain == "www.example.com" && (r.HTTP == nil || r.HTTP.Status != 200) {
			t.Errorf("in-scope redirect not followed during a scan: %+v", r.HTTP)
		}
	}
}

func TestInScope(t *testing.T) {
	cases := map[[2]string]bool{
		{"example.com", "example.com"}:      true,
		{"a.b.example.com.", "example.com"}: true,
		{"WWW.Example.COM", "example.com"}:  true,
		{"notexample.com", "example.com"}:   false,
		{"example.com.evil", "example.com"}: false,
		{"example.com", ""}:                 false,
	}
	for in, want := range cases {
		if got := scanner.InScope(in[0], in[1]); got != want {
			t.Errorf("InScope(%q, %q) = %v, want %v", in[0], in[1], got, want)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"23.192.228.80":            true,
		"2600:1406::1":             true,
		"127.0.0.1":                false,
		"10.1.2.3":                 false,
		"172.16.0.1":               false,
		"192.168.1.1":              false,
		"169.254.169.254":          false,
		"100.64.0.1":               false,
		"0.0.0.0":                  false,
		"::1":                      false,
		"fe80::1":                  false,
		"fd00::1":                  false,
		"224.0.0.1":                false,
		"192.0.2.10":               false, // TEST-NET-1
		"198.51.100.7":             false, // TEST-NET-2
		"203.0.113.9":              false, // TEST-NET-3
		"198.18.0.1":               false, // benchmarking
		"192.0.0.8":                false, // IETF protocol assignments
		"240.0.0.1":                false, // reserved
		"255.255.255.255":          false,
		"::ffff:127.0.0.1":         false, // IPv4-mapped loopback
		"::ffff:23.192.228.80":     true,
		"::127.0.0.1":              false, // IPv4-compatible
		"2001:db8::1":              false, // documentation
		"3fff::1":                  false, // documentation
		"2001:2::1":                false, // benchmarking
		"2001::1":                  false, // Teredo
		"2002:7f00:1::1":           false, // 6to4 embedding 127.0.0.1
		"64:ff9b:1::1":             false, // local-use translation
		"100::1":                   false, // discard-only
		"fc00::1":                  false,
		"8.8.8.8":                  true,
		"2a00:1450:4009:81f::200e": true,
	}
	for in, want := range cases {
		if got := scanner.IsPublicIP(net.ParseIP(in)); got != want {
			t.Errorf("IsPublicIP(%s) = %v, want %v", in, got, want)
		}
	}
}
