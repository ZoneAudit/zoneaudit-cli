package scanner_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

func TestCertificateExpiryAndIssuer(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()

	res := f.s.CheckSubdomain(ctx, "example.com")
	if res.SSL == nil {
		t.Fatal("no certificate details")
	}
	if res.SSL.Issuer != "DigiCert Global G3 TLS ECC SHA384 2020 CA1" {
		t.Errorf("issuer = %q", res.SSL.Issuer)
	}
	if res.SSL.DaysLeft != 60 || res.SSL.IsCritical {
		t.Errorf("days left = %d critical = %v, want 60 and false", res.SSL.DaysLeft, res.SSL.IsCritical)
	}
	if res.SSL.Expiry.Location() != time.UTC {
		t.Error("expiry should be reported in UTC")
	}

	res = f.s.CheckSubdomain(ctx, "www.example.com")
	if res.SSL == nil {
		t.Fatal("no certificate details for www")
	}
	if res.SSL.Issuer != "Let's Encrypt" {
		t.Errorf("issuer without a common name should fall back to the organisation, got %q", res.SSL.Issuer)
	}
	if res.SSL.DaysLeft != 10 || !res.SSL.IsCritical {
		t.Errorf("days left = %d critical = %v, want 10 and true", res.SSL.DaysLeft, res.SSL.IsCritical)
	}
}

func TestCertificateExpired(t *testing.T) {
	f := newFixture(t, func(c *scanner.Config) {
		c.CertFetcher = &scannertest.Certs{Chains: map[string][]*x509.Certificate{
			"example.com": {scannertest.Certificate("example.com", pkix.Name{CommonName: "Old CA"}, scannertest.Now.AddDate(0, 0, -5))},
		}}
	})
	res := f.s.CheckSubdomain(context.Background(), "example.com")
	if res.SSL == nil || res.SSL.DaysLeft != -5 || !res.SSL.IsCritical {
		t.Errorf("expired certificate: %+v, want -5 days and critical", res.SSL)
	}
}

func TestNoCertificateWhenHandshakeFails(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "shop.example.com")
	if res.SSL != nil {
		t.Errorf("expected no certificate details, got %+v", res.SSL)
	}
}

func TestHTTPBanner(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "example.com")
	if res.HTTP == nil {
		t.Fatal("no HTTP details")
	}
	want := scanner.HTTPInfo{Status: 200, Server: "ECS (nyd/D10E)", Title: "Example Domain & Co"}
	if *res.HTTP != want {
		t.Errorf("got %+v, want %+v", *res.HTTP, want)
	}
	for _, ua := range f.transport.UserAgents() {
		if !strings.HasPrefix(ua, "zoneaudit-cli/") {
			t.Errorf("request sent with User-Agent %q", ua)
		}
	}
}

func TestHTTPBannerFollowsRedirect(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "www.example.com")
	if res.HTTP == nil || res.HTTP.Status != 200 || res.HTTP.Title != "Example Domain & Co" {
		t.Errorf("redirect not followed: %+v", res.HTTP)
	}
}

func TestHTTPBannerFallsBackToHTTP(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "shop.example.com")
	if res.HTTP == nil {
		t.Fatal("no HTTP details")
	}
	if res.HTTP.Status != 403 || res.HTTP.Server != "AmazonS3" || res.HTTP.Title != "" {
		t.Errorf("got %+v", *res.HTTP)
	}
	var schemes []string
	for _, r := range f.transport.Requests {
		schemes = append(schemes, r.URL.Scheme)
	}
	if strings.Join(schemes, ",") != "https,http" {
		t.Errorf("requests = %v, want one HTTPS attempt then one HTTP", schemes)
	}
}

func TestHTTPRedirectLoopIsCapped(t *testing.T) {
	f := newFixture(t, nil)
	loop := scannertest.RawResponse(302, map[string]string{"Location": "https://example.com/"}, "")
	f.transport.Routes["https://example.com"] = loop
	f.transport.Routes["https://example.com/"] = loop
	res := f.s.CheckSubdomain(context.Background(), "example.com")
	if res.HTTP == nil || res.HTTP.Status != 302 {
		t.Fatalf("got %+v, want the last 302 response", res.HTTP)
	}
	if n := len(f.transport.Requests); n != 3 {
		t.Errorf("made %d requests, want 3 (the first plus 2 redirects)", n)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<title>Hello</title>":                        "Hello",
		"<TITLE lang=\"en\">  Multi\n line  </TITLE>": "Multi line",
		"<title>Caf&eacute; &lt;3</title>":            "Café <3",
		"<html><body>no title</body></html>":          "",
		"<title>first</title><title>second</title>":   "first",
	}
	for in, want := range cases {
		if got := scanner.ExtractTitle([]byte(in)); got != want {
			t.Errorf("ExtractTitle(%q) = %q, want %q", in, got, want)
		}
	}
}
