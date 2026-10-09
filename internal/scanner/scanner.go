package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Defaults for polite scanning. Every outbound request (each DNS lookup,
// TLS handshake, HTTP request and the RDAP query) waits for the shared rate
// limiter and is bounded by the per-request timeout.
const (
	DefaultConcurrency = 10
	DefaultRate        = 25 // requests per second, across all request types
	MaxRate            = 100
	DefaultTimeout     = 5 * time.Second
	MinTimeout         = 1 * time.Second
	MaxTimeout         = 60 * time.Second
	MaxConcurrency     = 50

	// DefaultRDAPBaseURL is the RDAP bootstrap redirector used for domain expiry.
	DefaultRDAPBaseURL = "https://rdap.org/domain/"
)

// Resolver is the subset of *net.Resolver the scanner uses. Tests inject a
// fake backed by recorded answers so no network is needed.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// CertFetcher returns the certificate chain presented by host on port 443.
type CertFetcher interface {
	FetchCertificates(ctx context.Context, host string) ([]*x509.Certificate, error)
}

// Config controls a Scanner. Zero values fall back to the defaults above.
type Config struct {
	Concurrency int
	Rate        int           // maximum requests per second
	Timeout     time.Duration // per request

	Resolver    Resolver
	HTTPClient  *http.Client // used for banners and RDAP; its Transport is rate limited
	CertFetcher CertFetcher
	RDAPBaseURL string
	Wordlist    []string
	Now         func() time.Time
}

// Scanner runs the read-only checks against one domain.
type Scanner struct {
	cfg      Config
	limiter  *Limiter
	resolver Resolver
	http     *http.Client // banners: accepts invalid certificates so they can be reported
	rdap     *http.Client // RDAP: verifies certificates
	certs    CertFetcher
	now      func() time.Time
}

// UserAgent identifies the CLI to the web servers it contacts.
func UserAgent() string {
	return "zoneaudit-cli/" + Version + " (+https://github.com/ZoneAudit/zoneaudit-cli)"
}

// New builds a Scanner, validating the polite-scanning limits.
func New(cfg Config) (*Scanner, error) {
	if cfg.Concurrency == 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.Rate == 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > MaxConcurrency {
		return nil, fmt.Errorf("concurrency must be between 1 and %d", MaxConcurrency)
	}
	if cfg.Rate < 1 || cfg.Rate > MaxRate {
		return nil, fmt.Errorf("rate must be between 1 and %d requests per second", MaxRate)
	}
	if cfg.Timeout < MinTimeout || cfg.Timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout must be between %s and %s", MinTimeout, MaxTimeout)
	}
	if cfg.RDAPBaseURL == "" {
		cfg.RDAPBaseURL = DefaultRDAPBaseURL
	}
	if cfg.Wordlist == nil {
		cfg.Wordlist = CommonSubdomains
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	s := &Scanner{cfg: cfg, limiter: NewLimiter(cfg.Rate), now: cfg.Now}

	base := cfg.Resolver
	if base == nil {
		base = net.DefaultResolver
	}
	s.resolver = &limitedResolver{base: base, limiter: s.limiter, timeout: cfg.Timeout}

	var client http.Client
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	} else {
		client = http.Client{
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // read banners even when the certificate is invalid
				TLSHandshakeTimeout: cfg.Timeout,
				DisableKeepAlives:   true,
			},
		}
	}
	if client.Timeout == 0 || client.Timeout > cfg.Timeout {
		client.Timeout = cfg.Timeout
	}
	baseRT := client.Transport
	if baseRT == nil {
		baseRT = http.DefaultTransport
	}
	client.Transport = &limitedTransport{base: baseRT, limiter: s.limiter}
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	s.http = &client

	if cfg.HTTPClient != nil {
		s.rdap = s.http
	} else {
		s.rdap = &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &limitedTransport{base: http.DefaultTransport, limiter: s.limiter},
		}
	}

	certs := cfg.CertFetcher
	if certs == nil {
		certs = tlsCertFetcher{timeout: cfg.Timeout}
	}
	s.certs = &limitedCertFetcher{base: certs, limiter: s.limiter, timeout: cfg.Timeout}
	return s, nil
}

// Config returns the effective configuration after defaults were applied.
func (s *Scanner) Config() Config { return s.cfg }

// Wordlist returns the hostnames tried under the domain.
func (s *Scanner) Wordlist() []string { return s.cfg.Wordlist }

// RootResolves reports whether the domain has address or NS records. A
// mail-only domain may have no A record, so NS records also count.
func (s *Scanner) RootResolves(ctx context.Context, domain string) bool {
	if ips, err := s.resolver.LookupHost(ctx, domain); err == nil && len(ips) > 0 {
		return true
	}
	ns, err := s.resolver.LookupNS(ctx, domain)
	return err == nil && len(ns) > 0
}

var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// ErrInvalidDomain is returned by NormaliseDomain for input that is not a hostname.
var ErrInvalidDomain = errors.New("not a valid domain name")

// NormaliseDomain lower-cases the input and strips a URL scheme, path,
// port and trailing dot, then checks that what is left is a hostname.
func NormaliseDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	d = strings.TrimSuffix(d, ".")
	if len(d) > 253 || !hostnameRe.MatchString(d) {
		return "", fmt.Errorf("%q: %w", in, ErrInvalidDomain)
	}
	return d, nil
}

// daysUntil returns whole days from now until t (negative once t has passed).
func daysUntil(now, t time.Time) int {
	return int(t.Sub(now).Hours() / 24)
}
