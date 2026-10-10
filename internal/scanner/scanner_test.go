package scanner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
)

func TestNormaliseDomain(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"example.com", "example.com", true},
		{"  Example.COM.  ", "example.com", true},
		{"https://www.example.com/path?q=1", "www.example.com", true},
		{"example.com:8443", "example.com", true},
		{"sub-domain.example.co.uk", "sub-domain.example.co.uk", true},
		{"", "", false},
		{"localhost", "", false},
		{"-bad.example.com", "", false},
		{"exa mple.com", "", false},
		{"example.com; rm -rf /", "", false},
		{"192.0.2.1", "", false},
	}
	for _, c := range cases {
		got, err := scanner.NormaliseDomain(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("NormaliseDomain(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		if !c.ok && !errors.Is(err, scanner.ErrInvalidDomain) {
			t.Errorf("NormaliseDomain(%q) = %q, %v; want ErrInvalidDomain", c.in, got, err)
		}
	}
}

func TestNewDefaultsAndLimits(t *testing.T) {
	s, err := scanner.New(scanner.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Config()
	if cfg.Rate != scanner.DefaultRate || cfg.Timeout != scanner.DefaultTimeout || cfg.Concurrency != scanner.DefaultConcurrency {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if len(s.Wordlist()) != len(scanner.CommonSubdomains) {
		t.Errorf("wordlist = %d names, want %d", len(s.Wordlist()), len(scanner.CommonSubdomains))
	}

	bad := []scanner.Config{
		{Rate: scanner.MaxRate + 1},
		{Rate: -1},
		{Timeout: 500 * time.Millisecond},
		{Timeout: 2 * time.Minute},
		{Concurrency: -1},
		{Concurrency: scanner.MaxConcurrency + 1},
	}
	for _, cfg := range bad {
		if _, err := scanner.New(cfg); err == nil {
			t.Errorf("New(%+v) accepted an out-of-range limit", cfg)
		}
	}
}

func TestWordlistHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range scanner.CommonSubdomains {
		if seen[w] {
			t.Errorf("duplicate wordlist entry %q", w)
		}
		seen[w] = true
	}
	if len(scanner.CommonSubdomains) != 143 {
		t.Errorf("wordlist has %d names; the README says 143", len(scanner.CommonSubdomains))
	}
}

func TestRootResolves(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	if !f.s.RootResolves(ctx, "example.com") {
		t.Error("example.com should resolve")
	}
	if !f.s.RootResolves(ctx, "mailonly.example") {
		t.Error("a domain with only NS records should count as resolving")
	}
	if f.s.RootResolves(ctx, "nonexistent.example") {
		t.Error("nonexistent.example should not resolve")
	}
}
