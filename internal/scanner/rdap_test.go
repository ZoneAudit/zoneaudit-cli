package scanner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

func TestDomainExpiryFromRecordedRDAP(t *testing.T) {
	f := newFixture(t, nil)
	exp, err := f.s.GetDomainExpiry(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2027, 8, 13, 4, 0, 0, 0, time.UTC)
	if !exp.ExpiryDate.Equal(want) {
		t.Errorf("expiry = %s, want %s", exp.ExpiryDate, want)
	}
	if exp.DaysLeft != 307 || exp.IsCritical {
		t.Errorf("days left = %d critical = %v, want 307 and false", exp.DaysLeft, exp.IsCritical)
	}
	if got := f.transport.Requests[0].Header.Get("Accept"); got == "" {
		t.Error("RDAP request should send an Accept header")
	}
}

func TestDomainExpiryHTTPError(t *testing.T) {
	f := newFixture(t, nil)
	f.transport.Routes["https://rdap.test/domain/example.com"] = scannertest.RawResponse(404, nil, "")
	if _, err := f.s.GetDomainExpiry(context.Background(), "example.com"); err == nil {
		t.Error("a 404 should be an error")
	}
}

func TestParseRDAPExpiry(t *testing.T) {
	now := scannertest.Now
	exp, err := scanner.ParseRDAPExpiry([]byte(`{"events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2026-10-20T12:00:00+01:00"}]}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if exp.DaysLeft != 10 || !exp.IsCritical {
		t.Errorf("days left = %d critical = %v, want 10 and true", exp.DaysLeft, exp.IsCritical)
	}
	if exp.ExpiryDate.Location() != time.UTC {
		t.Error("expiry should be in UTC")
	}

	exp, err = scanner.ParseRDAPExpiry([]byte(`{"events":[{"eventAction":"expiration","eventDate":"2027-01-01T00:00:00"}]}`), now)
	if err != nil || exp.ExpiryDate.Year() != 2027 {
		t.Errorf("date without a zone: %+v, %v", exp, err)
	}

	if _, err := scanner.ParseRDAPExpiry([]byte(`{"events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"}]}`), now); !errors.Is(err, scanner.ErrNoExpiry) {
		t.Errorf("missing expiration: err = %v, want ErrNoExpiry", err)
	}
	if _, err := scanner.ParseRDAPExpiry([]byte(`not json`), now); err == nil {
		t.Error("invalid JSON should be an error")
	}
}
