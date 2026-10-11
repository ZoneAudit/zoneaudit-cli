package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// RDAPResponse represents the subset of the RDAP JSON structure the CLI reads.
type RDAPResponse struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

// DomainExpiry holds expiration data.
type DomainExpiry struct {
	ExpiryDate time.Time `json:"expiry_date"`
	DaysLeft   int       `json:"days_left"`
	IsCritical bool      `json:"is_critical"`
}

// ErrNoExpiry is returned when the RDAP record has no expiration event.
var ErrNoExpiry = errors.New("expiration event not found in RDAP response")

// maxRDAPBody bounds how much of an RDAP response is read.
const maxRDAPBody = 1 << 20

// GetDomainExpiry queries RDAP (one request) for the domain's expiry date.
func (s *Scanner) GetDomainExpiry(ctx context.Context, domain string) (*DomainExpiry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.RDAPBaseURL+url.PathEscape(domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := s.rdap.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP query failed with status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRDAPBody))
	if err != nil {
		return nil, err
	}
	return ParseRDAPExpiry(body, s.now())
}

// ParseRDAPExpiry finds the expiration event in an RDAP domain response.
func ParseRDAPExpiry(body []byte, now time.Time) (*DomainExpiry, error) {
	var rdap RDAPResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		return nil, err
	}
	for _, event := range rdap.Events {
		if event.Action != "expiration" {
			continue
		}
		expiry, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			expiry, err = time.Parse("2006-01-02T15:04:05", event.Date)
		}
		if err != nil {
			continue
		}
		days := daysUntil(now, expiry)
		return &DomainExpiry{
			ExpiryDate: expiry.UTC(),
			DaysLeft:   days,
			IsCritical: days < CriticalDays,
		}, nil
	}
	return nil, ErrNoExpiry
}
