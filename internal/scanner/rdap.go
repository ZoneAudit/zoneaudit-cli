package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// RDAPResponse represents a subset of the RDAP JSON structure
type RDAPResponse struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

// DomainExpiry holds expiration data
type DomainExpiry struct {
	ExpiryDate time.Time `json:"expiry_date"`
	DaysLeft   int       `json:"days_left"`
	IsCritical bool      `json:"is_critical"`
}

// GetDomainExpiry queries RDAP for domain expiration information
func GetDomainExpiry(domain string) (*DomainExpiry, error) {
	// RDAP bootstrap for .com, .net, etc. using rdap.org as a redirector
	url := fmt.Sprintf("https://rdap.org/domain/%s", domain)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP query failed with status: %d", resp.StatusCode)
	}

	var rdap RDAPResponse
	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return nil, err
	}

	for _, event := range rdap.Events {
		if event.Action == "expiration" {
			expiry, err := time.Parse(time.RFC3339, event.Date)
			if err != nil {
				// Try alternative common format if RFC3339 fails
				expiry, err = time.Parse("2006-01-02T15:04:05Z", event.Date)
			}

			if err == nil {
				daysLeft := int(time.Until(expiry).Hours() / 24)
				return &DomainExpiry{
					ExpiryDate: expiry,
					DaysLeft:   daysLeft,
					IsCritical: daysLeft < 30,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("expiration event not found in RDAP response")
}
