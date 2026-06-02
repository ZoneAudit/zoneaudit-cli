package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// Record represents a simplified DNS or service record for the CLI output.
type Record struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

// Result represents the scanning outcome for a specific subdomain.
type Result struct {
	Subdomain string   `json:"subdomain"`
	Records   []Record `json:"records,omitempty"`
	IsActive  bool     `json:"is_active"`
	SSL       *SSLInfo `json:"ssl,omitempty"`
}

// SSLInfo holds basic certificate details.
type SSLInfo struct {
	Issuer     string    `json:"issuer"`
	Expiry     time.Time `json:"expiry"`
	DaysLeft   int       `json:"days_left"`
	IsCritical bool      `json:"is_critical"`
}

// CheckSubdomain performs DNS lookups and active service probing.
func CheckSubdomain(ctx context.Context, fqdn string) Result {
	res := Result{
		Subdomain: fqdn,
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{}

	// Check A/AAAA records
	ips, err := resolver.LookupHost(lookupCtx, fqdn)
	if err == nil && len(ips) > 0 {
		res.IsActive = true
		res.Records = append(res.Records, Record{
			Type:  "A/AAAA",
			Value: ips,
		})

		// If IP exists, try a quick SSL check on 443
		if ssl := checkSSL(fqdn); ssl != nil {
			res.SSL = ssl
		}
	}

	// Check CNAME (spotting dangling assets)
	cname, err := resolver.LookupCNAME(lookupCtx, fqdn)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != strings.TrimSuffix(fqdn, ".") {
		res.IsActive = true
		res.Records = append(res.Records, Record{
			Type:  "CNAME",
			Value: []string{cname},
		})
	}

	return res
}

func checkSSL(fqdn string) *SSLInfo {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fqdn+":443", &tls.Config{
		InsecureSkipVerify: true, // We want to see the cert even if it's expired/invalid
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	leaf := certs[0]
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

	return &SSLInfo{
		Issuer:     leaf.Issuer.CommonName,
		Expiry:     leaf.NotAfter,
		DaysLeft:   daysLeft,
		IsCritical: daysLeft < 30,
	}
}
