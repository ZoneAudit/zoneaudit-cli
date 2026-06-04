package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
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
	Subdomain string    `json:"subdomain"`
	Records   []Record  `json:"records,omitempty"`
	IsActive  bool      `json:"is_active"`
	SSL       *SSLInfo  `json:"ssl,omitempty"`
	HTTP      *HTTPInfo `json:"http,omitempty"`
}

// SSLInfo holds basic certificate details.
type SSLInfo struct {
	Issuer     string    `json:"issuer"`
	Expiry     time.Time `json:"expiry"`
	DaysLeft   int       `json:"days_left"`
	IsCritical bool      `json:"is_critical"`
}

// HTTPInfo holds basic web service metadata.
type HTTPInfo struct {
	Server string `json:"server,omitempty"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status"`
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

		// Try HTTP(S) metadata extraction
		if httpInfo := checkHTTP(fqdn); httpInfo != nil {
			res.HTTP = httpInfo
		}
	}

	// Check CNAME (spotting dangling assets)
	cname, err := resolver.LookupCNAME(lookupCtx, fqdn)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != strings.TrimSuffix(fqdn, ".") {
		res.IsActive = true
		cnameClean := strings.TrimSuffix(cname, ".")
		res.Records = append(res.Records, Record{
			Type:  "CNAME",
			Value: []string{cnameClean},
		})

		// Check for potentially orphaned CNAME (Dangling DNS)
		// If the CNAME target doesn't resolve to any IPs, it's a "Dangling" risk
		if _, err := resolver.LookupHost(lookupCtx, cnameClean); err != nil {
			res.Records = append(res.Records, Record{
				Type:  "RISK",
				Value: []string{"DANGLING-CNAME"},
			})
		}
	}

	// Check TXT records (for SPF, verification, etc.)
	txts, err := resolver.LookupTXT(lookupCtx, fqdn)
	if err == nil && len(txts) > 0 {
		res.IsActive = true
		res.Records = append(res.Records, Record{
			Type:  "TXT",
			Value: txts,
		})
	}

	// Check MX records (for mail infrastructure)
	mxs, err := resolver.LookupMX(lookupCtx, fqdn)
	if err == nil && len(mxs) > 0 {
		res.IsActive = true
		var values []string
		for _, mx := range mxs {
			values = append(values, fmt.Sprintf("%s (%d)", mx.Host, mx.Pref))
		}
		res.Records = append(res.Records, Record{
			Type:  "MX",
			Value: values,
		})
	}

	// Email Security Presence Check (DMARC/SPF/DKIM indicators)
	if fqdn == strings.TrimSuffix(fqdn, ".") { // Root or major subdomain
		if checkEmailSecurity(lookupCtx, resolver, fqdn) {
			res.Records = append(res.Records, Record{
				Type:  "EMAIL-SEC",
				Value: []string{"Configured"},
			})
		}
	}

	return res
}

func checkEmailSecurity(ctx context.Context, r *net.Resolver, domain string) bool {
	// Simple presence check for SPF or DMARC
	txts, _ := r.LookupTXT(ctx, domain)
	for _, txt := range txts {
		if strings.Contains(txt, "v=spf1") {
			return true
		}
	}
	dmarcTxts, _ := r.LookupTXT(ctx, "_dmarc."+domain)
	if len(dmarcTxts) > 0 {
		return true
	}
	return false
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

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func checkHTTP(fqdn string) *HTTPInfo {
	// Try HTTPS first, then HTTP
	protocols := []string{"https://", "http://"}
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, proto := range protocols {
		resp, err := client.Get(proto + fqdn)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		info := &HTTPInfo{
			Status: resp.StatusCode,
			Server: resp.Header.Get("Server"),
		}

		// Read small chunk for title
		body := make([]byte, 2048)
		n, _ := io.ReadFull(resp.Body, body)
		if n > 0 {
			matches := titleRegex.FindStringSubmatch(string(body[:n]))
			if len(matches) > 1 {
				info.Title = strings.TrimSpace(matches[1])
			}
		}

		return info
	}

	return nil
}
