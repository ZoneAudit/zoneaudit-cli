package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
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

	return res
}

// EmailSecurity reports SPF and DMARC separately for the root domain.
// Presence of one never implies the other: a domain with SPF but no DMARC is still spoofable.
type EmailSecurity struct {
	SPF         bool   `json:"spf"`
	DMARC       bool   `json:"dmarc"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
}

// CheckEmailSecurity looks up SPF on the domain and DMARC on _dmarc.<domain>.
func CheckEmailSecurity(ctx context.Context, domain string) EmailSecurity {
	var es EmailSecurity
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r := net.DefaultResolver
	txts, _ := r.LookupTXT(lookupCtx, domain)
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			es.SPF = true
		}
	}
	dmarcTxts, _ := r.LookupTXT(lookupCtx, "_dmarc."+domain)
	for _, txt := range dmarcTxts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			es.DMARC = true
			for _, part := range strings.Split(txt, ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) == 2 && strings.EqualFold(kv[0], "p") {
					es.DMARCPolicy = strings.ToLower(strings.TrimSpace(kv[1]))
				}
			}
		}
	}
	return es
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
				info.Title = strings.TrimSpace(html.UnescapeString(matches[1]))
			}
		}

		return info
	}

	return nil
}
