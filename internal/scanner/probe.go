package scanner

import (
	"context"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

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

// CriticalDays is the threshold below which a certificate or domain expiry is flagged.
const CriticalDays = 30

// checkSSL reads the leaf certificate's expiry and issuer from one TLS handshake.
func (s *Scanner) checkSSL(ctx context.Context, fqdn string) *SSLInfo {
	certs, err := s.certs.FetchCertificates(ctx, fqdn)
	if err != nil || len(certs) == 0 {
		return nil
	}
	leaf := certs[0]
	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	days := daysUntil(s.now(), leaf.NotAfter)
	return &SSLInfo{
		Issuer:     issuer,
		Expiry:     leaf.NotAfter.UTC(),
		DaysLeft:   days,
		IsCritical: days < CriticalDays,
	}
}

var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// maxBodyRead is how much of a page is read to find its title.
const maxBodyRead = 8192

// checkHTTP makes one GET request over HTTPS, falling back to HTTP only if
// HTTPS does not answer, and reads the Server header and page title.
func (s *Scanner) checkHTTP(ctx context.Context, fqdn string) *HTTPInfo {
	for _, scheme := range []string{"https://", "http://"} {
		if info := s.fetchBanner(ctx, scheme+fqdn); info != nil {
			return info
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return nil
}

func (s *Scanner) fetchBanner(ctx context.Context, url string) *HTTPInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	info := &HTTPInfo{
		Status: resp.StatusCode,
		Server: strings.TrimSpace(resp.Header.Get("Server")),
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	info.Title = ExtractTitle(body)
	return info
}

// ExtractTitle returns the decoded, whitespace-collapsed page title, if any.
func ExtractTitle(body []byte) string {
	m := titleRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := html.UnescapeString(string(m[1]))
	return strings.Join(strings.Fields(t), " ")
}
