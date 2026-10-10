package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Record types reported in Result.Records.
const (
	RecordAddress = "A/AAAA"
	RecordCNAME   = "CNAME"
	RecordTXT     = "TXT"
	RecordMX      = "MX"
	RecordRisk    = "RISK"
	// RecordUnchecked lists checks that could not be completed because a
	// lookup failed (timeout, SERVFAIL, cancellation). Added in schema 1.1.
	RecordUnchecked = "UNCHECKED"

	// RiskDanglingCNAME flags a CNAME whose target no longer resolves.
	RiskDanglingCNAME = "DANGLING-CNAME"
)

// Lookup outcomes reported for SPF and DMARC (schema 1.1).
const (
	StatusPresent     = "present"
	StatusMissing     = "missing"
	StatusUnavailable = "unavailable" // the lookup failed, so presence is unknown
)

// isAuthoritativeAbsence reports whether err means the name or the record
// does not exist (NXDOMAIN or an answer with no records), as opposed to a
// failure such as a timeout, SERVFAIL or cancellation.
func isAuthoritativeAbsence(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTimeout && !dnsErr.IsTemporary
}

// CheckSubdomain performs the DNS lookups for one host and, when it has an
// address, one TLS handshake and a light HTTP(S) request.
func (s *Scanner) CheckSubdomain(ctx context.Context, fqdn string) Result {
	res := Result{Subdomain: fqdn}

	// A/AAAA records
	ips, err := s.resolver.LookupHost(ctx, fqdn)
	if err == nil && len(ips) > 0 {
		res.IsActive = true
		ips = append([]string(nil), ips...)
		sort.Strings(ips)
		res.Records = append(res.Records, Record{Type: RecordAddress, Value: ips})

		if ssl := s.checkSSL(ctx, fqdn); ssl != nil {
			res.SSL = ssl
		}
		if info := s.checkHTTP(ctx, fqdn); info != nil {
			res.HTTP = info
		}
	}

	// CNAME, and the dangling CNAME check
	cname, err := s.resolver.LookupCNAME(ctx, fqdn)
	target := strings.TrimSuffix(cname, ".")
	if err == nil && target != "" && !strings.EqualFold(target, strings.TrimSuffix(fqdn, ".")) {
		res.IsActive = true
		res.Records = append(res.Records, Record{Type: RecordCNAME, Value: []string{target}})

		// A CNAME whose target does not resolve can be taken over by whoever
		// registers or claims that target. Only an authoritative "does not
		// exist" or an empty answer counts; any other failure leaves the
		// risk undetermined.
		addrs, err := s.resolver.LookupHost(ctx, target)
		switch {
		case err == nil && len(addrs) == 0, err != nil && isAuthoritativeAbsence(err):
			res.Records = append(res.Records, Record{Type: RecordRisk, Value: []string{RiskDanglingCNAME}})
		case err != nil:
			res.Records = append(res.Records, Record{Type: RecordUnchecked, Value: []string{RiskDanglingCNAME}})
		}
	}

	// TXT records (SPF, site verification and so on)
	txts, err := s.resolver.LookupTXT(ctx, fqdn)
	if err == nil && len(txts) > 0 {
		res.IsActive = true
		txts = append([]string(nil), txts...)
		sort.Strings(txts)
		res.Records = append(res.Records, Record{Type: RecordTXT, Value: txts})
	}

	// MX records (mail infrastructure)
	mxs, err := s.resolver.LookupMX(ctx, fqdn)
	if err == nil && len(mxs) > 0 {
		res.IsActive = true
		sorted := append(mxs[:0:0], mxs...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].Pref != sorted[j].Pref {
				return sorted[i].Pref < sorted[j].Pref
			}
			return sorted[i].Host < sorted[j].Host
		})
		values := make([]string, 0, len(sorted))
		for _, mx := range sorted {
			values = append(values, fmt.Sprintf("%s (%d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
		res.Records = append(res.Records, Record{Type: RecordMX, Value: values})
	}

	return res
}

// EmailSecurity reports SPF and DMARC separately for the root domain.
// Presence of one never implies the other: a domain with SPF but no DMARC is still spoofable.
type EmailSecurity struct {
	SPF         bool   `json:"spf"`
	DMARC       bool   `json:"dmarc"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	// DMARCWeak is true when a DMARC record exists but its policy is "none"
	// (monitoring only), so spoofed email is not blocked.
	DMARCWeak bool `json:"dmarc_weak"`
	// SPFStatus and DMARCStatus are "present", "missing" or "unavailable"
	// (the lookup failed, so SPF or DMARC may still exist). Schema 1.1.
	SPFStatus   string `json:"spf_status"`
	DMARCStatus string `json:"dmarc_status"`
}

// CheckEmailSecurity looks up SPF on the domain and DMARC on _dmarc.<domain>.
// A failed lookup is reported as unavailable, never as missing.
func (s *Scanner) CheckEmailSecurity(ctx context.Context, domain string) EmailSecurity {
	txts, rootErr := s.resolver.LookupTXT(ctx, domain)
	dmarc, dmarcErr := s.resolver.LookupTXT(ctx, "_dmarc."+domain)
	es := EvaluateEmailSecurity(txts, dmarc)
	if rootErr != nil && !isAuthoritativeAbsence(rootErr) {
		es.SPFStatus = StatusUnavailable
	}
	if dmarcErr != nil && !isAuthoritativeAbsence(dmarcErr) {
		es.DMARCStatus = StatusUnavailable
	}
	return es
}

// EvaluateEmailSecurity interprets the root TXT records and the _dmarc TXT
// records, assuming both lookups were answered.
func EvaluateEmailSecurity(rootTXT, dmarcTXT []string) EmailSecurity {
	es := EmailSecurity{SPFStatus: StatusMissing, DMARCStatus: StatusMissing}
	for _, txt := range rootTXT {
		if hasTag(txt, "v=spf1") {
			es.SPF = true
			es.SPFStatus = StatusPresent
		}
	}
	for _, txt := range dmarcTXT {
		if !hasTag(txt, "v=dmarc1") {
			continue
		}
		es.DMARC = true
		es.DMARCStatus = StatusPresent
		for _, part := range strings.Split(txt, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "p") {
				es.DMARCPolicy = strings.ToLower(strings.TrimSpace(kv[1]))
			}
		}
	}
	es.DMARCWeak = es.DMARC && es.DMARCPolicy == "none"
	return es
}

// hasTag reports whether a TXT record starts with the given version tag,
// ignoring case and surrounding space.
func hasTag(txt, tag string) bool {
	t := strings.ToLower(strings.TrimSpace(txt))
	if !strings.HasPrefix(t, tag) {
		return false
	}
	rest := t[len(tag):]
	return rest == "" || rest[0] == ' ' || rest[0] == ';' || rest[0] == '\t'
}
