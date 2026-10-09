package scanner_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
)

func TestCheckSubdomainAddressRecords(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "example.com")
	if !res.IsActive {
		t.Fatal("example.com should be active")
	}
	a := recordOf(res, scanner.RecordAddress)
	if a == nil {
		t.Fatal("no A/AAAA record")
	}
	want := []string{"23.192.228.80", "2600:1406:3a00:21::173e:2e65"}
	if !reflect.DeepEqual(a.Value, want) {
		t.Errorf("A/AAAA = %v, want sorted %v", a.Value, want)
	}
	if res.Records[0].Type != scanner.RecordAddress {
		t.Errorf("first record = %s, want A/AAAA", res.Records[0].Type)
	}
	if recordOf(res, scanner.RecordCNAME) != nil {
		t.Error("a name that is its own canonical name must not report a CNAME")
	}
}

func TestCheckSubdomainCNAME(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "shop.example.com")
	c := recordOf(res, scanner.RecordCNAME)
	if c == nil || c.Value[0] != "shop.provider.example.net" {
		t.Fatalf("CNAME = %+v, want shop.provider.example.net without trailing dot", c)
	}
	if recordOf(res, scanner.RecordRisk) != nil {
		t.Error("a CNAME whose target resolves must not be flagged as dangling")
	}
}

func TestCheckSubdomainDanglingCNAME(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "old.example.com")
	if !res.IsActive {
		t.Fatal("a host with only a CNAME should still be reported")
	}
	risk := recordOf(res, scanner.RecordRisk)
	if risk == nil || risk.Value[0] != scanner.RiskDanglingCNAME {
		t.Fatalf("RISK = %+v, want %s", risk, scanner.RiskDanglingCNAME)
	}
	if res.SSL != nil || res.HTTP != nil {
		t.Error("no TLS or HTTP request should be made to a host without addresses")
	}
}

func TestCheckSubdomainTXTAndMX(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "example.com")

	txt := recordOf(res, scanner.RecordTXT)
	wantTXT := []string{"google-site-verification=abc123", "v=spf1 include:_spf.example.com -all"}
	if txt == nil || !reflect.DeepEqual(txt.Value, wantTXT) {
		t.Errorf("TXT = %+v, want %v", txt, wantTXT)
	}

	mx := recordOf(res, scanner.RecordMX)
	wantMX := []string{"mx1.example.com (10)", "mx2.example.com (20)"}
	if mx == nil || !reflect.DeepEqual(mx.Value, wantMX) {
		t.Errorf("MX = %+v, want %v (sorted by preference)", mx, wantMX)
	}
}

func TestCheckSubdomainMailOnlyHost(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "mail.example.com")
	if !res.IsActive {
		t.Fatal("a host with TXT and MX but no address should be active")
	}
	if recordOf(res, scanner.RecordAddress) != nil || res.HTTP != nil || res.SSL != nil {
		t.Errorf("unexpected address, HTTP or TLS data: %+v", res)
	}
}

func TestCheckSubdomainInactive(t *testing.T) {
	f := newFixture(t, nil)
	res := f.s.CheckSubdomain(context.Background(), "vpn.example.com")
	if res.IsActive || len(res.Records) != 0 {
		t.Errorf("vpn.example.com should be inactive with no records, got %+v", res)
	}
}

func TestEvaluateEmailSecurity(t *testing.T) {
	cases := []struct {
		name  string
		root  []string
		dmarc []string
		want  scanner.EmailSecurity
	}{
		{"nothing", nil, nil, scanner.EmailSecurity{}},
		{"spf only", []string{"v=spf1 -all"}, nil, scanner.EmailSecurity{SPF: true}},
		{"spf upper case and spaces", []string{"  V=SPF1 include:x -all"}, nil, scanner.EmailSecurity{SPF: true}},
		{"not spf", []string{"v=spf10 -all", "spf1 -all"}, nil, scanner.EmailSecurity{}},
		{"dmarc reject", nil, []string{"v=DMARC1; p=reject; rua=mailto:a@example.com"}, scanner.EmailSecurity{DMARC: true, DMARCPolicy: "reject"}},
		{"dmarc quarantine spaced", nil, []string{"v=DMARC1 ;  P = Quarantine "}, scanner.EmailSecurity{DMARC: true, DMARCPolicy: "quarantine"}},
		{"dmarc none warns", []string{"v=spf1 -all"}, []string{"v=DMARC1; p=none"}, scanner.EmailSecurity{SPF: true, DMARC: true, DMARCPolicy: "none", DMARCWeak: true}},
		{"sp is not p", nil, []string{"v=DMARC1; sp=none; p=reject"}, scanner.EmailSecurity{DMARC: true, DMARCPolicy: "reject"}},
		{"dmarc without policy", nil, []string{"v=DMARC1"}, scanner.EmailSecurity{DMARC: true}},
		{"other txt at _dmarc", nil, []string{"some-verification=1"}, scanner.EmailSecurity{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanner.EvaluateEmailSecurity(c.root, c.dmarc); got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestCheckEmailSecurityFromDNS(t *testing.T) {
	f := newFixture(t, nil)
	es := f.s.CheckEmailSecurity(context.Background(), "example.com")
	want := scanner.EmailSecurity{SPF: true, DMARC: true, DMARCPolicy: "none", DMARCWeak: true}
	if es != want {
		t.Errorf("got %+v, want %+v", es, want)
	}
	es = f.s.CheckEmailSecurity(context.Background(), "nonexistent.example")
	if es != (scanner.EmailSecurity{}) {
		t.Errorf("a domain without records should report nothing present, got %+v", es)
	}
}
