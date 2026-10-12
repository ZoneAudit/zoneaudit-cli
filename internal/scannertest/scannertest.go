// Package scannertest provides fakes backed by recorded fixtures, so the
// scanner and CLI tests are repeatable and never touch the network.
//
// testdata/rdap/example.com.json is a real RDAP response recorded from
// rdap.org. The DNS and HTTP fixtures are synthetic answers for the reserved
// example.com domain, stored in the shape the resolver and servers return.
package scannertest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed testdata
var fixtures embed.FS

// Now is the fixed clock used with the fixtures.
var Now = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// Fixture returns the bytes of a file under testdata.
func Fixture(name string) []byte {
	b, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return b
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// Resolver answers lookups from a DNS fixture file.
type Resolver struct {
	Host  map[string][]string `json:"host"`
	CNAME map[string]string   `json:"cname"`
	TXT   map[string][]string `json:"txt"`
	MX    map[string][]struct {
		Host string `json:"host"`
		Pref uint16 `json:"pref"`
	} `json:"mx"`
	NS map[string][]string `json:"ns"`

	// Errors forces a lookup to fail. Keys are "<type> <name>", for example
	// "host gone.example.net" or "txt _dmarc.example.com"; types are host,
	// cname, txt, mx and ns.
	Errors map[string]error `json:"-"`

	mu        sync.Mutex
	Calls     int
	Deadlines []time.Duration // time left on each lookup's context
}

// LoadResolver reads testdata/dns/<name>.json.
func LoadResolver(name string) *Resolver {
	r := &Resolver{}
	if err := json.Unmarshal(Fixture("dns/"+name+".json"), r); err != nil {
		panic(err)
	}
	return r
}

func (r *Resolver) record(ctx context.Context, typ, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls++
	if dl, ok := ctx.Deadline(); ok {
		r.Deadlines = append(r.Deadlines, time.Until(dl))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.Errors[typ+" "+key(name)]
}

// ServFail is the error the Go resolver returns for a SERVFAIL answer.
func ServFail(name string) error {
	return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

// Timeout is the error the Go resolver returns when a lookup times out.
func Timeout(name string) error {
	return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, IsTemporary: true}
}

// NotFound is the error the Go resolver returns for NXDOMAIN or no records.
func NotFound(name string) error { return notFound(name) }

func key(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// LookupHost returns the recorded addresses.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := r.record(ctx, "host", host); err != nil {
		return nil, err
	}
	if v, ok := r.Host[key(host)]; ok {
		return append([]string(nil), v...), nil
	}
	return nil, notFound(host)
}

// LookupCNAME behaves like the Go resolver: a name with addresses but no
// CNAME returns itself as the canonical name.
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err := r.record(ctx, "cname", host); err != nil {
		return "", err
	}
	if v, ok := r.CNAME[key(host)]; ok {
		return v, nil
	}
	if _, ok := r.Host[key(host)]; ok {
		return key(host) + ".", nil
	}
	return "", notFound(host)
}

// LookupTXT returns the recorded TXT strings.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := r.record(ctx, "txt", name); err != nil {
		return nil, err
	}
	if v, ok := r.TXT[key(name)]; ok {
		return append([]string(nil), v...), nil
	}
	return nil, notFound(name)
}

// LookupMX returns the recorded MX records.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := r.record(ctx, "mx", name); err != nil {
		return nil, err
	}
	v, ok := r.MX[key(name)]
	if !ok {
		return nil, notFound(name)
	}
	out := make([]*net.MX, 0, len(v))
	for _, mx := range v {
		out = append(out, &net.MX{Host: mx.Host, Pref: mx.Pref})
	}
	return out, nil
}

// LookupNS returns the recorded NS records.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	if err := r.record(ctx, "ns", name); err != nil {
		return nil, err
	}
	v, ok := r.NS[key(name)]
	if !ok {
		return nil, notFound(name)
	}
	out := make([]*net.NS, 0, len(v))
	for _, ns := range v {
		out = append(out, &net.NS{Host: ns})
	}
	return out, nil
}

// Transport replays recorded HTTP responses. Requests are keyed by
// "<scheme>_<host>" (testdata/http/<key>.http) or by exact URL in Routes.
// Anything else fails as if the connection was refused.
type Transport struct {
	Routes map[string][]byte // URL -> raw HTTP response

	mu       sync.Mutex
	Requests []*http.Request
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.Requests = append(t.Requests, req)
	t.mu.Unlock()
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	raw, ok := t.Routes[req.URL.String()]
	if !ok {
		var err error
		raw, err = fixtures.ReadFile(fmt.Sprintf("testdata/http/%s_%s.http", req.URL.Scheme, req.URL.Host))
		if err != nil {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		}
	}
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
}

// UserAgents returns the User-Agent header of every request seen.
func (t *Transport) UserAgents() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for _, r := range t.Requests {
		out = append(out, r.Header.Get("User-Agent"))
	}
	return out
}

// RawResponse builds a raw HTTP response for Transport.Routes.
func RawResponse(status int, headers map[string]string, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	return []byte(b.String())
}

// Certs serves certificate chains from memory.
type Certs struct {
	Chains map[string][]*x509.Certificate
}

// FetchCertificates implements scanner.CertFetcher.
func (c *Certs) FetchCertificates(ctx context.Context, host string) ([]*x509.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if chain, ok := c.Chains[key(host)]; ok {
		return chain, nil
	}
	return nil, io.EOF
}

// Certificate makes a leaf certificate for host, issued by a CA with the
// given issuer name, expiring at notAfter.
func Certificate(host string, issuer pkix.Name, notAfter time.Time) *x509.Certificate {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               issuer,
		NotBefore:             notAfter.AddDate(-1, 0, 0),
		NotAfter:              notAfter.AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notAfter.AddDate(0, -3, 0),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

// DefaultCerts returns certificates for the example.com fixture hosts:
// example.com expires in 60 days, www.example.com in 10 days.
func DefaultCerts() *Certs {
	return &Certs{Chains: map[string][]*x509.Certificate{
		"example.com":     {Certificate("example.com", pkix.Name{CommonName: "DigiCert Global G3 TLS ECC SHA384 2020 CA1"}, Now.AddDate(0, 0, 60).Add(time.Hour))},
		"www.example.com": {Certificate("www.example.com", pkix.Name{Organization: []string{"Let's Encrypt"}}, Now.AddDate(0, 0, 10).Add(time.Hour))},
	}}
}
