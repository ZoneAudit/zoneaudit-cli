package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"time"
)

// Limiter spaces requests evenly so that no more than the configured number
// start in any one second. It is safe for concurrent use. A nil Limiter does
// not limit.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	count    int64
}

// NewLimiter returns a limiter allowing perSecond requests per second.
// perSecond <= 0 means no limit.
func NewLimiter(perSecond int) *Limiter {
	l := &Limiter{}
	if perSecond > 0 {
		l.interval = time.Second / time.Duration(perSecond)
	}
	return l
}

// Wait blocks until the next request may start, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil {
		return nil
	}
	l.mu.Lock()
	l.count++
	if l.interval == 0 {
		l.mu.Unlock()
		return nil
	}
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Count returns how many requests have passed through the limiter.
func (l *Limiter) Count() int64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// RequestCount returns how many outbound requests the scanner has made.
func (s *Scanner) RequestCount() int64 { return s.limiter.Count() }

// limitedResolver applies the rate limit and a per-request timeout to every lookup.
type limitedResolver struct {
	base    Resolver
	limiter *Limiter
	timeout time.Duration
}

func (r *limitedResolver) begin(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if err := r.limiter.Wait(ctx); err != nil {
		return nil, nil, err
	}
	c, cancel := context.WithTimeout(ctx, r.timeout)
	return c, cancel, nil
}

func (r *limitedResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	c, cancel, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return r.base.LookupHost(c, host)
}

func (r *limitedResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	c, cancel, err := r.begin(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	return r.base.LookupCNAME(c, host)
}

func (r *limitedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	c, cancel, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return r.base.LookupTXT(c, name)
}

func (r *limitedResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	c, cancel, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return r.base.LookupMX(c, name)
}

func (r *limitedResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	c, cancel, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return r.base.LookupNS(c, name)
}

// limitedTransport rate limits every HTTP request, including redirects.
type limitedTransport struct {
	base    http.RoundTripper
	limiter *Limiter
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", UserAgent())
	}
	return t.base.RoundTrip(req)
}

// limitedCertFetcher rate limits and times out each TLS handshake.
type limitedCertFetcher struct {
	base    CertFetcher
	limiter *Limiter
	timeout time.Duration
}

func (f *limitedCertFetcher) FetchCertificates(ctx context.Context, host string) ([]*x509.Certificate, error) {
	if err := f.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	c, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	return f.base.FetchCertificates(c, host)
}

// tlsCertFetcher performs a real TLS handshake on port 443.
type tlsCertFetcher struct {
	timeout time.Duration
}

func (f tlsCertFetcher) FetchCertificates(ctx context.Context, host string) ([]*x509.Certificate, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: f.timeout},
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // report the certificate even if it is expired or invalid
		},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates, nil
}
