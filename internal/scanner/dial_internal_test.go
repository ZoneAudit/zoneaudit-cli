package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

// dialRecorder stands in for the network: it records every address the
// scanner tries to connect to and refuses the connection.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
	left  []time.Duration // time left on each dial's context
}

func (d *dialRecorder) dial(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	if dl, ok := ctx.Deadline(); ok {
		d.left = append(d.left, time.Until(dl))
	}
	d.mu.Unlock()
	return nil, errors.New("refused by test")
}

// ownTransportScanner builds a scanner that uses its own HTTP transport,
// TLS fetcher and RDAP client, with the network replaced by a recorder.
func ownTransportScanner(t *testing.T, r Resolver, mutate func(*Config)) (*Scanner, *dialRecorder) {
	t.Helper()
	cfg := Config{Rate: MaxRate, Timeout: 2 * time.Second, Resolver: r, Wordlist: []string{}, RDAPBaseURL: "https://rdap.test/domain/"}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := &dialRecorder{}
	s.dialer.dial = rec.dial
	return s, rec
}

// rebindingResolver answers a host's first address lookup with a public
// address and every later one with loopback, as a DNS rebinding attack would.
type rebindingResolver struct {
	*scannertest.Resolver
	mu   sync.Mutex
	seen map[string]int
}

func (r *rebindingResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	r.mu.Lock()
	n := r.seen[host]
	r.seen[host]++
	r.mu.Unlock()
	if host == "rebind.example.com" {
		if n == 0 {
			return []string{"23.192.228.99"}, nil
		}
		return []string{"127.0.0.1"}, nil
	}
	return r.Resolver.LookupHost(ctx, host)
}

func TestDialPathRejectsRebindingToLoopback(t *testing.T) {
	res := &rebindingResolver{Resolver: scannertest.LoadResolver("example.com"), seen: map[string]int{}}
	// No HTTPClient or CertFetcher: the scanner's own transport and TLS
	// fetcher are used, with the network replaced by the recorder.
	s, err := New(Config{Rate: MaxRate, Timeout: 2 * time.Second, Resolver: res, Wordlist: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &dialRecorder{}
	s.dialer.dial = rec.dial

	got := s.CheckSubdomain(context.Background(), "rebind.example.com")
	if !got.IsActive || got.Records[0].Value[0] != "23.192.228.99" {
		t.Fatalf("the public answer should still be reported: %+v", got.Records)
	}
	if got.SSL != nil || got.HTTP != nil {
		t.Errorf("no TLS or HTTP result expected: %+v %+v", got.SSL, got.HTTP)
	}
	if len(rec.addrs) != 0 {
		t.Errorf("connected to %v; the rebound loopback address must never be dialled", rec.addrs)
	}
	if res.seen["rebind.example.com"] < 2 {
		t.Errorf("the dialer should resolve the host itself (lookups: %d)", res.seen["rebind.example.com"])
	}
}

func TestPublicDialerDialsOnlyPublicAddresses(t *testing.T) {
	r := scannertest.LoadResolver("example.com")
	r.Host["mixed.example.com"] = []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "23.192.228.80"}
	r.Host["private.example.com"] = []string{"192.168.1.10", "fe80::1"}
	rec := &dialRecorder{}
	d := &publicDialer{resolver: r, dial: rec.dial}
	ctx := context.Background()

	if _, err := d.DialContext(ctx, "tcp", "mixed.example.com:443"); err == nil {
		t.Error("the recorder refuses every connection, so dialling should fail")
	}
	if len(rec.addrs) != 1 || rec.addrs[0] != "23.192.228.80:443" {
		t.Errorf("dialled %v, want only the public address", rec.addrs)
	}

	rec.addrs = nil
	for _, addr := range []string{"private.example.com:80", "169.254.169.254:80", "[::1]:443"} {
		_, err := d.DialContext(ctx, "tcp", addr)
		var np *NonPublicAddressError
		if !errors.As(err, &np) {
			t.Errorf("%s: err = %v, want NonPublicAddressError", addr, err)
		}
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialled %v, want no connection to a non-public address", rec.addrs)
	}
}

func TestBannerToPrivateHostIsNotConnected(t *testing.T) {
	// A host in the domain that resolves to a private address is reported
	// in DNS results, but neither the first request nor a redirect to it
	// is connected.
	r := scannertest.LoadResolver("example.com")
	r.Host["internal.example.com"] = []string{"10.0.0.5"}
	s, err := New(Config{Rate: MaxRate, Timeout: 2 * time.Second, Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	rec := &dialRecorder{}
	s.dialer.dial = rec.dial
	if info := s.checkHTTP(WithScope(context.Background(), "example.com"), "internal.example.com"); info != nil {
		t.Errorf("got %+v, want no banner", info)
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialled %v, want nothing", rec.addrs)
	}
}

func TestConnectionLookupsAreCounted(t *testing.T) {
	r := scannertest.LoadResolver("example.com")
	r.Host["internal.example.com"] = []string{"10.0.0.5"}
	s, rec := ownTransportScanner(t, r, nil)
	s.CheckSubdomain(context.Background(), "www.example.com")
	if len(rec.addrs) == 0 {
		t.Fatal("expected TLS and HTTP connection attempts")
	}
	// Every DNS lookup (including the dialer's) and every TLS or HTTP
	// request that reached the network went through the limiter.
	if got, want := s.RequestCount(), int64(r.Calls+len(rec.addrs)); got != want {
		t.Errorf("requests = %d, want %d (%d lookups + %d connections)", got, want, r.Calls, len(rec.addrs))
	}

	// A host with no public address costs its lookups only: no TLS or
	// HTTP request is admitted or counted.
	before, calls := s.RequestCount(), r.Calls
	s.CheckSubdomain(context.Background(), "internal.example.com")
	if got, want := s.RequestCount()-before, int64(r.Calls-calls); got != want {
		t.Errorf("private host: %d requests counted, want %d (lookups only)", got, want)
	}
}

func TestConnectionTimeoutStartsAfterItsOwnWait(t *testing.T) {
	// At one request per second with a 1s timeout, the TLS handshake's
	// address lookup must not run inside the handshake's timeout, or the
	// lookup's own limiter wait would use it all up.
	s, rec := ownTransportScanner(t, scannertest.LoadResolver("example.com"), func(c *Config) {
		c.Rate, c.Timeout = 1, time.Second
	})
	s.certs.FetchCertificates(context.Background(), "www.example.com")
	if len(rec.addrs) != 1 {
		t.Fatalf("dialled %v, want one attempt", rec.addrs)
	}
	if rec.left[0] < 500*time.Millisecond {
		t.Errorf("only %s of the 1s timeout was left when connecting", rec.left[0])
	}
}

func TestRDAPUsesThePublicDialer(t *testing.T) {
	r := scannertest.LoadResolver("example.com")
	r.Host["rdap.test"] = []string{"127.0.0.1"}
	s, rec := ownTransportScanner(t, r, nil)
	if exp, err := s.GetDomainExpiry(context.Background(), "example.com"); err == nil {
		t.Errorf("got %+v, want an error: rdap.test only has a loopback address", exp)
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialled %v, want nothing", rec.addrs)
	}

	r.Host["rdap.test"] = []string{"23.192.228.70"}
	s.GetDomainExpiry(context.Background(), "example.com")
	if len(rec.addrs) != 1 || rec.addrs[0] != "23.192.228.70:443" {
		t.Errorf("dialled %v, want the RDAP server's public address", rec.addrs)
	}
}

func TestDialFallsBackToIPv4WhenIPv6Hangs(t *testing.T) {
	r := scannertest.LoadResolver("example.com")
	r.Host["dual.example.com"] = []string{"2600:1406:3a00:21::173e:2e65", "23.192.228.80"}
	var mu sync.Mutex
	var tried []string
	d := &publicDialer{resolver: r, timeout: 5 * time.Second, dial: func(ctx context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		tried = append(tried, address)
		mu.Unlock()
		if strings.HasPrefix(address, "[") { // IPv6 never answers
			<-ctx.Done()
			return nil, ctx.Err()
		}
		c, other := net.Pipe()
		other.Close()
		return c, nil
	}}
	start := time.Now()
	c, err := d.DialContext(context.Background(), "tcp", "dual.example.com:443")
	if err != nil {
		t.Fatalf("dial failed: %v (tried %v)", err, tried)
	}
	c.Close()
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("IPv4 fallback took %s; it should start after %s", took, fallbackDelay)
	}
}

func TestDialReservesTimeForLaterAddresses(t *testing.T) {
	r := scannertest.LoadResolver("example.com")
	r.Host["two.example.com"] = []string{"23.192.228.80", "23.192.228.81"}
	d := &publicDialer{resolver: r, timeout: 5 * time.Second, dial: func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "23.192.228.80:443" { // never answers
			<-ctx.Done()
			return nil, ctx.Err()
		}
		c, other := net.Pipe()
		other.Close()
		return c, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "two.example.com:443")
	if err != nil {
		t.Fatalf("the second address was never tried in time: %v", err)
	}
	c.Close()
}

func TestPartialTimeout(t *testing.T) {
	cases := []struct {
		left time.Duration
		n    int
		want time.Duration
	}{
		{6 * time.Second, 2, 3 * time.Second},
		{3 * time.Second, 3, 2 * time.Second}, // at least minDialTime
		{time.Second, 2, time.Second},         // all that is left
		{5 * time.Second, 1, 5 * time.Second},
	}
	for _, c := range cases {
		if got := partialTimeout(c.left, c.n); got != c.want {
			t.Errorf("partialTimeout(%s, %d) = %s, want %s", c.left, c.n, got, c.want)
		}
	}
}
