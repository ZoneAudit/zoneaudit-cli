package scanner

import (
	"context"
	"errors"
	"net"
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
}

func (d *dialRecorder) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	return nil, errors.New("refused by test")
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
