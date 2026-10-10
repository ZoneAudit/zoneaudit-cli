package scanner

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

// Regression: the per-request HTTP timeout must start after the rate
// limiter's wait. At -rate 1 with several workers, later requests wait
// longer than the timeout in the queue, yet must still succeed.
func TestHTTPTimeoutExcludesRateLimitWait(t *testing.T) {
	tr := &scannertest.Transport{}
	s, err := New(Config{
		Rate:        1,
		Timeout:     time.Second,
		Concurrency: 4,
		Resolver:    scannertest.LoadResolver("example.com"),
		HTTPClient:  &http.Client{Transport: tr},
		CertFetcher: scannertest.DefaultCerts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]*HTTPInfo, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.fetchBanner(context.Background(), "https://example.com")
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r == nil || r.Status != 200 {
			t.Errorf("request %d failed after queueing behind the rate limit: %+v", i, r)
		}
	}
}

// The timeout still applies to the request itself.
func TestHTTPTimeoutStillApplies(t *testing.T) {
	s, err := New(Config{
		Rate:       100,
		Timeout:    time.Second,
		HTTPClient: &http.Client{Transport: hangingTransport{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if r := s.fetchBanner(context.Background(), "https://example.com"); r != nil {
		t.Errorf("a hanging server should give no banner, got %+v", r)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("request took %s; the 1s timeout was not applied", d)
	}
}

type hangingTransport struct{}

func (hangingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}
