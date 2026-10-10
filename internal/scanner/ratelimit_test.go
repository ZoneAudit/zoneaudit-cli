package scanner_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
)

func TestLimiterSpacesRequests(t *testing.T) {
	l := scanner.NewLimiter(50) // one every 20ms
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 11; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Wait(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// 11 requests at 50 per second need at least 10 intervals of 20ms.
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond {
		t.Errorf("11 requests at 50/s finished in %s; the limit was not applied", elapsed)
	}
	if l.Count() != 11 {
		t.Errorf("count = %d, want 11", l.Count())
	}
}

func TestLimiterHonoursCancellation(t *testing.T) {
	l := scanner.NewLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())
	if err := l.Wait(ctx); err != nil { // first request passes at once
		t.Fatal(err)
	}
	cancel()
	start := time.Now()
	if err := l.Wait(ctx); err == nil {
		t.Error("Wait should fail once the context is cancelled")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("Wait did not return promptly after cancellation")
	}
}

func TestScanIsRateLimited(t *testing.T) {
	f := newFixture(t, func(c *scanner.Config) {
		c.Rate = 40
		c.Wordlist = []string{"a", "b", "c"}
	})
	start := time.Now()
	f.s.RunScan(context.Background(), "example.com", nil)
	elapsed := time.Since(start)
	n := f.s.RequestCount()
	if n < 10 {
		t.Fatalf("only %d requests counted", n)
	}
	minimum := time.Duration(n-1) * (time.Second / 40)
	if elapsed < minimum*9/10 {
		t.Errorf("%d requests took %s; at 40 per second they need at least %s", n, elapsed, minimum)
	}
}

func TestEveryLookupHasTheRequestTimeout(t *testing.T) {
	f := newFixture(t, func(c *scanner.Config) { c.Timeout = 3 * time.Second })
	f.s.CheckSubdomain(context.Background(), "example.com")
	if len(f.resolver.Deadlines) == 0 {
		t.Fatal("no lookups recorded")
	}
	for _, left := range f.resolver.Deadlines {
		if left <= 0 || left > 3*time.Second {
			t.Errorf("lookup deadline %s is outside the 3s timeout", left)
		}
	}
}
