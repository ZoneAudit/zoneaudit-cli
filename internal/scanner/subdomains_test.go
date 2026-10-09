package scanner_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ZoneAudit/zoneaudit-cli/internal/scanner"
	"github.com/ZoneAudit/zoneaudit-cli/internal/scannertest"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRunScanOrderAndTotals(t *testing.T) {
	f := newFixture(t, nil)
	progress := make(chan int, 10)
	res := f.s.RunScan(context.Background(), "example.com", progress)
	close(progress)

	var got []string
	for _, r := range res.Active {
		got = append(got, r.Subdomain)
	}
	want := []string{"example.com", "mail.example.com", "old.example.com", "shop.example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("active = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("active = %v, want %v (root first, then sorted)", got, want)
		}
	}
	if res.Total != 5 {
		t.Errorf("total = %d, want 5", res.Total)
	}
	ticks := 0
	for p := range progress {
		ticks += p
	}
	if ticks != 5 {
		t.Errorf("progress = %d, want 5", ticks)
	}
	if res.SchemaVersion != scanner.SchemaVersion || res.Tool.Name != scanner.ToolName {
		t.Errorf("report header = %q %q", res.SchemaVersion, res.Tool.Name)
	}
}

func TestRunScanStopsWhenCancelled(t *testing.T) {
	f := newFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := f.s.RunScan(ctx, "example.com", nil)
	if len(res.Active) != 0 {
		t.Errorf("a cancelled scan should find nothing, got %d hosts", len(res.Active))
	}
}

// TestJSONReportGolden pins the JSON format. If this fails after an
// intentional change, update docs/json-output.md and SchemaVersion, then
// run: go test ./internal/scanner -run Golden -update
func TestJSONReportGolden(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	res := f.s.RunScan(ctx, "example.com", nil)
	exp, err := f.s.GetDomainExpiry(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	es := f.s.CheckEmailSecurity(ctx, "example.com")
	res.DomainExpiry, res.EmailSecurity = exp, &es
	res.GeneratedAt = scannertest.Now
	res.DurationMS = 1234
	res.Requests = 0 // depends on scheduling; covered elsewhere
	res.Tool.Version, res.Version = "0.0.0-test", "0.0.0-test"

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "report.golden.json")
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), buf.Bytes()) {
		t.Errorf("JSON report changed:\n%s", buf.String())
	}

	// The documented required fields are all present.
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "tool", "domain", "generated_at", "duration_ms", "settings", "requests", "domain_expiry", "email_security", "active", "total_scanned", "version"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON report is missing %q", k)
		}
	}
	if _, err := time.Parse(time.RFC3339, m["generated_at"].(string)); err != nil {
		t.Errorf("generated_at is not RFC 3339: %v", err)
	}
}
