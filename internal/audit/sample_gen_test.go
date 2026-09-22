package audit

import (
	"os"
	"testing"
	"time"

	"github.com/makzee/tailnet-audit/internal/tailscale"
)

// TestGenerateSample renders the README's example output from real fixtures so
// the documented output cannot drift from what the code actually prints.
// Skipped unless -run is aimed at it explicitly.
func TestGenerateSample(t *testing.T) {
	if os.Getenv("TAILNET_AUDIT_GEN_SAMPLE") == "" {
		t.Skip("set TAILNET_AUDIT_GEN_SAMPLE=1 to render the README sample")
	}
	at := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	cfg := Config{StaleAfter: 30 * 24 * time.Hour, ExpiryWithin: 14 * 24 * time.Hour,
		Now: func() time.Time { return at }}

	devices := []tailscale.Device{
		{ID: "n1", Hostname: "laptop-zee", User: "zeeshan@example.com", OS: "macOS",
			ClientVersion: "1.88.0", Authorized: true,
			LastSeen: tailscale.APITime{Time: at.Add(-2 * time.Minute)},
			Expires:  tailscale.APITime{Time: at.Add(88 * 24 * time.Hour)}},
		{ID: "n2", Hostname: "homelab-traefik", User: "zeeshan@example.com", OS: "linux",
			ClientVersion: "1.80.0", UpdateAvailable: true, Authorized: true,
			Tags:             []string{"tag:server"},
			LastSeen:         tailscale.APITime{Time: at.Add(-5 * time.Minute)},
			Expires:          tailscale.APITime{Time: at.Add(-9 * 24 * time.Hour)},
			AdvertisedRoutes: []string{"192.168.1.0/24"}, EnabledRoutes: nil},
		{ID: "n3", Hostname: "old-pixel", User: "zeeshan@example.com", OS: "android",
			ClientVersion: "1.62.1", Authorized: true,
			LastSeen: tailscale.APITime{Time: at.Add(-214 * 24 * time.Hour)},
			Expires:  tailscale.APITime{Time: at.Add(4 * 24 * time.Hour)}},
		{ID: "n4", Hostname: "ci-runner", OS: "linux", ClientVersion: "1.90.0",
			Authorized: false,
			LastSeen:   tailscale.APITime{Time: at.Add(-time.Hour)},
			Expires:    tailscale.APITime{Time: at.Add(30 * 24 * time.Hour)}},
	}

	report := NewReport("-", len(devices), Run(devices, cfg), at)
	if err := report.WriteTable(os.Stdout); err != nil {
		t.Fatal(err)
	}
}
