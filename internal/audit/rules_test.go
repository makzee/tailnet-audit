package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/makzee/tailnet-audit/internal/tailscale"
)

// now is fixed so nothing in this package depends on the wall clock.
var now = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func testConfig() Config {
	return Config{
		StaleAfter:   30 * 24 * time.Hour,
		ExpiryWithin: 14 * 24 * time.Hour,
		Now:          func() time.Time { return now },
	}
}

// device builds a device that trips no rules, so each test can perturb exactly
// one thing and assert on exactly one finding.
func device(mutate ...func(*tailscale.Device)) tailscale.Device {
	d := tailscale.Device{
		ID:            "nodeid-1",
		Hostname:      "healthy",
		User:          "zeeshan@example.com",
		OS:            "linux",
		ClientVersion: "1.999.0",
		Authorized:    true,
		LastSeen:      tailscale.APITime{Time: now.Add(-time.Hour)},
		Expires:       tailscale.APITime{Time: now.Add(90 * 24 * time.Hour)},
	}
	for _, m := range mutate {
		m(&d)
	}
	return d
}

func rules(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Rule)
	}
	return out
}

func TestRules(t *testing.T) {
	tests := []struct {
		name      string
		device    tailscale.Device
		wantRules []string
		wantSev   Severity
	}{
		{
			name:      "healthy device produces nothing",
			device:    device(),
			wantRules: nil,
		},
		{
			name:      "unauthorized is critical",
			device:    device(func(d *tailscale.Device) { d.Authorized = false }),
			wantRules: []string{"unauthorized"},
			wantSev:   SeverityCritical,
		},
		{
			name: "expired key is critical",
			device: device(func(d *tailscale.Device) {
				d.Expires = tailscale.APITime{Time: now.Add(-48 * time.Hour)}
			}),
			wantRules: []string{"key-expired"},
			wantSev:   SeverityCritical,
		},
		{
			name: "key expiring inside the window warns",
			device: device(func(d *tailscale.Device) {
				d.Expires = tailscale.APITime{Time: now.Add(3 * 24 * time.Hour)}
			}),
			wantRules: []string{"key-expiring-soon"},
			wantSev:   SeverityWarn,
		},
		{
			name: "key expiring outside the window is silent",
			device: device(func(d *tailscale.Device) {
				d.Expires = tailscale.APITime{Time: now.Add(20 * 24 * time.Hour)}
			}),
			wantRules: nil,
		},
		{
			name: "expiry disabled on an untagged device warns",
			device: device(func(d *tailscale.Device) {
				d.KeyExpiryDisabled = true
				d.Expires = tailscale.APITime{}
			}),
			wantRules: []string{"key-expiry-disabled"},
			wantSev:   SeverityWarn,
		},
		{
			name: "expiry disabled on a tagged server is expected, not a finding",
			device: device(func(d *tailscale.Device) {
				d.KeyExpiryDisabled = true
				d.Expires = tailscale.APITime{}
				d.Tags = []string{"tag:subnetrouter"}
			}),
			wantRules: nil,
		},
		{
			name: "a device not seen for months is stale",
			device: device(func(d *tailscale.Device) {
				d.LastSeen = tailscale.APITime{Time: now.Add(-120 * 24 * time.Hour)}
			}),
			wantRules: []string{"device-stale"},
			wantSev:   SeverityWarn,
		},
		{
			name: "a device with no lastSeen at all is not called stale",
			device: device(func(d *tailscale.Device) {
				d.LastSeen = tailscale.APITime{}
			}),
			wantRules: nil,
		},
		{
			name: "advertised but unapproved routes warn",
			device: device(func(d *tailscale.Device) {
				d.AdvertisedRoutes = []string{"10.0.0.0/24", "192.168.1.0/24"}
				d.EnabledRoutes = []string{"10.0.0.0/24"}
			}),
			wantRules: []string{"routes-unapproved"},
			wantSev:   SeverityWarn,
		},
		{
			name: "fully approved routes are silent",
			device: device(func(d *tailscale.Device) {
				d.AdvertisedRoutes = []string{"10.0.0.0/24"}
				d.EnabledRoutes = []string{"10.0.0.0/24"}
			}),
			wantRules: nil,
		},
		{
			name:      "an available update is informational",
			device:    device(func(d *tailscale.Device) { d.UpdateAvailable = true }),
			wantRules: []string{"update-available"},
			wantSev:   SeverityInfo,
		},
		{
			name: "a tailnet lock error is critical",
			device: device(func(d *tailscale.Device) {
				d.TailnetLockError = "node key not signed"
			}),
			wantRules: []string{"tailnet-lock-error"},
			wantSev:   SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Run([]tailscale.Device{tt.device}, testConfig())
			gotRules := rules(got)

			if len(gotRules) != len(tt.wantRules) {
				t.Fatalf("rules = %v, want %v", gotRules, tt.wantRules)
			}
			for i, want := range tt.wantRules {
				if gotRules[i] != want {
					t.Fatalf("rules = %v, want %v", gotRules, tt.wantRules)
				}
			}
			if len(got) > 0 {
				if got[0].Severity != tt.wantSev {
					t.Errorf("severity = %s, want %s", got[0].Severity, tt.wantSev)
				}
				if got[0].Device != tt.device.DisplayName() {
					t.Errorf("device = %q, want %q", got[0].Device, tt.device.DisplayName())
				}
				if got[0].Detail == "" {
					t.Error("detail is empty; a finding must say what is wrong")
				}
			}
		})
	}
}

func TestExpiryIgnoredWhenDisabled(t *testing.T) {
	// A stale `expires` alongside keyExpiryDisabled must not produce a
	// key-expired finding: the key does not expire.
	d := device(func(d *tailscale.Device) {
		d.KeyExpiryDisabled = true
		d.Tags = []string{"tag:server"}
		d.Expires = tailscale.APITime{Time: now.Add(-365 * 24 * time.Hour)}
	})
	if got := Run([]tailscale.Device{d}, testConfig()); len(got) != 0 {
		t.Fatalf("findings = %v, want none", rules(got))
	}
}

func TestFindingsSortedBySeverityThenDevice(t *testing.T) {
	devices := []tailscale.Device{
		device(func(d *tailscale.Device) { d.Hostname = "zulu"; d.UpdateAvailable = true }),
		device(func(d *tailscale.Device) { d.Hostname = "alpha"; d.Authorized = false }),
		device(func(d *tailscale.Device) {
			d.Hostname = "mike"
			d.LastSeen = tailscale.APITime{Time: now.Add(-200 * 24 * time.Hour)}
		}),
	}
	got := Run(devices, testConfig())
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	want := []Severity{SeverityCritical, SeverityWarn, SeverityInfo}
	for i, sev := range want {
		if got[i].Severity != sev {
			t.Fatalf("finding %d severity = %s, want %s (order: %v)", i, got[i].Severity, sev, rules(got))
		}
	}
}

func TestOneDeviceCanTripSeveralRules(t *testing.T) {
	d := device(func(d *tailscale.Device) {
		d.Authorized = false
		d.UpdateAvailable = true
		d.Expires = tailscale.APITime{Time: now.Add(-time.Hour)}
	})
	got := Run([]tailscale.Device{d}, testConfig())
	if len(got) != 3 {
		t.Fatalf("rules = %v, want 3 findings", rules(got))
	}
	if Count(got, SeverityCritical) != 2 {
		t.Errorf("critical count = %d, want 2", Count(got, SeverityCritical))
	}
	if Count(got, SeverityInfo) != 3 {
		t.Errorf("count at or above info = %d, want 3", Count(got, SeverityInfo))
	}
}

func TestParseSeverity(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"info", SeverityInfo, true},
		{"warn", SeverityWarn, true},
		{"warning", SeverityWarn, true},
		{"CRITICAL", SeverityCritical, true},
		{"  crit ", SeverityCritical, true},
		{"never", 0, false},
		{"", 0, false},
	} {
		got, ok := ParseSeverity(tt.in)
		if ok != tt.ok {
			t.Errorf("ParseSeverity(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("ParseSeverity(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestReportTableAndJSON(t *testing.T) {
	findings := Run([]tailscale.Device{
		device(func(d *tailscale.Device) { d.Hostname = "alpha"; d.Authorized = false }),
	}, testConfig())
	report := NewReport("-", 1, findings, now)

	var table bytes.Buffer
	if err := report.WriteTable(&table); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	for _, want := range []string{"critical", "alpha", "unauthorized", "1 devices audited"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("table output missing %q:\n%s", want, table.String())
		}
	}

	var out bytes.Buffer
	if err := report.WriteJSON(&out); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded struct {
		Version  int `json:"version"`
		Findings []struct {
			Severity string `json:"severity"`
			Rule     string `json:"rule"`
		} `json:"findings"`
		Summary Summary `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("report JSON does not round-trip: %v\n%s", err, out.String())
	}
	if decoded.Version != 1 {
		t.Errorf("version = %d, want 1", decoded.Version)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].Severity != "critical" {
		t.Fatalf("findings = %+v, want one critical", decoded.Findings)
	}
	if decoded.Summary.Critical != 1 {
		t.Errorf("summary.critical = %d, want 1", decoded.Summary.Critical)
	}
}

func TestCleanReportSaysSo(t *testing.T) {
	var buf bytes.Buffer
	if err := NewReport("-", 12, nil, now).WriteTable(&buf); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("clean report = %q, want it to say there were no findings", buf.String())
	}
	// A nil findings slice must still marshal as [] rather than null, so a
	// consumer can range over it unconditionally.
	var out bytes.Buffer
	if err := NewReport("-", 12, nil, now).WriteJSON(&out); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(out.String(), `"findings": []`) {
		t.Errorf("empty findings marshalled as null, want []:\n%s", out.String())
	}
}
