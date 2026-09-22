// Package audit turns a list of tailnet devices into posture findings.
//
// Every rule is a pure function of a device and a Config, with "now" injected,
// so the whole package is testable without a clock or a network.
package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/makzee/tailnet-audit/internal/tailscale"
)

// Severity orders findings from advisory to urgent.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarn
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityWarn:
		return "warn"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// MarshalJSON renders the severity as its name rather than an opaque integer.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// ParseSeverity accepts the names used on the command line. "never" is a
// threshold above every severity, meaning "do not fail".
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, true
	case "warn", "warning":
		return SeverityWarn, true
	case "critical", "crit":
		return SeverityCritical, true
	default:
		return 0, false
	}
}

// Finding is one rule firing against one device.
type Finding struct {
	Device   string   `json:"device"`
	DeviceID string   `json:"deviceId"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// Config holds the thresholds a run is judged against.
type Config struct {
	// StaleAfter flags a device not seen for longer than this.
	StaleAfter time.Duration
	// ExpiryWithin warns about a key expiring inside this window.
	ExpiryWithin time.Duration
	// Now is injectable so tests are not time-dependent. Zero means time.Now.
	Now func() time.Time
}

// DefaultConfig is a month of silence and a fortnight of expiry warning.
func DefaultConfig() Config {
	return Config{StaleAfter: 30 * 24 * time.Hour, ExpiryWithin: 14 * 24 * time.Hour}
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Run evaluates every rule against every device. Findings come back sorted
// most-severe first, then by device, so the output is stable across runs and
// diffable in CI.
func Run(devices []tailscale.Device, cfg Config) []Finding {
	var findings []Finding
	now := cfg.now()
	for _, d := range devices {
		findings = append(findings, evaluate(d, cfg, now)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Device != findings[j].Device {
			return findings[i].Device < findings[j].Device
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings
}

func evaluate(d tailscale.Device, cfg Config, now time.Time) []Finding {
	var out []Finding
	add := func(rule string, sev Severity, format string, args ...any) {
		out = append(out, Finding{
			Device:   d.DisplayName(),
			DeviceID: d.ID,
			Rule:     rule,
			Severity: sev,
			Detail:   fmt.Sprintf(format, args...),
		})
	}

	// An unapproved device is waiting at the door of a tailnet that has device
	// approval switched on.
	if !d.Authorized {
		add("unauthorized", SeverityCritical, "device is not authorized on this tailnet")
	}

	if d.TailnetLockError != "" {
		add("tailnet-lock-error", SeverityCritical, "tailnet lock: %s", d.TailnetLockError)
	}

	// Key expiry only means anything when expiry is enabled and the API gave us
	// a real timestamp.
	if !d.KeyExpiryDisabled && !d.Expires.IsZero() {
		switch {
		case d.Expires.Before(now):
			add("key-expired", SeverityCritical,
				"node key expired %s ago (%s)",
				humanDuration(now.Sub(d.Expires.Time)), d.Expires.Format(time.RFC3339))
		case d.Expires.Sub(now) <= cfg.ExpiryWithin:
			add("key-expiring-soon", SeverityWarn,
				"node key expires in %s (%s)",
				humanDuration(d.Expires.Sub(now)), d.Expires.Format(time.RFC3339))
		}
	}

	// Tagged nodes are servers; Tailscale does not require key renewal for
	// them, so flagging those would be noise. An untagged device with expiry
	// switched off is a real gap.
	if d.KeyExpiryDisabled && !d.Tagged() {
		add("key-expiry-disabled", SeverityWarn,
			"key expiry is disabled on an untagged device (owner %s)", fallback(d.User, "unknown"))
	}

	if cfg.StaleAfter > 0 && !d.LastSeen.IsZero() {
		if idle := now.Sub(d.LastSeen.Time); idle > cfg.StaleAfter {
			add("device-stale", SeverityWarn,
				"not seen for %s (last seen %s)", humanDuration(idle), d.LastSeen.Format(time.RFC3339))
		}
	}

	// Someone advertised a subnet route and nobody ever approved it: the route
	// silently does nothing, which is the kind of gap that survives for months.
	if unapproved := d.UnapprovedRoutes(); len(unapproved) > 0 {
		add("routes-unapproved", SeverityWarn,
			"advertises %d unapproved route(s): %s", len(unapproved), strings.Join(unapproved, ", "))
	}

	if d.UpdateAvailable {
		add("update-available", SeverityInfo,
			"client %s is out of date", fallback(d.ClientVersion, "(unknown version)"))
	}

	return out
}

// Count returns how many findings sit at or above sev.
func Count(findings []Finding, sev Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity >= sev {
			n++
		}
	}
	return n
}

func fallback(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// humanDuration renders a span at the coarsest unit that still says something
// useful — "3 months" beats "2160h0m0s" in a report a person reads.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 24*time.Hour:
		return plural(int(d.Hours()), "hour")
	case d < 60*24*time.Hour:
		return plural(int(d.Hours()/24), "day")
	default:
		return plural(int(d.Hours()/24/30), "month")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
