package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

// Report is the JSON shape of a run. It is versioned so a consumer parsing it
// in CI can tell when the contract changes under them.
type Report struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`
	Tailnet     string    `json:"tailnet"`
	DeviceCount int       `json:"deviceCount"`
	Findings    []Finding `json:"findings"`
	Summary     Summary   `json:"summary"`
}

// Summary counts findings by severity.
type Summary struct {
	Critical int `json:"critical"`
	Warn     int `json:"warn"`
	Info     int `json:"info"`
}

// NewReport assembles a report from a completed run.
func NewReport(tailnet string, deviceCount int, findings []Finding, generatedAt time.Time) Report {
	if findings == nil {
		findings = []Finding{}
	}
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityWarn:
			s.Warn++
		default:
			s.Info++
		}
	}
	return Report{
		Version:     1,
		GeneratedAt: generatedAt.UTC(),
		Tailnet:     tailnet,
		DeviceCount: deviceCount,
		Findings:    findings,
		Summary:     s,
	}
}

// WriteJSON emits the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteTable emits the human-readable form: one row per finding, then a
// one-line summary. A clean tailnet gets a single reassuring line rather than
// an empty table.
func (r Report) WriteTable(w io.Writer) error {
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintf(w, "%d devices audited, no findings.\n", r.DeviceCount)
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tDEVICE\tRULE\tDETAIL"); err != nil {
		return err
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.Device, f.Rule, f.Detail); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintf(w, "\n%d devices audited: %d critical, %d warn, %d info.\n",
		r.DeviceCount, r.Summary.Critical, r.Summary.Warn, r.Summary.Info)
	return err
}
