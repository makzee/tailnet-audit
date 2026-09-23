// Command tailnet-audit reports posture problems in a Tailscale tailnet:
// expired keys, unapproved subnet routes, stale devices, unauthorized nodes.
//
// It is read-only. Every request it makes is a GET.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/oauth2/clientcredentials"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/makzee/tailnet-audit/internal/audit"
	"github.com/makzee/tailnet-audit/internal/tailscale"
)

// Exit codes are part of the tool's contract: a cron job or CI step reads
// these, so they are documented in the README and must not drift.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

const tokenEnv = "TAILSCALE_API_KEY"
const oauthClientIdEnv = "TAILSCALE_OAUTH_CLIENT_ID"
const oauthClientSecretEnv = "TAILSCALE_OAUTH_CLIENT_SECRET"

type options struct {
	tailnet      string
	staleAfter   time.Duration
	expiryWithin time.Duration
	format       string
	failOn       string
	timeout      time.Duration
	verbose      bool
}

func main() {
	os.Exit(run())
}

func run() int {
	opts, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitClean
		}
		fmt.Fprintln(os.Stderr, "tailnet-audit:", err)
		return exitError
	}

	logger := newLogger(opts.verbose)

	// Ctrl-C cancels the run, including any pending retry backoff.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	id := os.Getenv(oauthClientIdEnv)
	secret := os.Getenv(oauthClientSecretEnv)
	var cfg *clientcredentials.Config
	if id != "" && secret != "" {
		cfg = &clientcredentials.Config{
			ClientID:     id,
			ClientSecret: secret,
		}
	}

	token := os.Getenv(tokenEnv)

	client, err := tailscale.New(tailscale.WithLogger(logger), tailscale.WithToken(token), tailscale.WithOAuth(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailnet-audit:", err)
		return exitError
	}

	devices, err := client.ListDevices(ctx, opts.tailnet)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailnet-audit:", explain(err))
		return exitError
	}

	findings := audit.Run(devices, audit.Config{
		StaleAfter:   opts.staleAfter,
		ExpiryWithin: opts.expiryWithin,
	})
	report := audit.NewReport(opts.tailnet, len(devices), findings, time.Now())

	if opts.format == "json" {
		err = report.WriteJSON(os.Stdout)
	} else {
		err = report.WriteTable(os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailnet-audit: writing report:", err)
		return exitError
	}

	if opts.failOn == "never" {
		return exitClean
	}
	threshold, _ := audit.ParseSeverity(opts.failOn)
	if audit.Count(findings, threshold) > 0 {
		return exitFindings
	}
	return exitClean
}

func parseFlags(args []string, errOut *os.File) (options, error) {
	var opts options
	fs := flag.NewFlagSet("tailnet-audit", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&opts.tailnet, "tailnet", tailscale.DefaultTailnet,
		`tailnet to audit; "-" means the token's own tailnet`)
	fs.DurationVar(&opts.staleAfter, "stale-after", 30*24*time.Hour,
		"flag devices not seen for longer than this")
	fs.DurationVar(&opts.expiryWithin, "expiry-within", 14*24*time.Hour,
		"warn when a node key expires within this window")
	fs.StringVar(&opts.format, "format", "table", `output format: "table" or "json"`)
	fs.StringVar(&opts.failOn, "fail-on", "critical",
		`exit 1 when findings reach this severity: "critical", "warn", "info" or "never"`)
	fs.DurationVar(&opts.timeout, "timeout", 30*time.Second, "overall deadline for the run")
	fs.BoolVar(&opts.verbose, "v", false, "debug logging to stderr")
	fs.Usage = func() {
		fmt.Fprintf(errOut, "tailnet-audit — report posture problems in a Tailscale tailnet.\n\n")
		fmt.Fprintf(errOut, "Usage:\n  tailnet-audit [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(errOut, "\nThe API token is read from %s. Exit codes: 0 clean, 1 findings, 2 error.\n", tokenEnv)
	}

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if opts.format != "table" && opts.format != "json" {
		return opts, fmt.Errorf("unknown -format %q: want \"table\" or \"json\"", opts.format)
	}
	if opts.failOn != "never" {
		if _, ok := audit.ParseSeverity(opts.failOn); !ok {
			return opts, fmt.Errorf("unknown -fail-on %q: want \"critical\", \"warn\", \"info\" or \"never\"", opts.failOn)
		}
	}
	if opts.timeout <= 0 {
		return opts, errors.New("-timeout must be positive")
	}
	return opts, nil
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// explain turns the client's typed errors into something a person can act on
// without reading the source.
func explain(err error) string {
	switch {
	case errors.Is(err, tailscale.ErrUnauthorized):
		return fmt.Sprintf("the API token was rejected — check %s (tokens expire after at most 90 days): %v", tokenEnv, err)
	case errors.Is(err, tailscale.ErrForbidden):
		return fmt.Sprintf("the token lacks permission to read devices (needs the devices:core:read scope): %v", err)
	case errors.Is(err, tailscale.ErrNotFound):
		return fmt.Sprintf("no such tailnet — check -tailnet, or use \"-\" for the token's own: %v", err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("timed out — raise -timeout: %v", err)
	case errors.Is(err, context.Canceled):
		return "cancelled"
	default:
		return err.Error()
	}
}
