// Command tailnet-audit reports posture problems in a Tailscale tailnet:
// expired keys, unapproved subnet routes, stale devices, unauthorized nodes.
//
// It is read-only. Every API request it makes is a GET; the only POST is the
// OAuth token exchange, which changes nothing in the tailnet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/makzee/tailnet-audit/internal/audit"
	"github.com/makzee/tailnet-audit/internal/tailscale"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Exit codes are part of the tool's contract: a cron job or CI step reads
// these, so they are documented in the README and must not drift.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

// Credentials come from the environment only: flags land in shell history and
// in the process table.
const (
	tokenEnv             = "TAILSCALE_API_KEY"
	oauthClientIDEnv     = "TAILSCALE_OAUTH_CLIENT_ID"
	oauthClientSecretEnv = "TAILSCALE_OAUTH_CLIENT_SECRET"
)

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

	cred, err := credential(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailnet-audit:", err)
		return exitError
	}

	// Ctrl-C cancels the run, including any pending retry backoff.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	client, err := tailscale.New(tailscale.WithLogger(logger), cred)
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
		fmt.Fprintf(errOut, "\nCredentials are read from %s and %s (preferred), or %s.\nExit codes: 0 clean, 1 findings, 2 error.\n",
			oauthClientIDEnv, oauthClientSecretEnv, tokenEnv)
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

// credential picks the API credential from the environment. An OAuth client
// wins over an API access token because it can be scoped to read-only. Half
// an OAuth pair is a mistake, not a reason to fall back silently.
func credential(getenv func(string) string) (tailscale.Option, error) {
	id, secret := getenv(oauthClientIDEnv), getenv(oauthClientSecretEnv)
	switch {
	case id != "" && secret != "":
		return tailscale.WithOAuth(&clientcredentials.Config{ClientID: id, ClientSecret: secret}), nil
	case id != "" || secret != "":
		return nil, fmt.Errorf("set both %s and %s, or neither", oauthClientIDEnv, oauthClientSecretEnv)
	}
	if token := getenv(tokenEnv); token != "" {
		return tailscale.WithToken(token), nil
	}
	return nil, fmt.Errorf("no credentials: set %s and %s (an OAuth client with the devices:core:read scope), or %s",
		oauthClientIDEnv, oauthClientSecretEnv, tokenEnv)
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
	var rErr *oauth2.RetrieveError
	switch {
	case errors.As(err, &rErr) && rErr.Response != nil && rErr.Response.StatusCode < 500:
		return fmt.Sprintf("the OAuth client was rejected — check %s and %s: %v", oauthClientIDEnv, oauthClientSecretEnv, err)
	case errors.Is(err, tailscale.ErrUnauthorized):
		return fmt.Sprintf("the API token was rejected — check %s (tokens expire after at most 90 days): %v", tokenEnv, err)
	case errors.Is(err, tailscale.ErrForbidden):
		return fmt.Sprintf("not allowed to read devices — an OAuth client needs the devices:core:read scope: %v", err)
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
