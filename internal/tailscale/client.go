package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DefaultBaseURL is the documented root of the Tailscale v2 API.
const DefaultBaseURL = "https://api.tailscale.com/api/v2"

// DefaultTailnet is the API's shorthand for "the tailnet this token belongs
// to", which is what almost every caller wants.
const DefaultTailnet = "-"

// Sentinel errors. Callers match with errors.Is rather than inspecting status
// codes or, worse, error strings.
var (
	ErrUnauthorized = errors.New("tailscale: unauthorized")
	ErrForbidden    = errors.New("tailscale: forbidden")
	ErrNotFound     = errors.New("tailscale: not found")
	ErrRateLimited  = errors.New("tailscale: rate limited")
	ErrServer       = errors.New("tailscale: server error")
)

// APIError is a non-2xx response from the API. Message carries the API's own
// "message" field when the body parses, and a truncated body otherwise.
type APIError struct {
	StatusCode int
	Message    string
	Method     string
	Path       string

	// RetryAfter carries a server-mandated delay when the response supplied a
	// Retry-After header; Set says whether it did, so a legitimate zero is
	// distinguishable from an absent header.
	RetryAfter    time.Duration
	RetryAfterSet bool
}

// retryAfter satisfies retryAfterHolder so backoff can defer to the server.
func (e *APIError) retryAfter() (time.Duration, bool) { return e.RetryAfter, e.RetryAfterSet }

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("tailscale: %s %s: %d %s", e.Method, e.Path, e.StatusCode, msg)
}

// Unwrap maps the status onto a sentinel so errors.Is(err, ErrNotFound) works
// without the caller ever touching StatusCode.
func (e *APIError) Unwrap() error {
	switch {
	case e.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case e.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case e.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case e.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	case e.StatusCode >= 500:
		return ErrServer
	default:
		return nil
	}
}

// Retryable reports whether re-sending the same request could plausibly
// succeed. 429 and 5xx qualify; every other 4xx is the caller's fault and
// retrying it only burns quota.
func (e *APIError) Retryable() bool {
	return retryableStatus(e.StatusCode)
}

func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// RetryPolicy bounds how hard the client tries before giving up.
type RetryPolicy struct {
	MaxAttempts int           // total attempts, including the first
	BaseDelay   time.Duration // first backoff step
	MaxDelay    time.Duration // ceiling for any single backoff
}

// DefaultRetryPolicy is deliberately modest: this is an auditing tool, not a
// service, and a caller would rather see an error than wait two minutes.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 4, BaseDelay: 250 * time.Millisecond, MaxDelay: 5 * time.Second}
}

// Client is a read-only Tailscale API client. It is safe for concurrent use.
type Client struct {
	baseURL string
	token   string
	oauth   *clientcredentials.Config
	http    *http.Client
	limiter *rate.Limiter
	retry   RetryPolicy
	logger  *slog.Logger
	sleep   func(context.Context, time.Duration) error

	mu     sync.Mutex
	cached *oauth2.Token
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL points the client at a different root — used by the tests to aim
// it at an httptest server.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimSuffix(u, "/") }
}

// WithHTTPClient supplies the underlying transport.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

func WithOAuth(cfg *clientcredentials.Config) Option {
	return func(c *Client) {
		if cfg != nil {
			cp := *cfg
			c.oauth = &cp
		}
	}
}

func WithToken(token string) Option {
	return func(c *Client) {
		if strings.TrimSpace(token) != "" {
			c.token = token
		}
	}
}

// WithRetryPolicy overrides the retry bounds.
func WithRetryPolicy(p RetryPolicy) Option {
	return func(c *Client) {
		if p.MaxAttempts < 1 {
			p.MaxAttempts = 1
		}
		c.retry = p
	}
}

// WithRateLimit bounds outbound requests to r per second with the given burst,
// independent of anything the server advertises.
func WithRateLimit(r float64, burst int) Option {
	return func(c *Client) {
		if r > 0 && burst > 0 {
			c.limiter = rate.NewLimiter(rate.Limit(r), burst)
		}
	}
}

// WithLogger attaches a structured logger. The token is never logged.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.logger = l
		}
	}
}

// New builds a client. The token is required; it is read from the environment
// by the caller rather than accepted as a flag.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		baseURL: DefaultBaseURL,
		http:    &http.Client{Timeout: 15 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(5), 5),
		retry:   DefaultRetryPolicy(),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		sleep:   sleepCtx,
	}
	for _, opt := range opts {
		opt(c)
	}

	switch {
	case c.oauth != nil:
		c.oauth.TokenURL = c.baseURL + "/oauth/token"
		c.oauth.AuthStyle = oauth2.AuthStyleInParams
		c.token = ""
	case c.token != "":
	default:
		return nil, errors.New("tailscale: no token or oauth creds are supplied")
	}
	return c, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	if c.oauth == nil {
		return c.token, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached.Valid() {
		return c.cached.AccessToken, nil
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)
	tok, err := c.oauth.Token(ctx)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return "", &transportError{Path: "/oauth/token", Err: err}
		}
		return "", err
	}
	c.cached = tok
	return tok.AccessToken, nil
}

// ListDevices returns every device in the tailnet. Pass DefaultTailnet ("-")
// for the token's own tailnet.
//
// fields=all is not optional: the default field set omits lastSeen, expires,
// keyExpiryDisabled, authorized, tags and the route lists, which is most of
// what an audit needs.
func (c *Client) ListDevices(ctx context.Context, tailnet string) ([]Device, error) {
	if tailnet == "" {
		tailnet = DefaultTailnet
	}
	var body struct {
		Devices []Device `json:"devices"`
	}
	path := "/tailnet/" + url.PathEscape(tailnet) + "/devices"
	if err := c.get(ctx, path, url.Values{"fields": {"all"}}, &body); err != nil {
		return nil, err
	}
	return body.Devices, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var lastErr error
	for attempt := 0; attempt < c.retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := c.backoff(attempt, lastErr)
			c.logger.DebugContext(ctx, "retrying request",
				slog.String("path", path),
				slog.Int("attempt", attempt+1),
				slog.Duration("delay", delay),
				slog.String("cause", lastErr.Error()))
			if err := c.sleep(ctx, delay); err != nil {
				return err
			}
		}

		// Bound our own request rate whatever the server is doing.
		if err := c.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("tailscale: rate limiter: %w", err)
		}

		err := c.attempt(ctx, endpoint, path, out)
		if err == nil {
			return nil
		}
		// A cancelled or expired context is final, never a retry.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(err, ctxErr)
		}
		if !retryable(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("tailscale: giving up after %d attempts: %w", c.retry.MaxAttempts, lastErr)
}

// attempt performs exactly one request/response cycle, always draining and
// closing the body so the connection goes back to the pool.
func (c *Client) attempt(ctx context.Context, endpoint, path string, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("tailscale: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return &transportError{Path: path, Err: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	c.logger.DebugContext(ctx, "tailscale api call",
		slog.String("path", path),
		slog.Int("status", resp.StatusCode),
		slog.Duration("elapsed", time.Since(start)))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return newAPIError(resp, http.MethodGet, path)
	}
	// Cap the body we are willing to decode; a wedged proxy should not be able
	// to exhaust memory.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
		return fmt.Errorf("tailscale: decode %s response: %w", path, err)
	}
	return nil
}

const userAgent = "tailnet-audit/1.0 (+https://github.com/makzee/tailnet-audit)"

// transportError marks a network-level failure, which is always worth retrying.
type transportError struct {
	Path string
	Err  error
}

func (e *transportError) Error() string {
	return fmt.Sprintf("tailscale: GET %s: %v", e.Path, e.Err)
}
func (e *transportError) Unwrap() error { return e.Err }

func retryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable()
	}
	var rErr *oauth2.RetrieveError
	if errors.As(err, &rErr) {
		return rErr.Response == nil || retryableStatus(rErr.Response.StatusCode)
	}
	var transErr *transportError
	return errors.As(err, &transErr)
}

func newAPIError(resp *http.Response, method, path string) *APIError {
	apiErr := &APIError{StatusCode: resp.StatusCode, Method: method, Path: path}

	// A server that tells us when to come back outranks our own backoff curve.
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
		apiErr.RetryAfter, apiErr.RetryAfterSet = d, true
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil || len(body) == 0 {
		return apiErr
	}
	var payload struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Message != "" {
		apiErr.Message = payload.Message
		return apiErr
	}
	apiErr.Message = strings.TrimSpace(string(body))
	if len(apiErr.Message) > 200 {
		apiErr.Message = apiErr.Message[:200] + "…"
	}
	return apiErr
}

// backoff computes the wait before the next attempt: exponential with full
// jitter, so concurrent callers spread out instead of resynchronising.
func (c *Client) backoff(attempt int, lastErr error) time.Duration {
	if d, ok := retryAfter(lastErr); ok {
		if d > c.retry.MaxDelay {
			return c.retry.MaxDelay
		}
		return d
	}
	exp := float64(c.retry.BaseDelay) * math.Pow(2, float64(attempt-1))
	ceiling := time.Duration(math.Min(exp, float64(c.retry.MaxDelay)))
	if ceiling <= 0 {
		return 0
	}
	return rand.N(ceiling)
}

// retryAfterHolder lets an error carry a server-mandated delay.
type retryAfterHolder interface{ retryAfter() (time.Duration, bool) }

func retryAfter(err error) (time.Duration, bool) {
	var holder retryAfterHolder
	if errors.As(err, &holder) {
		return holder.retryAfter()
	}
	return 0, false
}

// parseRetryAfter understands both forms RFC 9110 allows: delay-seconds and an
// HTTP-date.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(value); err == nil {
		d := when.Sub(now)
		if d < 0 {
			return 0, true
		}
		return d, true
	}
	return 0, false
}

// sleepCtx waits for d, or returns early if the context is done. A plain
// time.Sleep here would make Ctrl-C feel broken.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
