package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Distinctive values, so a leak check cannot pass or fail by coincidence.
const (
	testClientID     = "k123456CNTRL"
	testClientSecret = "tskey-client-SUPERSECRET"
	testIssuedToken  = "tok-issued-123"
)

func testOAuthConfig() *clientcredentials.Config {
	return &clientcredentials.Config{ClientID: testClientID, ClientSecret: testClientSecret}
}

// newOAuthTestClient is newTestClient authenticated with OAuth client
// credentials instead of an API token. No token is set, so a test that sees
// the issued token on the API call knows it came from the exchange.
func newOAuthTestClient(t *testing.T, h http.Handler, opts ...Option) (*Client, *[]time.Duration) {
	return newTestClient(t, h, append([]Option{WithOAuth(testOAuthConfig())}, opts...)...)
}

// oauthMux serves the two endpoints an OAuth run touches. The token URL is
// derived from the base URL, so one stub server covers both.
func oauthMux(token, devices http.HandlerFunc) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", token)
	mux.HandleFunc("/tailnet/-/devices", devices)
	return mux
}

// issueToken answers like Tailscale's token endpoint. The Content-Type is not
// decoration: without it oauth2 parses the body as form data and reports a
// missing access_token.
func issueToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600}`, testIssuedToken)
}

func tokenError(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func counted(n *atomic.Int32, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}
}

func TestOAuth_ExchangesCredentialsAndUsesIssuedToken(t *testing.T) {
	var gotAuth string
	c, _ := newOAuthTestClient(t, oauthMux(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("token request method = %s, want POST", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q, want client_credentials", got)
			}
			// Tailscale documents the credentials in the form body; that is
			// what AuthStyleInParams pins, instead of oauth2's Basic-auth probe.
			if r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != testClientSecret {
				t.Errorf("credentials not sent in the form body: %v", r.PostForm)
			}
			if _, _, ok := r.BasicAuth(); ok {
				t.Error("credentials also sent as Basic auth")
			}
			issueToken(w, r)
		},
		func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			fmt.Fprint(w, `{"devices":[]}`)
		},
	))

	if _, err := c.ListDevices(context.Background(), "-"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if want := "Bearer " + testIssuedToken; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestOAuth_TokenIsReusedAcrossCalls(t *testing.T) {
	var tokenHits, deviceHits atomic.Int32
	c, _ := newOAuthTestClient(t, oauthMux(
		counted(&tokenHits, issueToken),
		counted(&deviceHits, devicesJSON(`{"devices":[]}`)),
	))

	for i := 0; i < 2; i++ {
		if _, err := c.ListDevices(context.Background(), "-"); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (the token lasts an hour)", got)
	}
	if got := deviceHits.Load(); got != 2 {
		t.Errorf("devices endpoint hit %d times, want 2", got)
	}
}

func TestOAuth_RejectedCredentialsAreNotRetried(t *testing.T) {
	var tokenHits, deviceHits atomic.Int32
	c, slept := newOAuthTestClient(t, oauthMux(
		counted(&tokenHits, tokenError(http.StatusUnauthorized, `{"error":"invalid_client"}`)),
		counted(&deviceHits, devicesJSON(`{"devices":[]}`)),
	))

	_, err := c.ListDevices(context.Background(), "-")
	var rErr *oauth2.RetrieveError
	if !errors.As(err, &rErr) {
		t.Fatalf("err = %v, want an *oauth2.RetrieveError", err)
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1: a 401 will not fix itself", got)
	}
	if len(*slept) != 0 {
		t.Errorf("backed off %v before giving up, want no retries", *slept)
	}
	if got := deviceHits.Load(); got != 0 {
		t.Errorf("devices endpoint hit %d times without a token", got)
	}
}

// Some servers report an OAuth error with a 200. The status is what
// retryable() judges, so this must not be mistaken for success or retried.
func TestOAuth_ErrorInOKResponseIsNotRetried(t *testing.T) {
	var tokenHits atomic.Int32
	c, _ := newOAuthTestClient(t, oauthMux(
		counted(&tokenHits, tokenError(http.StatusOK, `{"error":"invalid_client"}`)),
		devicesJSON(`{"devices":[]}`),
	))

	if _, err := c.ListDevices(context.Background(), "-"); err == nil {
		t.Fatal("expected an error")
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1", got)
	}
}

func TestOAuth_TokenEndpointServerErrorIsRetried(t *testing.T) {
	var tokenHits atomic.Int32
	c, slept := newOAuthTestClient(t, oauthMux(
		func(w http.ResponseWriter, r *http.Request) {
			if tokenHits.Add(1) == 1 {
				tokenError(http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`)(w, r)
				return
			}
			issueToken(w, r)
		},
		devicesJSON(`{"devices":[]}`),
	))

	if _, err := c.ListDevices(context.Background(), "-"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if got := tokenHits.Load(); got != 2 {
		t.Errorf("token endpoint hit %d times, want 2", got)
	}
	if len(*slept) != 1 {
		t.Errorf("slept %d times, want 1 backoff before the retry", len(*slept))
	}
}

// A connection failure on the token request must be retried like one on the
// API request. oauth2 hands back a bare *url.Error, which accessToken wraps.
func TestOAuth_NetworkFailureIsRetried(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	dead := srv.URL
	srv.Close() // nothing is listening at dead any more

	c, err := New(WithBaseURL(dead), WithOAuth(testOAuthConfig()),
		WithRetryPolicy(RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 4 * time.Millisecond}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var slept []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		return ctx.Err()
	}

	_, err = c.ListDevices(context.Background(), "-")
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("err = %v, want the *url.Error still reachable through the wrapping", err)
	}
	if len(slept) != 2 {
		t.Errorf("slept %d times, want 2 (three attempts)", len(slept))
	}
}

// The reason for fetching tokens with the per-call context: cancelling a
// ListDevices call must also abandon a token request that is in flight.
func TestOAuth_CancellationReachesTokenFetch(t *testing.T) {
	entered := make(chan struct{})
	c, slept := newOAuthTestClient(t, oauthMux(
		func(w http.ResponseWriter, r *http.Request) {
			// Consume the body first: the server only starts watching for a
			// client hang-up (which cancels r.Context) once it has been read.
			_ = r.ParseForm()
			close(entered)
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second): // do not hang the suite if cancellation is broken
			}
		},
		devicesJSON(`{"devices":[]}`),
	))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-entered
		cancel()
	}()

	start := time.Now()
	_, err := c.ListDevices(ctx, "-")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v to notice cancellation", elapsed)
	}
	if len(*slept) != 0 {
		t.Errorf("backed off %v after cancellation, want none", *slept)
	}
}

func TestOAuth_ErrorStringNeverLeaksSecret(t *testing.T) {
	c, _ := newOAuthTestClient(t, oauthMux(
		tokenError(http.StatusUnauthorized, `{"error":"invalid_client"}`),
		devicesJSON(`{"devices":[]}`),
	))

	_, err := c.ListDevices(context.Background(), "-")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testClientSecret) {
		t.Fatalf("error message leaked the client secret: %q", err.Error())
	}
}

func TestOAuth_WinsWhenBothCredentialsAreGiven(t *testing.T) {
	var gotAuth string
	c, _ := newOAuthTestClient(t, oauthMux(
		issueToken,
		func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			fmt.Fprint(w, `{"devices":[]}`)
		},
	), WithToken("tskey-api-test"))

	if _, err := c.ListDevices(context.Background(), "-"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if want := "Bearer " + testIssuedToken; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestNew_RequiresACredential(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{"nothing", nil},
		{"blank token", []Option{WithToken("   ")}},
		{"nil OAuth config", []Option{WithOAuth(nil)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.opts...); err == nil {
				t.Fatal("expected New to refuse a client with no credential")
			}
		})
	}
}

func TestWithOAuth_DoesNotModifyCallersConfig(t *testing.T) {
	cfg := testOAuthConfig()
	if _, err := New(WithBaseURL("https://example.invalid/api/v2"), WithOAuth(cfg)); err != nil {
		t.Fatalf("New: %v", err)
	}
	if cfg.TokenURL != "" || cfg.AuthStyle != oauth2.AuthStyleAutoDetect {
		t.Errorf("New changed the caller's config: TokenURL=%q AuthStyle=%v", cfg.TokenURL, cfg.AuthStyle)
	}
}

// countingTransport counts requests per path on their way to the network.
type countingTransport struct {
	token, devices atomic.Int32
}

func (ct *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch r.URL.Path {
	case "/oauth/token":
		ct.token.Add(1)
	case "/tailnet/-/devices":
		ct.devices.Add(1)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// The token request must go through the client's own *http.Client (its
// timeout, and WithHTTPClient), not oauth2's fallback of http.DefaultClient.
func TestOAuth_TokenRequestUsesConfiguredHTTPClient(t *testing.T) {
	ct := &countingTransport{}
	c, _ := newOAuthTestClient(t, oauthMux(issueToken, devicesJSON(`{"devices":[]}`)),
		WithHTTPClient(&http.Client{Transport: ct}))

	if _, err := c.ListDevices(context.Background(), "-"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if got := ct.token.Load(); got != 1 {
		t.Errorf("token requests through the configured client = %d, want 1", got)
	}
	if got := ct.devices.Load(); got != 1 {
		t.Errorf("devices requests through the configured client = %d, want 1", got)
	}
}
