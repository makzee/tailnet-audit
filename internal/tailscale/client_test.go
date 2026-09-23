package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient aims a client at a stub server and removes the real waiting:
// backoff still gets computed and asserted on, it just does not cost the suite
// wall-clock time. The caller supplies the credential.
func newTestClient(t *testing.T, h http.Handler, opts ...Option) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	var slept []time.Duration
	base := []Option{
		WithBaseURL(srv.URL),
		WithRetryPolicy(RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 4 * time.Millisecond}),
	}
	c, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		return ctx.Err()
	}
	return c, &slept
}

// newTokenTestClient is newTestClient authenticated with an API access token.
func newTokenTestClient(t *testing.T, h http.Handler, opts ...Option) (*Client, *[]time.Duration) {
	return newTestClient(t, h, append([]Option{WithToken("tskey-api-test")}, opts...)...)
}

func devicesJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
}

func TestListDevices_RequestShape(t *testing.T) {
	var gotPath, gotQuery, gotAuth, gotAccept string
	c, _ := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotAuth, gotAccept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		fmt.Fprint(w, `{"devices":[]}`)
	}))

	if _, err := c.ListDevices(context.Background(), "-"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if want := "/tailnet/-/devices"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	// fields=all is load-bearing: the default field set omits everything the
	// audit rules read.
	if want := "fields=all"; gotQuery != want {
		t.Errorf("query = %q, want %q", gotQuery, want)
	}
	if want := "Bearer tskey-api-test"; gotAuth != want {
		t.Errorf("auth header = %q, want %q", gotAuth, want)
	}
	if want := "application/json"; gotAccept != want {
		t.Errorf("accept header = %q, want %q", gotAccept, want)
	}
}

func TestListDevices_DecodesDevices(t *testing.T) {
	c, _ := newTokenTestClient(t, devicesJSON(`{"devices":[
		{"id":"1","hostname":"alpha","lastSeen":"2026-09-01T10:00:00Z","expires":"2026-12-01T10:00:00Z",
		 "authorized":true,"tags":["tag:server"],"advertisedRoutes":["10.0.0.0/24"],"enabledRoutes":[]},
		{"id":"2","hostname":"beta","expires":"","keyExpiryDisabled":true}
	]}`))

	got, err := c.ListDevices(context.Background(), "-")
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d devices, want 2", len(got))
	}
	if got[0].Hostname != "alpha" || !got[0].Tagged() {
		t.Errorf("device 0 = %+v, want tagged alpha", got[0])
	}
	if routes := got[0].UnapprovedRoutes(); len(routes) != 1 || routes[0] != "10.0.0.0/24" {
		t.Errorf("unapproved routes = %v, want [10.0.0.0/24]", routes)
	}
	// An empty timestamp string must decode to the zero time rather than
	// failing the whole response.
	if !got[1].Expires.IsZero() {
		t.Errorf("empty expires decoded to %v, want zero time", got[1].Expires)
	}
}

func TestListDevices_UnknownFieldsIgnored(t *testing.T) {
	c, _ := newTokenTestClient(t, devicesJSON(`{"devices":[{"id":"1","hostname":"a","somethingNew":{"x":1}}],"nextPage":"x"}`))
	got, err := c.ListDevices(context.Background(), "-")
	if err != nil {
		t.Fatalf("a new server-side field broke the client: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1", len(got))
	}
}

func TestListDevices_DefaultsTailnetToDash(t *testing.T) {
	var gotPath string
	c, _ := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"devices":[]}`)
	}))
	if _, err := c.ListDevices(context.Background(), ""); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if want := "/tailnet/-/devices"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestStatusMapsToSentinel(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, `{"message":"invalid key"}`, ErrUnauthorized},
		{"forbidden", http.StatusForbidden, `{"message":"insufficient scope"}`, ErrForbidden},
		{"not found", http.StatusNotFound, `{"message":"tailnet not found"}`, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))

			_, err := c.ListDevices(context.Background(), "-")
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want errors.Is(..., %v)", err, tt.want)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want an *APIError", err)
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tt.status)
			}
			// The API's own message must survive to the caller.
			if apiErr.Message == "" {
				t.Error("Message is empty, want the API's message field")
			}
		})
	}
}

func TestNonRetryableStatusIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"message":"bad request"}`)
	}))

	if _, err := c.ListDevices(context.Background(), "-"); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d calls, want 1 — a 400 must never be retried", got)
	}
}

func TestRetriesServerErrorThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	c, slept := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"message":"boom"}`)
			return
		}
		fmt.Fprint(w, `{"devices":[{"id":"1","hostname":"alpha"}]}`)
	}))

	got, err := c.ListDevices(context.Background(), "-")
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1", len(got))
	}
	if calls.Load() != 2 {
		t.Errorf("made %d calls, want 2", calls.Load())
	}
	if len(*slept) != 1 {
		t.Fatalf("backed off %d times, want 1", len(*slept))
	}
	// Full jitter means the delay is random within the ceiling, so assert the
	// bound rather than an exact value.
	if d := (*slept)[0]; d < 0 || d > time.Millisecond {
		t.Errorf("backoff = %v, want within [0, 1ms] for the first retry", d)
	}
}

func TestRetryAfterHeaderOverridesBackoff(t *testing.T) {
	var calls atomic.Int32
	c, slept := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"message":"slow down"}`)
			return
		}
		fmt.Fprint(w, `{"devices":[]}`)
	}))

	if _, err := c.ListDevices(context.Background(), "-"); err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(*slept) != 1 {
		t.Fatalf("backed off %d times, want 1", len(*slept))
	}
	// Retry-After said 2s; MaxDelay caps it at 4ms. The cap must win, but the
	// value must be the cap rather than the jittered curve.
	if got := (*slept)[0]; got != 4*time.Millisecond {
		t.Errorf("backoff = %v, want the 4ms MaxDelay cap applied to Retry-After", got)
	}
}

func TestRetryExhaustionReturnsLastError(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"message":"unavailable"}`)
	}))

	_, err := c.ListDevices(context.Background(), "-")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrServer) {
		t.Errorf("err = %v, want errors.Is(..., ErrServer)", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("made %d calls, want 3 (MaxAttempts)", got)
	}
}

func TestCancelledContextStopsImmediately(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTokenTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.ListDevices(ctx, "-")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := calls.Load(); got > 1 {
		t.Errorf("made %d calls on a cancelled context, want at most 1", got)
	}
}

func TestMalformedBodyIsAnError(t *testing.T) {
	c, _ := newTokenTestClient(t, devicesJSON(`{"devices":[{"id":`))
	if _, err := c.ListDevices(context.Background(), "-"); err == nil {
		t.Fatal("expected a decode error on a truncated body")
	}
}

func TestEmptyTokenRejected(t *testing.T) {
	if _, err := New(WithToken("   ")); err == nil {
		t.Fatal("expected New to reject a blank token")
	}
}

func TestErrorStringNeverLeaksToken(t *testing.T) {
	const token = "tskey-api-SUPERSECRET"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"invalid key"}`)
	}))
	t.Cleanup(srv.Close)

	c, err := New(WithBaseURL(srv.URL), WithToken(token), WithRetryPolicy(RetryPolicy{MaxAttempts: 1}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.ListDevices(context.Background(), "-")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error message leaked the API token: %q", err.Error())
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"seconds", "30", 30 * time.Second, true},
		{"zero seconds", "0", 0, true},
		{"http date in future", now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{"http date in past", now.Add(-time.Hour).Format(http.TimeFormat), 0, true},
		{"empty", "", 0, false},
		{"garbage", "soon please", 0, false},
		{"negative", "-5", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("duration = %v, want %v", got, tt.want)
			}
		})
	}
}
