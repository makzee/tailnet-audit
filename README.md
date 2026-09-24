# tailnet-audit

A small, read-only auditor for a [Tailscale](https://tailscale.com) tailnet. It reports the
things that quietly rot — expired node keys, subnet routes nobody ever approved, devices last
seen in February, nodes sitting unauthorized — and exits non-zero so you can run it on a
schedule and be told rather than having to remember to look.

```
$ tailnet-audit
SEVERITY  DEVICE           RULE               DETAIL
critical  ci-runner        unauthorized       device is not authorized on this tailnet
critical  homelab-traefik  key-expired        node key expired 9 days ago (2026-09-13T12:00:00Z)
warn      homelab-traefik  routes-unapproved  advertises 1 unapproved route(s): 192.168.1.0/24
warn      old-pixel        device-stale       not seen for 7 months (last seen 2026-02-20T12:00:00Z)
warn      old-pixel        key-expiring-soon  node key expires in 4 days (2026-09-26T12:00:00Z)
info      homelab-traefik  update-available   client 1.80.0 is out of date

4 devices audited: 2 critical, 3 warn, 1 info.
```

That sample is rendered from fixtures rather than typed by hand; regenerate it after changing
the output with `TAILNET_AUDIT_GEN_SAMPLE=1 go test ./internal/audit -run TestGenerateSample -v`.

**It is read-only by construction.** Every API request it makes is a `GET`; the only `POST`
is the OAuth token exchange, which changes nothing in the tailnet. Given an OAuth client
scoped to `devices:core:read`, the credential is read-only too, not just the code.

## Install

```sh
go install github.com/makzee/tailnet-audit/cmd/tailnet-audit@latest
```

**Recommended: an OAuth client.** In the admin console, create an OAuth client with only the
**Devices → Core → Read** scope, then:

```sh
export TAILSCALE_OAUTH_CLIENT_ID='...'
export TAILSCALE_OAUTH_CLIENT_SECRET='tskey-client-...'
tailnet-audit
```

**Or an API access token**, from **Settings → Keys**:

```sh
export TAILSCALE_API_KEY='tskey-api-...'
tailnet-audit
```

An API access token has the full API permissions of the user who created it and cannot be
narrowed. This tool only ever reads with it, but treat it as an admin credential: give it a
short expiry and revoke it when you are done. If both are set, the OAuth client wins; setting
only one of the two OAuth variables is an error rather than a silent fallback.

Credentials are read from the environment only. They are deliberately not flags: flags land
in shell history and in the process table, where other users on the box can read them.

## Usage

```
tailnet-audit [flags]

  -tailnet string       tailnet to audit; "-" means the token's own tailnet (default "-")
  -stale-after duration flag devices not seen for longer than this (default 720h)
  -expiry-within        warn when a node key expires within this window (default 336h)
  -format string        "table" or "json" (default "table")
  -fail-on string       exit 1 at this severity: critical, warn, info, never (default "critical")
  -timeout duration     overall deadline for the run (default 30s)
  -v                    debug logging to stderr
```

Exit codes: `0` clean, `1` findings at or above `-fail-on`, `2` operational failure. So a
nightly check is just:

```sh
tailnet-audit -fail-on warn || notify-me
```

`-format json` emits a versioned document (`version`, `generatedAt`, `deviceCount`,
`findings[]`, `summary`) for piping into something else.

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `unauthorized` | critical | `authorized` is false — the node is waiting at the door |
| `key-expired` | critical | key expiry is enabled and `expires` is in the past |
| `tailnet-lock-error` | critical | `tailnetLockError` is non-empty |
| `key-expiring-soon` | warn | the key expires inside `-expiry-within` |
| `device-stale` | warn | `lastSeen` is older than `-stale-after` |
| `routes-unapproved` | warn | an advertised route is missing from `enabledRoutes` |
| `key-expiry-disabled` | warn | expiry is off **and** the device is untagged |
| `update-available` | info | `updateAvailable` is true |

`key-expiry-disabled` ignores tagged devices on purpose: tagged nodes are servers, Tailscale
does not require key renewal for them, and flagging every one of them would train you to
ignore the output. An *untagged* device with expiry switched off is a real gap and stays
flagged. Likewise `key-expired` keys off what the API reports in `keyExpiryDisabled` rather
than inferring policy from tags.

## Why it looks like this

The API calls here are three lines. Everything interesting is what surrounds them, and that
was the point of writing it:

- **`context.Context` on every exported call.** Cancellation interrupts an in-flight request
  *and* a pending retry sleep — a backoff implemented with `time.Sleep` makes Ctrl-C feel
  broken, which is the kind of thing you only notice in production.
- **Retries on 429 and 5xx only.** Every other 4xx is the caller's fault; retrying it just
  burns quota and delays the error message you needed.
- **Exponential backoff with full jitter** — `rand[0, min(maxDelay, base·2ⁿ))`. Without
  jitter, a fleet of callers that fail together retries together, and the retry storm is
  worse than the original outage.
- **`Retry-After` replaces the backoff curve.** If the server tells you when to come back,
  your backoff curve is an opinion and theirs is a fact. Both forms RFC 9110 allows are
  parsed: delay-seconds and HTTP-date. The one exception is that the wait is capped at the
  retry policy's `MaxDelay` (5s by default), so a server asking for a minute cannot eat the
  whole `-timeout`. The cost is that an early retry may simply get another 429.
- **A client-side rate limiter** bounds outbound requests regardless of what the server
  advertises, so a bug in a loop cannot turn into an accidental denial of service.
- **Typed errors.** `*APIError` carries the status and the API's own `message`, and unwraps to
  sentinels, so callers write `errors.Is(err, tailscale.ErrNotFound)` instead of matching
  strings. The CLI uses that to turn a 401 into "the token was rejected — check it has not
  expired" rather than printing a status code at you.
- **Every body drained and closed**, including the discarded bodies of retried attempts, so
  connections go back to the pool instead of leaking.
- **Bounded reads.** Response bodies are decoded through an `io.LimitReader`; a wedged proxy
  should not be able to exhaust memory.
- **Tolerant time parsing.** An empty timestamp decodes to the zero time instead of failing
  the response. One odd field on one device should not cost you the other two hundred.
- **OAuth tokens are fetched with the caller's context.** oauth2's own HTTP transport fetches
  tokens with a context fixed when the client is built, so cancelling a call would not stop a
  hung token request. Instead the client fetches the token itself inside each attempt, with
  that call's context, and caches it until it nears expiry. The token request then falls
  under the same retry rule as everything else: 429, 5xx and network failures retry; a
  rejected client does not.
- **Credentials never appear** in a log line or an error message: not the API token, not the
  OAuth client secret. There are tests that fail if either ever does.
- **No base-URL flag.** The API root is not configurable from the command line, because a
  flag that redirects an authenticated client at an arbitrary host is a token-exfiltration
  primitive. The tests point the client at `httptest` through a `WithBaseURL` option, which
  lives in an `internal` package, so no code outside this module can call it.

## Tests

```sh
go test ./... -race
```

66 cases; coverage is 83.5% of `internal/audit` and 81.1% of `internal/tailscale`. Every
test runs against `httptest.NewServer` — nothing touches the network, and there is no
recorded-fixture replay to go stale.

The suite is weighted towards the failure paths, because those are the ones nobody exercises
by hand: 401/403/404 mapping to sentinels, a 429 with `Retry-After` honoured, retry
exhaustion, a 500 that succeeds on the second attempt, a 400 that must *not* be retried,
cancellation mid-flight, a truncated body, an unknown server-side field that must not break
decoding, and a token-leak check on the error string. The OAuth tests do the same for the
token endpoint: a rejected client not retried, a 503 retried, a dropped connection retried,
cancellation reaching an in-flight token request, and the client secret kept out of errors.
Backoff is asserted through an injected sleep, so the timing behaviour is tested without the
suite paying for it in wall-clock time.

The `cmd` package is deliberately thin — flag parsing, wiring, and exit codes. Only its
credential selection is unit-tested; the rest is smoke-tested.

## How this was built

I asked a coding agent (Claude Code) to build a small Go tool against a public API, and chose
the Tailscale API. In one session the agent wrote [`SPEC.md`](SPEC.md) first, then the code
and tests from it, with build, `go vet`, `gofmt`, and the test suite as the gate before the
first commit. There was no separate review of that first version.

An earlier version of this section said a review had caught two bugs: a `Retry-After` value
that never reached the backoff, and a hand-rolled substring helper in the tests. No review
happened. The agent fixed both in its own first draft, seconds after writing them, and then
wrote this section as if a reviewer had found them. The same first README also said an API
access token could be read-only, which it can't. Both came out when I went back over the
work, and they are the most useful thing this project taught me about agent-generated code:
check what it says about itself as carefully as the code.

OAuth support came later. I implemented it over several review rounds with an AI assistant,
which proposed fetching tokens with the per-call context, wrote the OAuth test suite, and
tidied up the CLI's credential handling. The commit history says who wrote what.

## Limitations

- One API call, no pagination: `GET /tailnet/{tailnet}/devices` returns the whole tailnet in
  a single response today. If that ever changes this will need a cursor loop.
- A connection that drops while the token response is being read is not retried. oauth2
  reports that case with the cause formatted into a string rather than wrapped, so it cannot
  be told apart from a malformed response.
- No policy-file (ACL) analysis. Auditing an ACL properly means evaluating it, not pattern
  matching it, and that is a much larger project than this one.

Written against Tailscale's published OpenAPI document, read 2026-09-22.

## Licence

MIT — see [LICENSE](LICENSE).
