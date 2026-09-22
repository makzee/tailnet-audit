# tailnet-audit — specification

Written before any code. The implementation was produced with a coding agent working from
this document; the spec is the contract the tests check against, and it is committed so the
review trail is visible. See README "How this was built".

## Problem

The Tailscale admin console shows you a tailnet's devices. It does not nag you about the
things that quietly rot: a node whose key expired last week, a subnet route someone
advertised that nobody ever approved, a laptop last seen in March, a device sitting
unauthorized while device approval is on.

`tailnet-audit` reads a tailnet through the Tailscale API and reports those findings, with an
exit code you can gate CI or a cron job on.

**Read-only by construction.** The tool issues `GET` requests only. It has no code path that
mutates a tailnet, and the API token it needs carries the `devices:core:read` OAuth scope.

## Scope

In scope:

- List devices for a tailnet via `GET /api/v2/tailnet/{tailnet}/devices?fields=all`.
- Evaluate a fixed set of posture rules (below) against each device.
- Emit a table (human) or JSON (machine) report.
- Exit non-zero when findings reach a configured severity.

Out of scope, deliberately: writing to the API, the policy-file (ACL) endpoints, OAuth
client-credential exchange (a personal access token is enough for a read-only auditor),
persistence, and any kind of daemon mode.

## API contract

Source of truth: Tailscale's published OpenAPI document
(`https://api.tailscale.com/api/v2?outputOpenapiSchema=true`), read 2026-09-22.

- Base URL `https://api.tailscale.com/api/v2`.
- Auth: HTTP bearer — `Authorization: Bearer <token>`.
- `GET /tailnet/{tailnet}/devices` returns `{"devices": [Device, ...]}`.
- The path segment `-` means "the default tailnet of the access token", and is the default.
- `?fields=all` is required: the `default` field set omits `lastSeen`, `expires`,
  `keyExpiryDisabled`, `authorized`, `tags`, and the route fields, which is most of what
  this tool reasons about.
- Errors are `{"message": "..."}` with a meaningful HTTP status.
- Timestamps are RFC 3339. `expires` is the zero time when key expiry is disabled.

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `unauthorized` | critical | `authorized` is false — device approval is on and this node is waiting, or was never approved |
| `key-expired` | critical | key expiry is enabled and `expires` is in the past |
| `tailnet-lock-error` | critical | `tailnetLockError` is non-empty |
| `key-expiring-soon` | warn | key expiry is enabled and `expires` is within the warning window |
| `device-stale` | warn | `lastSeen` is older than the stale window |
| `routes-unapproved` | warn | a route in `advertisedRoutes` is absent from `enabledRoutes` |
| `key-expiry-disabled` | warn | `keyExpiryDisabled` is true **and** the device is untagged |
| `update-available` | info | `updateAvailable` is true |

`key-expiry-disabled` deliberately ignores tagged devices: tagged nodes are servers and
Tailscale does not require key renewal for them, so flagging those is noise. Untagged devices
with expiry switched off are a real posture gap and stay flagged.

## Client requirements

These are the point of the project — the calls themselves are three lines.

- `context.Context` is the first parameter of every exported call. Cancellation must
  interrupt an in-flight request *and* a pending retry sleep.
- Retries: at most `MaxAttempts`, only for HTTP 429, HTTP 5xx, and transport errors.
  Never retry a 4xx that is not 429. Never retry once the context is done.
- Backoff is exponential with **full jitter** — `sleep = rand[0, min(maxDelay, base*2^n))` —
  so a fleet of callers does not resynchronise into a thundering herd.
- A `Retry-After` header, in either seconds or HTTP-date form, overrides the computed backoff.
- A client-side rate limiter bounds outbound requests regardless of what the server says.
- Every response body is drained and closed on every path, including the discarded bodies of
  retried attempts, so connections return to the pool.
- Errors are typed: `*APIError` carrying the status and the API's `message`, unwrapping to
  sentinels (`ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`, `ErrRateLimited`) so callers
  use `errors.Is` rather than matching strings.
- The token must never appear in a log line or an error message.
- Time parsing tolerates an empty string as the zero time rather than failing the whole
  response — one unexpected field should not cost you the other 200 devices.

## CLI

```
tailnet-audit [flags]

  -tailnet string     tailnet to audit (default "-", the token's own tailnet)
  -stale-after        flag a device not seen in this long (default 720h)
  -expiry-within      warn when a key expires within this long (default 336h)
  -format             "table" or "json" (default "table")
  -fail-on            "critical", "warn", "info", or "never" (default "critical")
  -timeout            overall deadline for the run (default 30s)
  -v                  debug logging to stderr
```

The token is read from `TAILSCALE_API_KEY`. It is never accepted as a flag, because flags
land in shell history and in the process table.

Exit codes: `0` clean, `1` findings at or above `-fail-on`, `2` operational failure (bad
token, network, cancelled).

## Testing

Every test runs against `httptest.NewServer`; no test touches the network. The failure paths
are the ones worth testing, so the suite covers: 401/403/404 mapping to sentinels, a 429 with
`Retry-After` honoured, retry exhaustion, a 500 that succeeds on the second attempt, a
non-retryable 400, context cancellation mid-flight, and a malformed JSON body. Rules are
table-driven against a fixed `now` injected through the config.
