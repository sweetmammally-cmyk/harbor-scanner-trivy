# Calling the scanner from a Temporal activity

For the backend team. The scanner's direct scan API (`/api/v2`) scans one image tag and keeps one result per tag. This guide shows how a Temporal activity should call it, which answers to retry, and how to read the result. A complete, tested example is in [integration/](integration/) (Go, Temporal Go SDK): `scanactivity.go` and its test.

## The calls

All calls send `Authorization: Bearer <token>` (the scanner's `SCANNER_V2_AUTH_TOKEN`).

1. `POST /api/v2/scans` with the image (`repository`, `name`, `tag`), `customer_ids`, `platforms` (Trivy result types such as `npm`, `jar`, `debian`) and optional `severity`, `max_db_age`, `force`, `customer_data`, `request_id`.
2. When the answer is a scan id without a result (202, or 200 with state `queued`/`scanning`), poll `GET /api/v2/scans/{scan_id}`, waiting the number of seconds in `Retry-After` between polls.
3. Stop when the state is `done` (the result is in the body) or `failed`.

The `scan_id` is fixed per image tag. Sending the same request again (for example after an activity retry) finds the scan that is already queued or running, or answers from the cache. No separate idempotency key is needed. `request_id` is only a correlation id for the scanner's logs (1-128 characters of `A-Za-z0-9._:-`); the example builds it from the workflow id and the activity id.

## What to do with each answer

| Answer | Meaning | Activity |
|---|---|---|
| 202 | New scan queued | Poll |
| 200, `state: done` | Result (from the cache when `cached: true`) | Return it |
| 200, `state: queued` or `scanning` | The same scan is already running | Poll |
| 409 `scan_in_progress` | Another scan of this tag (other digest or wider scope) is running | Wait `Retry-After` (5 s), POST again |
| 429 `queue_full` or `too_many_requests` | The scanner is busy | Wait `Retry-After`, POST again |
| 503 `not_ready`, `store_unavailable`, `registry_unavailable` | Starting up, MongoDB down, Harbor unreachable | Wait `Retry-After`, POST again |
| 400 `invalid_request` | Bad input | Fail, do not retry |
| 401 `unauthorized` | Wrong token | Fail, do not retry |
| 404 `image_not_found` | The tag is not in Harbor | Fail, do not retry |
| 502 `registry_auth_failed` | The scanner's robot account is refused by Harbor | Fail, do not retry (an operator must fix it) |
| Other errors, network errors | | Return a retryable error; Temporal retries the activity |

While polling: `queued`/`scanning` comes with `Retry-After: 2`. A `404` means the scan is gone (for example the database was reset): return a retryable error, the retry POSTs again.

Each wait records a heartbeat, so Temporal can tell a long scan from a dead worker.

## Reading the result

- `done`: the body has `summary` (counts per severity for the requested platforms), `vulnerabilities` (the requested platforms and severities), `platforms_found`, `platforms_not_found` (requested but not in the image: not a clean result), `has_more_platforms`, and the `db` block.
- `db.freshness` is `stale` when the scanner's vulnerability DB was not confirmed fresh within `max_db_age`. The result is valid but may miss the newest vulnerabilities. The example sets `Stale: true`.
- `failed` with a `previous` block: the newest scan failed, but the tag has an earlier good result (`previous.digest`, `previous.summary`, `previous.confirmed_at`). Treat it as a stale result: the example returns it with `Stale: true` and the `FailureClass`.
- `failed` without `previous`: there is no result. The example returns a Temporal application error whose type is the failure class, so the workflow's retry policy decides.

Failure classes: `trivy_timeout`, `trivy_exit_error`, `output_too_large`, `output_invalid`, `db_missing`, `java_db_missing` (the image has Java files and the scanner has no Java DB), `platform_not_found` (no manifest for the scanner's platform), `worker_lost`, `internal_error`. Retrying `platform_not_found` and `java_db_missing` does not help until the image or the scanner's configuration changes.

## Activity options

```go
options := workflow.ActivityOptions{
	// Queue wait plus one scan; the scanner kills a scan after SCANNER_SCAN_TIMEOUT (default 10m).
	StartToCloseTimeout: 30 * time.Minute,
	// The activity heartbeats on every wait (at most every Retry-After, a few seconds).
	HeartbeatTimeout: time.Minute,
	RetryPolicy: &temporal.RetryPolicy{
		InitialInterval:    5 * time.Second,
		BackoffCoefficient: 2,
		MaximumInterval:    time.Minute,
		MaximumAttempts:    5,
		NonRetryableErrorTypes: []string{
			"invalid_request", "unauthorized", "image_not_found", "registry_auth_failed",
			"platform_not_found", "java_db_missing",
		},
	},
}
ctx = workflow.WithActivityOptions(ctx, options)
var scanner *scanactivity.Scanner // nil: only names the activity
var outcome scanactivity.ScanOutcome
err := workflow.ExecuteActivity(ctx, scanner.ScanImage, input).Get(ctx, &outcome)
```

Register the activity on the worker with the scanner's base URL and token from your secret store:

```go
scanner := &scanactivity.Scanner{BaseURL: "http://scanner:8080", Token: token, HTTP: &http.Client{Timeout: 70 * time.Second}, MaxWait: 30 * time.Second}
w.RegisterActivity(scanner.ScanImage)
```

The HTTP timeout must be longer than one POST: the scanner resolves the tag in Harbor during the POST (up to two registry tries).

## The example

`integration/` is its own Go module (so the scanner does not depend on the Temporal SDK). `workflow_test.go` holds the workflow side above and runs it with a mocked activity. `scanactivity_test.go` runs the activity in Temporal's test environment against a fake scanner: 409 then 202 then polling until done; a cache hit; `image_not_found` not retried; `failed` with `previous` returned as stale; `failed` without `previous` as a retryable error named by its class.

```
cd docs/direct-scan/integration && go test ./...
```
