---
title: Usage
summary: What each request records, how usage and cost are read from responses, the hourly metrics, and exports.
---

# Usage

Every request that reaches a service's host through Keystub is recorded once, after it finishes.

## What is recorded

| Field | Example |
| --- | --- |
| Time | `2026-10-31T14:36:33Z` |
| Project, environment | `my-app`, `my-app/dev` |
| Token id and name, principal | `tk_…`, `wt-jepsen` |
| Service, method, host, path | `openai`, `POST`, `api.openai.com`, `/v1/chat/completions` |
| Status, and Keystub's note when it answered itself | `429`, `daily limit reached for token ci` |
| Duration, and Keystub's own time before going upstream | `956 ms`, `0 ms` |
| Operation and model | `chat`, `gpt-6-sol` |
| Outcome | `ok`, `key_rejected`, `rate_limited`, … (see below) |
| Usage | input, cached and cache-write tokens, output tokens, or the service's own units |
| Cost | `costMicros`: US dollars × 10⁶ |
| Upstream quota left | requests and tokens, from the service's rate-limit headers |

Never recorded: headers, query strings, request or response bodies. No key or token can end up in the log. Usage is read from the body as it streams past (below), and only the numbers and the model name are kept.

## Reading usage from responses

Each catalog service with `usage` metadata ([catalog](catalog.md#usage-metadata)) is metered on its way back to the client, by the proxy and the edge alike:

- **Never buffered.** JSON and server-sent events are scanned byte by byte for a few paths. The scanner holds one key or value at a time (64 and 128 bytes at most), so memory doesn't grow with the body, and every byte is relayed as soon as it arrives. Past 64 MiB a body isn't read any more.
- **Streams.** For server-sent events each event's data is its own JSON document; the last value seen wins, so the final usage event counts. Gemini's JSON-array stream works the same way.
- **Compression.** Keystub asks metered services for gzip or no compression (it keeps only `gzip` and `identity` in `Accept-Encoding`, dropping `br`, `zstd`, `deflate`, `compress` and `*`), and reads gzip as it passes. The client gets the gzipped bytes unchanged.
- **Only successful responses** are read for usage; headers (quota, outcome) are read on every response. A `GET` the catalog doesn't list as an operation isn't read: fetching a stored response (`GET /v1/responses/{id}`) or polling a job returns usage already counted. Nor is a request below a listed operation's path (`POST /v1/chat/completions/{id}` updates a stored completion and returns its usage again). Other unlisted requests (an image, a transcription) are read, with no operation name. Paths are matched after `.` and `..` are resolved.
- **Errors inside a 2xx.** A body or stream that reports a failure after a 200 (a top-level `"error": {…}` object, or an `error` or `response.failed` event, as Anthropic's `overloaded_error` mid-stream) is `upstream_error`; tokens it reported before failing still count.
- **Request body.** Where a service only names the model in the request (Cohere), the JSON request body is scanned the same way as it is sent.

What each event means:

| Field | Meaning |
| --- | --- |
| `usage.inputTokens` | Every input token: cached reads and cache writes included |
| `usage.cachedTokens`, `cacheWriteTokens` | The parts of the input read from and written to the prompt cache |
| `usage.outputTokens` | Output, reasoning included (added in where the service counts it apart, as xAI and Gemini do) |
| `usage.units` | The service's own unit where it doesn't count tokens (Cohere's search units) |
| `costMicros` | The service's own figure when it sends one (OpenRouter, Vercel AI Gateway, xAI, Perplexity's Agent API), else list prices from `catalog/pricing.json`; absent when neither is known |

Outcomes:

| Outcome | When |
| --- | --- |
| `ok` | 1xx–3xx from the service |
| `key_rejected` | The service answered 401: **the real key was rejected** (revoked, rotated, wrong). The Requests page says so |
| `rate_limited` | The service answered 429 |
| `upstream_error` | 5xx from the service, a status the catalog maps there (Groq's 498), or a 2xx whose body or stream reports an error |
| `client_error` | Any other 4xx from the service |
| `unreachable` | The service couldn't be reached |
| `refused` | Keystub answered itself: no or bad token, a limit, no saved key linked |
| `canceled` | The client went away before the service answered |

The edge marks a response it wrote itself with `Keystub-Outcome: refused` (or `unreachable`), and drops that header from services' responses. An agent forwarding to the edge logs that outcome instead of reading the edge's 401 or 429 as the service's.

Known gaps, from the providers' docs:

- OpenAI chat streams carry usage only with `stream_options.include_usage`; DeepSeek, Mistral and xAI streams likewise. Without it the event has the model and outcome but no tokens.
- Cache writes are priced at the default TTL (OpenAI 30 minutes, Anthropic 5 minutes); longer-lived writes cost more.
- Anthropic's server-side fallback bills every attempt (`usage.iterations`); Keystub counts the attempt that answered.
- Gemini's Interactions API and its tool-use prompt tokens aren't counted yet; whether Interactions input includes cached tokens isn't documented.
- DeepSeek's off-peak half price is modelled by hour and weekday, not Chinese public holidays.
- Gemini's `400 API_KEY_INVALID` isn't told apart from other 400s.
- A failure reported as a string (`{"error": "…"}`) inside a 2xx isn't recognised; only an `"error"` object or an `error` / `response.failed` event is.
- A request that bills units the price list has no unit price for (Cohere rerank's search units) is counted as `unpriced`, not $0.

Tunnelled traffic (hosts that aren't services) isn't recorded. A request refused before Keystub knows the service (a `/h` host not in the catalog) isn't either.

## Where it is kept

| Storage | Where | Kept for |
| --- | --- | --- |
| `--storage json` | `requests.jsonl`, plus the last 1,000 in memory for the dashboard | Rotated to `requests.jsonl.1` at 10 MB |
| `--storage sqlite` | The `events` table in `keystub.db` | 30 days |

The Requests page shows the latest 200 and refreshes every 5 seconds.

## Hourly metrics

One table, `metrics_hourly`, with the same columns self-hosted (SQLite) and hosted (with an account first in the key):

- **Key:** hour, project, environment, token, service, model, operation, saved key.
- **Counts:** requests; one column per outcome; input, cached, cache-write and output tokens; units; `cost_micros`; `unpriced` (requests with usage but no known price).
- **Latency:** `duration_ms_sum`, `overhead_ms_sum` (Keystub's own time, for requests that went upstream), and a histogram, `lat_10` … `lat_60000` and `lat_inf` (upper bounds in ms). p50 and p95 are estimated from it, interpolating within a bucket.

Every column adds, so each request is one upsert, and rows from several data planes or hours merge by summing.

- **`--storage sqlite`:** the rows are written in the same transaction as the event (a failed metrics write never loses the event), hourly rows are kept 400 days, and `metrics_total` keeps the same counts by every dimension but the hour, forever. A database from before hourly metrics is rolled up from its events once; metrics tables from another version are migrated in place (columns added, rows copied), never dropped. The usage page and `/metrics` read on their own read-only connections, so a big read never holds up the request path.
- **`--storage json`:** the rows live in memory, rebuilt at start from the two files kept (`requests.jsonl` and `requests.jsonl.1`, about 20 MB of entries), so a restart can shorten the history shown. Hours older than 400 days are dropped as new entries come in.

The Usage page shows requests over time and a table by service, model, token, environment, project or operation (the export and API also group by saved key), for the last 24 hours or the last 7 or 30 UTC days (today included), in one environment or all. Hours and days are UTC.

## Export

| Route (dashboard, admin token) | What |
| --- | --- |
| `GET /usage/export?format=csv&range=7d` | Hourly rows with every dimension (the saved key's ID in the last column, `key`), the token's name, cost in dollars, p50, p95, mean latency and Keystub's mean time. `by=service,model` groups instead; `in=<env>` filters |
| `GET /usage/export?format=json&…` | The same as `{"rows": [...]}` |
| `GET /metrics` | Prometheus text format: `keystub_requests_total{…,outcome}`, `keystub_tokens_total{…,kind}`, `keystub_units_total`, `keystub_cost_usd_total`, `keystub_request_duration_seconds` (histogram) and `keystub_overhead_seconds_total`, labelled by project, environment, service, model and operation. Counters that only go up: all time with SQLite (`metrics_total`), since start with the file log |

Prometheus scrapes `/metrics` with the admin token as a bearer token (`authorization: {credentials: <token>}`); it's off unless something scrapes it. CSV cells that a spreadsheet would run as a formula start with `'`.

## Hosted

The hosted edge meters with the same catalog metadata and prices and passes the same `conformance/usage.json`. The hosted dashboard's Usage page and exports read the same `metrics_hourly` rows, with an account first in the key.
