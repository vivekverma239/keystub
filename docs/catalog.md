---
title: Catalog
summary: The shared list of services, its fields, and how to add a service.
---

# Catalog

`catalog/services.json` lists the services Keystub knows. Every Keystub implementation reads the same file, so a service behaves the same self-hosted and hosted. The dashboard adds a catalog service in one click; it can be edited afterwards like any other.

## Fields

| Field | Required | What it does |
| --- | --- | --- |
| `id` | Yes | Lowercase slug: `a-z`, `0-9`, `-`, `_`. Used in `/s/<id>/…` |
| `name` | Yes | Shown in the dashboard |
| `hosts` | Yes | Host names the key may be sent to. `*.example.com` covers subdomains only, not `example.com` itself. Only letters, digits, dots and dashes |
| `auth.header`, `auth.format` | No | The service's own auth header and how to write the key in it, e.g. `x-api-key` / `{key}`. Default `Authorization` / `Bearer {key}` |
| `baseUrl.var`, `baseUrl.path` | No | The SDK's base-URL variable and the path it expects after the host, e.g. `OPENAI_BASE_URL` with `/v1`. Needed for quick start; also needs a host that isn't a wildcard. An agent or `--token` takes it only for a built-in service |
| `envVars` | No | Variables `keystub run` sets to the proxy token. `NAME=template` fills `{key}` (or `{key_compact}`, the dash-free form) into a shaped key, e.g. `CONVEX_DEPLOY_KEY=prod:my-app\|{key}` |
| `category`, `docs`, `note` | No | For display and for whoever edits the file |
| `statusPage` | No | The provider's status page, linked when a request fails upstream |
| `usage` | No | How to read usage, cost and outcome from responses; see below |

The loader rejects a bad entry at start-up, and `catalog/catalog_test.go` checks the whole file.

## How the auth header is used

The proxy token is swapped for the real key only in `Authorization` and in the service's own `auth.header`. A token in any other header refuses the request, because a service might store that header and return the real key later. So `auth.header` must be the header the service really reads the key from; a wrong one makes Keystub refuse requests that put the token there.

When a request carries no token in those headers, Keystub writes `auth.header: auth.format` itself.

## Adding a service

1. Check the provider's API docs for the hosts, the auth header and its format, the variable its SDK reads the key from, and any base-URL variable.
2. Add an entry to `catalog/services.json`, with `docs` pointing at the page you checked.
3. For an API that reports usage, add `usage` metadata and cases in `conformance/usage.json`, and prices in `pricing.json`, each checked against the provider's docs.
4. Run `go test ./catalog/ ./internal/swap/ ./internal/usage/`.

A service the catalog doesn't have can still be added on the dashboard with a name and hosts (and its header, if it isn't `Authorization`).

## Not in the catalog yet

Services whose auth doesn't fit one key in one header:

| Service | Why |
| --- | --- |
| Fly.io | Newer tokens use the `FlyV1` scheme and older ones `Bearer`, chosen by the token's prefix |
| Datadog | Most calls need two secrets, an API key and an application key, in two headers |
| Railway project tokens, Postmark account tokens, GitLab CI job tokens | A second token type in its own header; the catalog entry covers the main token type |

## Usage metadata

`usage` tells every data plane how to meter a service's responses ([usage](usage.md)). The LLM services have it: OpenAI, Anthropic, Gemini, Groq, Mistral, OpenRouter, Vercel AI Gateway, DeepSeek, Z.AI, xAI, Together, Fireworks, Cohere and Perplexity.

| Field | What it does |
| --- | --- |
| `operations` | `{name, method, path}`: names a request. `{model}` matches within one segment (up to `/` or `:`), `*` one segment, a trailing `/**` the rest |
| `model` | A term for the model name |
| `input`, `cached`, `cacheWrite`, `output`, `units` | Lists of terms, added up. `input` counts every input token, cache included; `output` includes reasoning |
| `unitName` | What `units` counts, e.g. `search units` |
| `cost`, `costPerUsd` | A term for the request's cost as the service reports it, and how many of its units make a dollar (xAI: 10¹⁰ ticks). It wins over list prices |
| `status` | Statuses whose outcome isn't the default (`"498": "upstream_error"`); keys like `403` or `5xx` |
| `quota.requests`, `quota.tokens` | Response headers with the requests and tokens left |

A **term** is alternatives separated by `|`; its value is the first alternative, in the order written, that was seen, and each alternative keeps the last value seen. An alternative is a dotted JSON path into the response body or each event's data (`usage.prompt_tokens`; arrays don't add to a path), `request:<path>` for the request body, `header:<name>` for a response header, or `path:model` for the operation's `{model}`. Paths go 8 levels deep at most, and a key spelled with escapes never matches. `request:` and `path:` alternatives count only when the service answered 2xx: they're the client's words, and a made-up model name the service refused shouldn't become a metrics row.

For example, Anthropic counts cache reads and writes apart from input, and streams input in `message_start` and output in `message_delta`:

```json
"input": [
  "usage.input_tokens|message.usage.input_tokens",
  "usage.cache_read_input_tokens|message.usage.cache_read_input_tokens",
  "usage.cache_creation_input_tokens|message.usage.cache_creation_input_tokens"
]
```

`conformance/usage.json` pins down what each service's metadata must read, response by response; check a change with `go test ./internal/usage/`.

## Pricing

`catalog/pricing.json` lists prices per service, in US dollars per million tokens:

| Field | What it does |
| --- | --- |
| `models` | API model names as the service returns them; `name*` covers names starting with `name` (dated snapshots). An exact name wins, then the longest pattern |
| `effective` | The first UTC day the price applies. Of a model's entries the latest effective on or before the request wins; the earliest also covers earlier requests |
| `input`, `cachedInput`, `cacheWrite`, `output` | Prices; cached and cache-write default to `input` |
| `unit` | Price per unit, for `units` |
| `above` | A long-context tier: prices for requests whose input passes `inputTokens` |
| `offPeak` | A discount `factor` outside `peakWeekdays` (0 Sunday) and `peakHoursUtc` (`[start, end)`) |
| `source`, `checked` | The pricing page and the day someone read it. Required |

A model with no entry has no cost unless the service reports one. Accounts may override prices later; the file is the default.
