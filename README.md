# Keystub

Keystub keeps real API keys out of your processes. A command gets a proxy token (`sk-stub-…`) instead, and Keystub swaps in the real key on the way out, only for that service's host. It runs as a local or self-hosted server with a proxy, an edge for quick start, and a dashboard. How it works and why: [docs/](docs/README.md).

Keystub was called Stubkey. Installs from then keep working: `STUBKEY_*` variables are still read when the `KEYSTUB_*` one is unset, an existing `~/.stubkey` folder and `stubkey.db` are used in place, the old Keychain items move to their new names on first use, and edges still accept the old `Stubkey-Token` header. Proxy tokens keep their `sk-stub-` form.

## Model

```
Saved keys ◄── link per service ── Environment ── Project
                                       └── proxy tokens
```

- A **project** holds environments, e.g. `my-app/dev`, `my-app/prod`. A fresh install has `default/dev`.
- A **saved key** is a service's real key, with a name, saved once. Each **environment** links one saved key per service, so `dev` can use a Stripe test key and `prod` a live one, or dev and staging can share one OpenAI key that is rotated once for both.
- A **proxy token** belongs to exactly one environment: an *environment token* may use every service linked there, a *service token* only one. It can have a daily and per-minute limit, and a lifetime. Give each worktree, sandbox or CI job its own, and revoke it when done.
- **Limits apply at every level**: a request must fit its project's, its environment's, its token's, and its saved key's if it has one. A refused request uses up nothing.
- Each request is logged with its project, environment, token and saved key, and for LLM services its model, tokens, cost and outcome, read from the response as it streams; hourly metrics export as CSV, JSON and Prometheus ([usage](docs/usage.md)).

```bash
go install github.com/vivekverma239/keystub/cmd/keystub@latest   # or, in a clone: go build -o "$(go env GOPATH)/bin/keystub" ./cmd/keystub
keystub serve                  # prints the dashboard link with its admin token
```

Open the printed link, add a service (OpenAI, Anthropic, GitHub, Stripe, Resend, Cloudflare, Vercel, or any name and hosts), and paste its real key (it's saved and linked into `default/dev`). Then:

```bash
keystub run -- npm run dev                      # this worktree's token in default/dev
keystub run --env my-app/prod -- node server.js
```

Quick start, with no proxy or CA, for SDKs that take a base URL (OpenAI, Anthropic):

```bash
eval "$(keystub env --direct)"   # OPENAI_BASE_URL=http://127.0.0.1:8789/s/openai/v1, OPENAI_API_KEY=sk-stub-…
```

For a sandbox or CI job, create a token on the Tokens page (a service token for one service, or an environment token), limits and a lifetime, and give it that token. The box then needs no server and holds no real keys:

```bash
export KEYSTUB_TOKEN=sk-stub-…                                  # keeps it out of `ps`
keystub run --remote https://keystub.example.com -- npm test    # a private agent for this command
```

On a dev box that should hold no keys, run only the agent, against a self-hosted `keystub serve` (its edge, behind TLS) or the hosted edge, and point commands at it:

```bash
export KEYSTUB_TOKEN=sk-stub-…
keystub agent --remote https://keystub.example.com
keystub run -- npm run dev
```

To skip `--token` on a dev box, link it once. An admin types the code it shows on the dashboard's Machines page, checks which machine it is, and picks the environments it may use (any program running as you on the box can use those, so tick production with care); after that, `keystub run` gets each worktree its own token from the server, and revoking the machine there stops them all:

```bash
keystub link https://keystub.example.com
keystub run -- npm run dev
```

The agent decrypts the hosts the edge's catalog lists for its token (services linked in its environment) that Keystub's built-in catalog also gives that service (a built-in service's host only ever as that service), and forwards each request to the edge's `/h` route, which checks the token and swaps the key. A custom service's hosts are decrypted only if the box allows them: `keystub agent --allow-host api.internal.example`, or `$KEYSTUB_ALLOW_HOSTS` (comma-separated, also for `run --remote`). A built-in service's own server, such as a self-hosted GitLab, is given by name: `--allow-host gitlab=gitlab.corp.example`, and is then GitLab's alone; a plain allowed host is only ever a custom service's, so the edge can't file it under GitHub and have `GH_TOKEN` set. The box's own credentials in auth headers never reach the edge: a request with no proxy token stays on the box (401), and so does one whose `Authorization` (or the service's own auth header) carries a real credential besides the token (400), so a tool that sends its own key up front (npm with a real `_authToken`, say) is refused rather than forwarded. Other headers, such as cookies, go to the edge with the request. The edge can't set what a command's environment holds: a built-in service's variables come from Keystub's catalog, and a custom one gets only key variables (`FOO_KEY`, `FOO_TOKEN`…) that no built-in service reads, and no base URL, so `--direct` against a remote edge covers built-in services only. `run --token` and `env --token` read any server's catalog this way, the box's own `keystub serve` included, so a custom service there that sets `OPENAI_API_KEY` (for a gateway, say) gets it only without `--token`. The remote must be `https://`, or `http://` on loopback. Pass the token in `$KEYSTUB_TOKEN` rather than `--token`, which other users of the box can see in `ps`.

Keys with a shape that a CLI reads on the box can use a template in the service's env vars, for example `CONVEX_DEPLOY_KEY=prod:my-app|{key}`. `{key_compact}` is the same key without dashes (`skstub…`), for CLIs that reject `-` in a token; the Vercel preset uses it.

For every shell in a repo, add this line to `.envrc` (direnv):

```bash
eval "$(keystub env)"
```

## The CLI

The same commands manage a self-hosted `keystub serve` and the hosted service. On the box running `keystub serve` they need no setup; elsewhere, `keystub login` (hosted) or `KEYSTUB_API_KEY` together with `KEYSTUB_SERVER` (the key is never sent to a server that wasn't named). `--server URL` (or `$KEYSTUB_SERVER`) picks the server, `--json` gives JSON, and `keystub help agents` prints a guide for coding agents ([docs/llms.txt](docs/llms.txt)).

```bash
keystub services add openai
printf %s "$OPENAI_KEY" | keystub keys add openai --name team # the value comes from stdin, never an argument
keystub envs add my-app/dev
keystub envs add my-app/staging
keystub envs link my-app/dev openai team                     # prints a new service token, once
keystub envs link my-app/staging openai team --no-token
printf %s "$NEW_KEY" | keystub keys replace team              # both environments use it now
keystub tokens create my-app/dev --name ci --ttl 7d --json | jq -r .token
```

A project's `.env` file can be moved over the same way, by name, without a value on screen: `keys scan` lists the variables a service reads, `--env-file` reads a key from the file, and `--write-env` writes a new token into it (never printing it), with `--base-urls` for SDKs that take one.

```bash
keystub keys scan .env
keystub keys add openai --name team --from-env OPENAI_API_KEY --env-file .env
keystub tokens create my-app/dev --name local --write-env .env --base-urls
```

Limits are set per level, and a level you don't name keeps its value: `keystub projects limits my-app --daily 10000`, `keystub envs limits my-app/prod --per-minute 60`, `keystub keys limits team --daily 5000`, or `--clear`.

Exit codes: 0 ok, 1 error, 2 usage, 3 not signed in, 4 not found, 5 conflict. The API it calls is in [protocol/api.md](protocol/api.md).

## The skill for coding agents

[`skills/keystub/`](skills/keystub/SKILL.md) is an [Agent Skill](https://agentskills.io): a `SKILL.md` folder that teaches Claude Code, Codex, Cursor and other agents to move a project's keys into Keystub with the CLI alone. `keystub keys scan .env` finds the keys by name, `keys add … --from-env VAR --env-file .env` saves each one from the file, and `tokens create … --write-env .env --base-urls` puts a token where the keys were, so the agent sees neither a key nor the token. Its rules: no key's value in an argument or on screen, `--json` everywhere, and the user asked before anything is deleted. Its command guide, `references/cli-guide.md`, is a copy of [docs/llms.txt](docs/llms.txt), and the tests check that the two match and that every `keystub` command line in either one parses with the CLI.

Install it in any of these ways.

| Agent | Install | Check it loaded |
| --- | --- | --- |
| Any, from the binary | `keystub skill install` writes `~/.claude/skills/keystub` and `~/.agents/skills/keystub`. `--agent claude\|codex\|cursor\|agents` picks one, `--project` writes this folder's `.claude/skills` or `.agents/skills`, and `--dir DIR` writes `DIR/keystub`. | as below |
| Claude Code, as a plugin | `/plugin marketplace add vivekverma239/keystub`, then `/plugin install keystub@keystub`. From a clone: `claude plugin marketplace add <path to the clone>`. | `/plugin`, or ask "what skills do you have?" |
| Claude Code, as a skill | `keystub skill install --agent claude`. With the plugin installed, skip this (use `--agent agents` for the others), or Claude Code has the skill twice. | the same |
| Codex | `keystub skill install --agent codex` (`~/.agents/skills`, or `.agents/skills` with `--project`) | `/skills` |
| Cursor | `keystub skill install --agent cursor` (`~/.cursor/skills`) | Customize → Skills |
| [skills.sh](https://skills.sh) | `npx skills add vivekverma239/keystub --skill keystub`, with `-a claude-code`, `-a codex` or `-a cursor` to pick agents and `-g` for every project. From a clone: `npx skills add <path to the clone>`. | as above |

The Claude Code plugin is this repository: [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json) names it, and its `skills/` folder holds the skill. [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json) lists it with `"source": "./"`, so the plugin and its marketplace are the same repository.

## How it works

- `keystub run` asks the server for the token named after the git worktree's folder (or `--name`) in the chosen environment, creating it on first use. It sets `HTTPS_PROXY` to `http://keystub:<token>@127.0.0.1:8787`, sets every service's key variable (`OPENAI_API_KEY`, `GH_TOKEN`, …) to the token, and replaces itself with your command.
- The proxy ends TLS only for hosts that belong to a service, with a 24-hour certificate from the local CA. It finds the token in `Proxy-Authorization` or in an auth header (`Authorization`, or the service's own such as Anthropic's `x-api-key`; also inside Basic auth, as git sends it), checks the token and every limit, and swaps in that environment's real key where the token was, so `token …`, `Bearer …` and prefixed keys keep their shape. With no token in those headers, it writes the service's auth header (`Authorization: Bearer {key}` unless the catalog says otherwise). A token in any other header refuses the request, since a service might store that header (an idempotency key, say) and hand the real key back. The request goes on over a verified connection; responses stream through unbuffered, `Expect: 100-continue` is answered at once, and websockets work.
- Every other host is tunnelled untouched. `localhost` and `127.0.0.1` skip the proxy, so local dev servers work as usual. When the proxy listens on anything but loopback, every connection, tunnels included, must carry a live token, and tunnels and plain HTTP can't reach loopback, private, link-local, carrier-grade NAT (Tailscale) or NAT64 addresses (the server's own dashboard, a cloud metadata service).
- The edge (`127.0.0.1:8789`) answers `/s/<service>/…` for quick start, and `/h/<host>/…` and `/catalog` for agents; see [protocol/](protocol/README.md). It speaks plain HTTP, so put TLS in front of it before exposing it.
- Real keys and proxy tokens are encrypted with envelope encryption (AES-256-GCM, a key per value, wrapped by a master key). Real keys can't be read back through the dashboard or the API.
- The master key lives in the macOS Keychain on a Mac, in `$KEYSTUB_MASTER_KEY` (64 hex characters, e.g. a Fly secret) on servers, or in a `master.key` file as a last resort. `--secrets auto|keychain|env|file` picks; `auto` is the default. An old `master.key` moves into the Keychain on first start and the file is deleted.
- The request log keeps method, host, path, status, duration and Keystub's own time. It never records headers, query strings or bodies.

Data lives in `~/.keystub` (or `$KEYSTUB_HOME`). An agent keeps its CA (`ca.pem`, `ca-key.pem`, `ca-bundle.pem`, and an empty `ca.lock`) and `agent.json` (where it listens and what it decrypts) there, and no keys. A linked box adds `machine.json` (its server, ID and environments; the credential too when it isn't in the Keychain). A server adds `admin.token`, and either `state.json` plus `requests.jsonl` (`--storage json`, the default) or one `keystub.db` (`--storage sqlite`, which also keeps limit counts across restarts and imports an existing `state.json` on first start). Stage 0 `state.json` files are migrated into `default/dev`, and the old one is kept as `state.json.v1`. Data from before saved keys is converted on first start (`state.json.v2` is kept): each real key becomes a saved key named `<env> <service>`, linked where it was; see [the model](docs/model.md#data-from-before-saved-keys).

## Architecture

`internal/core` decides everything and imports only the standard library. Everything that depends on where Keystub runs is an adapter behind a port (`internal/core/ports.go`), chosen in `cmd/keystub`; see [docs/architecture.md](docs/architecture.md).

| Port | Adapters today | Next |
| --- | --- | --- |
| `Repository` | `storage/jsonfile`, `storage/sqlite` | Postgres |
| `Sealer` | `secrets` envelope, master key from Keychain, env or file | KMS, Vault transit |
| `Limiter` | `limit` in memory, `storage/sqlite` | Redis, Postgres |
| `Sink` / `LogReader` | `reqlog` file, `storage/sqlite` | Parquet export, OpenTelemetry |
| Ingress | `proxy` (`CONNECT`, swapping or forwarding to an edge), `proxy.Edge` (`/s`, `/h`, `/catalog`) | transparent (iptables or DNS) |
| Hosts to decrypt (`proxy.Catalog`) | the core; `agent` asks an edge's `/catalog` | — |
| Catalog | `catalog/services.json` (with usage metadata) and `catalog/pricing.json`, shared with every Keystub implementation | usage metadata for more services |

New adapters pass the shared contracts: `storage/storagetest` for a Repository, `limit/limittest` for a Limiter. Every data plane passes the swap and usage cases in [`conformance/`](conformance/README.md).

## Which tools trust the proxy

| Runtime | How | Status |
| --- | --- | --- |
| curl | `CURL_CA_BUNDLE`, `HTTPS_PROXY` | Works |
| Node 24+ (`fetch`, SDKs) | `NODE_EXTRA_CA_CERTS`, `NODE_USE_ENV_PROXY=1` | Works |
| Python with OpenSSL (python.org, Homebrew, uv) | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | Works |
| Apple's bundled Python 3.9 (`/usr/bin/python3`, LibreSSL 2.8) | Ignores `SSL_CERT_FILE` | Fails; use another Python |
| Go programs on macOS | Use the system keychain, not `SSL_CERT_FILE` | Not yet |

No certificate is added to the macOS keychain. The only thing Keystub keeps there is a linked machine's credential (set `KEYSTUB_SECRETS=file` to keep it in `machine.json` instead).

## Not yet

Transparent mode for Linux boxes and sandboxes, the hosted edge, a Keychain for the machine credential off macOS, usage metadata beyond LLM services, keys in query strings or bodies, TCP connections (databases, SSH), name constraints on the CA, and a master key in KMS. With `--storage json`, limit counts are in memory and reset when the server restarts, and the request log rotates at 10 MB to `requests.jsonl.1`.

## Tests

```bash
go test -race ./...
KEYSTUB_TEST_KEYCHAIN=1 go test ./internal/secrets/   # also tests the real login keychain
```

The proxy tests run real TLS end to end: an upstream server, the proxy, and a client that trusts only the local CA.

## License

Apache-2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
