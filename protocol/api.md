# Control API

The JSON API that the `keystub` CLI, scripts and agents use to manage an account: saved keys, links, tokens, services, usage. The hosted control plane and `keystub serve` answer the same routes, so the CLI works against either. [README.md](README.md) covers the data-plane routes (`/s`, `/h`, `/catalog`) instead.

## Changed since the brief

What this page adds to, or changes in, the contract as first agreed, newest first:

1. **What hosted does differently:**
   - **Versions** of saved keys and links only go up, and may skip numbers: hosted's edge hands them out, so a refused write or a database rollback leaves a gap. On hosted, a link's version also goes up when it is removed and when its environment is deleted, so an old link can't be brought back.
   - **Deleting an environment or a service** may take hosted several requests. The answer then has `remaining`, the number of changes still to reach the edge: send the service's `DELETE` again, or `POST /api/environments/{env}/resync` for the deleted environment, until it is 0. The CLI does this. Self-hosted finishes in one request and leaves `remaining` out.
   - **Putting the same key on a link again** changes nothing, unless hosted's edge has lost its record of the link: then the key is linked again at a higher version.
   - **429** also comes from hosted's CLI login, for too many logins started or codes looked up.
   - **Names ignore case** for ASCII letters only on hosted, and for all letters on self-hosted, so avoid key names that differ only in the case of other letters.
2. **Services:** an ID that exists, from the catalog or custom, gets 409 from `POST /api/services`, and a custom service can't take a catalog service's ID. Only `PATCH /api/services/{id}` changes a custom service, and it gets 409 while any saved key exists for that service. Catalog services can't be changed.
3. **`POST /api/tokens/ensure`** hands out an existing token's value only if `ensure` made it: those tokens carry principal `keystub-run`. Any other live token of that name gets 409. Tokens converted from before saved keys with no services and no principal are marked `keystub-run`, so worktrees keep theirs; the conversion notices list the live ones marked.
4. **Conversion:** a token limited to two or more services is revoked rather than widened, and named in the conversion notices (`notices` in `GET /api/me`, the dashboard, `keystub whoami`). One service makes a service token; none makes an environment token.
5. **Key limits** are counted only while set. With none, a key shows no count. The other levels are always counted on self-hosted; hosted counts only levels with a limit (see [limits](../docs/limits.md)).
6. **`PATCH /api/environments/{env}`** needs `limits`: an object sets them, `null` clears them, and leaving it out is a 400.
7. **The 429 for a saved key's limit** names the service, not the key: `daily limit reached for the saved key for openai`.
8. **Errors** also include 403 (a signed-in page's cross-site request), 405 (a known route, another method), 413 (a body over 256 KiB) and, on the data plane, 502 (no saved key linked).
9. **Token names**, from any route, can be at most 128 characters, with no control characters.
10. **Interpretations** of the brief, kept as first written: `Link.version` is the link's own; usage `key` is the saved key's ID, last in the CSV; `Token` also has `principal` and `state`; `{env}` is sent with a literal slash; a new link's token is named after its service (`-2`, `-3`… if taken); setup lines use `<token>`.

## Calling it

- **Auth:** `Authorization: Bearer <key>` on every route except the CLI login ones.
  - Hosted: an account API key, or the `skcli_…` token `keystub login` gets, which acts as the user who approved it.
  - Self-hosted: the server's admin API key, the contents of `admin.token` in its data folder (`~/.keystub` or `$KEYSTUB_HOME`). It can do everything. The dashboard's own pages may call the API with their signed-in session instead.
  - Missing or wrong: 401.
- **Bodies:** JSON objects, sent with `Content-Type: application/json` (otherwise 415), at most 256 KiB.
- **Environments:** `{env}` is `<project>/<env>`, e.g. `my-app/dev`, with the slash sent as is: `/api/environments/my-app/dev/links`. Self-hosted also accepts it encoded (`my-app%2Fdev`).
- **Errors:** `{"error": {"type": "keystub", "message": "…"}}`, plus fields named below for particular errors.
  - 400: a bad request.
  - 401: missing or wrong auth.
  - 403: a request from a signed-in dashboard page sent from another site.
  - 404: something missing, or a route that doesn't exist.
  - 405: a route that exists, called with another method.
  - 409: a clash with what exists.
  - 413: a body over 256 KiB.
  - 415: a body that isn't JSON.
  - 429: too many requests (hosted's CLI login).
  - The data plane, not this API, answers 502 when the service has no saved key linked in the token's environment.
- **Times:** RFC 3339, UTC.

## Objects

```
Limits   = {"dailyRequests": int, "perMinute": int}           0 means none
Key      = {"id": "key_…", "name", "service", "version", "setAt",
            "limits": Limits | null, "linkedIn": [env]}
Link     = {"env", "service", "key": {"id", "name"}, "version", "setAt"}
Token    = {"id", "name", "env", "kind": "environment" | "service",
            "service": id | null, "limits": Limits, "expiresAt", "revokedAt",
            "createdAt", "principal": string | null, "state": "active" | "revoked" | "expired"}
NewToken = Token + {"token": "sk-stub-…"}
```

- **Key:**
  - A saved key is a service's real key with a name. The API never returns its value, sealed or plain, after it is saved.
  - `version` starts at 1 and goes up each time the value is replaced. It only ever goes up, and may skip numbers. `setAt` is when the value was last set.
  - `limits` is null when the key has none. When set, they count every request that uses the key, in every environment it is linked in. A key is counted only while it has limits: with none, there is no count, and limits added later count from then. A request refused at any level counts at none.
  - A 429 for a key's limit names the service (`the saved key for openai`), since the token's holder needn't know the key's name.
  - `linkedIn` lists the environments it is linked in, sorted.
  - Names are unique per service, ignoring case (on hosted, of ASCII letters only), and can be at most 128 characters. Values can be at most 64 KiB.
- **Link:**
  - A link picks the saved key a service uses in one environment.
  - `version` is the link's own: it goes up each time the link is switched to another key, and on hosted when it is removed. It only ever goes up, and may skip numbers.
  - `setAt` is when it was last made or switched.
- **Token:**
  - An `environment` token may use every service linked in its environment.
  - A `service` token may use only `service`, and only while that service is linked there. Either kind follows the link, so replacing or switching a key changes no token.
  - Self-hosted reports `kind: "unknown"` for a stored token with no kind it knows (none should exist after conversion); such a token may use nothing.
  - The token value (`sk-stub-…`) appears only in a `NewToken`: once, except that `tokens/ensure` returns a token it made again, value and all, each time it is called with that name.
  - `principal` names who the token is for: `machine:<id>` for a linked machine's tokens, `keystub-run` for those `tokens/ensure` made, else null.
  - Names: at most 128 characters, no control characters, unique among the environment's live tokens.

## Saved keys

```
GET    /api/keys                 -> 200 {"keys": [Key]}
POST   /api/keys                 {"service", "name", "value", "limits"?}
                                 -> 201 {"key": Key}
GET    /api/keys/{id}            -> 200 {"key": Key}
PUT    /api/keys/{id}/value      {"value"} -> 200 {"key": Key}        a higher version
PATCH  /api/keys/{id}            {"name"?, "limits"?} -> 200 {"key": Key}
DELETE /api/keys/{id}            -> 200 {"ok": true}
                                 | 409 {"error": {…, "linkedIn": [env]}}
```

- `GET /api/keys` is sorted by service, then name.
- `POST` with a name the service already has gets 409. A service that doesn't exist gets 404.
- `PATCH` with `"limits": null` clears the key's limits; leaving `limits` out leaves them as they are.
- A linked key can't be deleted: unlink it everywhere first. The 409 names the environments it is still linked in.
- The CLI takes a key's name or its ID. It looks names up in `GET /api/keys`, within one service if `--service` is given.

## Links

```
GET    /api/environments/{env}/links            -> 200 {"links": [Link]}
PUT    /api/environments/{env}/links/{service}  {"key": id, "serviceToken"?: bool, "tokenName"?}
                                                -> 200 {"link": Link, "token"?: NewToken}
DELETE /api/environments/{env}/links/{service}  -> 200 {"ok": true}
```

- **PUT, new link:**
  - It also makes a service token for that service, unless `serviceToken` is false (it defaults to true).
  - The token is called `tokenName`, or the service's ID if that is free in the environment, else `<service>-2`, `<service>-3`…
  - A `tokenName` that is taken gets 409, and nothing is linked.
- **PUT, existing link:**
  - Putting the same key again changes nothing, unless hosted's edge has lost its record of the link: then the key is linked again at a higher `version`.
  - Putting another key switches the link (a higher `version`) and makes no token: the environment's tokens use the new key on their next request.
- **PUT checks:** the key must be for `{service}` (else 400). The environment, the service and the key must exist (else 404).
- **DELETE:** a service that isn't linked gets 404. Its tokens stay, and are refused with 502 until it is linked again.

## Tokens

```
POST /api/environments/{env}/tokens  {"name", "ttl"?, "limits"?, "service"?}
                                     -> 201 {"token": NewToken}
GET  /api/environments/{env}/tokens  -> 200 {"tokens": [Token]}
POST /api/tokens/{id}/revoke         -> 200 {"ok": true}
```

- **POST, kind:** with no `service` it makes an environment token. With `service` it makes a service token, which needs that service linked in the environment (409 otherwise; an unknown service gets 404).
- **POST, `ttl`:** a lifetime such as `30m`, `12h` or `7d`, up to 10 years. Leave it out for none.
- **POST, names:** a token's name is unique among the environment's live tokens (409 otherwise), at most 128 characters, with no control characters (400).

## Usage and setup

```
GET /api/usage?env=&by=service,token,key&range=7d  -> 200 {"rows": [Row]}
GET /api/environments/{env}/setup  -> 200 {"edgeUrl", "gatewayUrl": url | null,
                                           "envLines": [line], "remoteProxyLines": [line] | null}
GET /api/ca.pem                    -> 200 the CA certificate (PEM)
```

- **Usage rows:**
  - Rows are the Usage export's rows (see [usage](../docs/usage.md)) plus `key`, the ID of the saved key the request used.
  - `by` groups them by any of `project`, `env`, `token`, `service`, `model`, `operation`, `key`; it defaults to `service`.
  - `range` is `24h`, `7d` (the default) or `30d`. `env` filters to one environment.
- **Setup:**
  - `setup` is what a box needs to use an environment by quick start: one line per variable of each linked service, with `<token>` where the token goes, e.g. `OPENAI_BASE_URL=https://edge…/s/openai/v1` and `OPENAI_API_KEY=<token>`.
  - `gatewayUrl` and `remoteProxyLines` are for the hosted remote proxy, and null where there is none.
- **CA:** `ca.pem` is the CA a box trusts to use the remote proxy (hosted: the account's) or the local proxy (self-hosted: the server's).

## CLI device login (hosted only)

```
POST /api/cli/login       {"name": "<hostname>"}   no auth
                          -> 200 {"code": "ABCD-EFGH", "url", "poll", "interval": 5, "expiresIn": 600}
POST /api/cli/login/poll  {"poll"}
                          -> 202 {"pending": true}
                           | 200 {"token": "skcli_…", "account": {"id", "name"}, "user": {"id", "name"}}
                           | 410 expired or turned down
POST /api/cli/logout                               auth: the skcli_ token itself
                          -> 200 {"ok": true}
                           | 400 the caller isn't a CLI session
                           | 401 no unrevoked session has that token
```

The CLI shows `code` and `url`, then polls every `interval` seconds until it gets an answer or `expiresIn` runs out. It keeps the token in `~/.keystub/cli.json` (mode 0600). Self-hosted answers these routes with 404; the CLI then says to use `KEYSTUB_API_KEY`.

`keystub logout` sends `POST /api/cli/logout` to the server it signed in to, which revokes that session (by its token, even one gone idle or whose user left the account), then deletes `cli.json`. If the server can't be reached it still deletes the file, and says to revoke the session on the dashboard's Account page.

## Self-hosted

`keystub serve` answers everything above except CLI login, members and invites. Its admin API key is `admin.token` (the same token the dashboard link carries). The CLI reads it only when talking to the server on the same machine; see [decisions](../docs/decisions.md).

It also answers routes the CLI and `keystub run` use:

```
GET    /api/me                         -> 200 {"server": "self-hosted", "account": {"id", "name"}, "apiKey": {"id", "envs": null}, "notices": [text]}
GET    /api/projects                   -> 200 {"projects": [Project]}
POST   /api/projects                   {"name", "limits"?} -> 201 {"project": Project}
PATCH  /api/projects/{id}              {"limits": Limits | null} -> 200 {"ok": true}
GET    /api/environments               -> 200 {"environments": [Environment]}
POST   /api/environments               {"project", "name", "limits"?} -> 201 {"environment": Environment}
PATCH  /api/environments/{env}         {"limits": Limits | null} -> 200 {"ok": true}
DELETE /api/environments/{env}         -> 200 {"ok": true, "remaining"?: int}
GET    /api/catalog                    -> 200 {"services": [Service]}       what can be added
GET    /api/services                   -> 200 {"services": [Service]}       what is added
POST   /api/services                   {"catalog": id} | {"name", "hosts", "header"?, "format"?, "envVars"?}
                                       -> 201 {"service": Service}
PATCH  /api/services/{id}              {"name"?, "hosts"?, "header"?, "format"?, "envVars"?} -> 200 {"service": Service}
DELETE /api/services/{id}              -> 200 {"ok": true, "remaining"?: int}
POST   /api/tokens/ensure              {"env", "name"} -> 200 {"id", "name", "env", "expiresAt"?, "token"}
```

- **`/api/me` without a key** answers 401 in the error shape above. The CLI checks this before sending the admin key to the server `serve.json` names, since that file outlives the server.
- **`notices`:** what converting older data changed, such as tokens it revoked. The dashboard and `keystub whoami` show them too.
- **Project and environment limits:** `PATCH` needs `limits`. An object sets them, `null` clears them, and leaving it out is a 400. An object replaces both levels; the CLI's `projects limits` and `envs limits` keep a level you don't name by reading it first. On hosted, these need a signed-in user: an API key gets 403.
- **Deleting an environment:** revokes its tokens, removes its links, and takes it off every linked machine. The saved keys stay. On hosted, a `remaining` above 0 means the edge hasn't heard all of it yet: `POST /api/environments/{env}/resync` until it is 0.
- **Services:**
  - A service's hosts and header decide where its saved keys are sent, so they never change by accident.
  - `POST` with an ID that exists gets 409, from the catalog or custom; so does a custom service whose name gives a catalog service's ID (`OpenAI` is `openai`).
  - `PATCH` changes a custom service, and gets 409 while any saved key exists for it: delete the keys first. A catalog service can't be changed (409).
  - `DELETE` removes the service, its links and its saved keys. On hosted, a `remaining` above 0 means it isn't finished: send it again until it is 0.
- **`tokens/ensure`:**
  - It returns the live token called `name` that `ensure` made (principal `keystub-run`), or makes one. This is how `keystub run` gets a worktree's token.
  - Self-hosted only: hosted keeps just a hash of each token, so it can't hand one out a second time, and answers 404. `keystub run` calls it only on the `keystub serve` on its own machine; with hosted, give it a token in `$KEYSTUB_TOKEN` or `--token`.
  - Any other live token of that name (a CI job's, or a link's service token, which is named after its service) gets 409, never its value.
