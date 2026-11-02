# Protocol

Any Keystub server (the Go `keystub serve`, or the hosted edge) answers these routes (the account-management API is in [api.md](api.md)), so agents and quick-start config work against either: `/s` and `/h` for requests, `/catalog` for agents. Only services in the server's catalog are reachable: neither route is an open proxy.

## `/s/<service>/<path>`: quick start

An SDK's base URL points here, e.g. `OPENAI_BASE_URL=https://<server>/s/openai/v1`. The request goes to the service's primary host with `<path>` and the query string unchanged.

The SDK sends the proxy token as its API key. The server swaps it for the real key in `Authorization` (`authHeaders` in [`conformance/swap.json`](../conformance/swap.json)) or the service's own header from the catalog. A token in any other header refuses the request with 400.

## `/h/<host>/<path>`: agents

A local agent that has already decrypted a request for `<host>` sends it here unchanged. When the client sent a token in `Proxy-Authorization` (always, with `keystub run`), the agent adds it:

```
Keystub-Token: sk-stub-…
```

The server uses this token if present, else the one in the auth headers, and removes the header before forwarding. Servers also accept the header's old name, `Stubkey-Token`, from agents built before the rename, and remove it too. A server built before the rename doesn't know `Keystub-Token` and refuses it as a stray token (400), so update edges before agents. Either way every token in the auth headers is swapped for that token's real key, so the proxy token decides, as it does when a local proxy swaps keys itself. The agent drops any `Keystub-Token` the client itself wrote, and refuses a token in any other header (400) before it leaves the box, as every data plane does. `<host>` always means port 443.

The agent keeps one long-lived HTTP/2 connection to an `https://` server; websocket upgrades come over HTTP/1.1.

## `GET /catalog`: what an agent decrypts

An agent asks which services a proxy token may use, to know which hosts to decrypt (every other host is tunnelled untouched) and which variables `keystub run` sets. The token goes in `Keystub-Token` (or `Authorization: Bearer`). Nothing is counted against limits or logged as a call.

```json
{
  "token": {"id": "tk_…", "name": "ci", "env": "my-app/dev", "expiresAt": "2026-11-01T00:00:00Z"},
  "services": [
    {"id": "openai", "name": "OpenAI", "hosts": ["api.openai.com"], "header": "Authorization",
     "envVars": ["OPENAI_API_KEY"], "baseUrl": {"var": "OPENAI_BASE_URL", "path": "/v1"}}
  ]
}
```

`services` lists only what the token may use (one service for a service token, all for an environment token) and that is linked to a saved key in the token's environment: a service the server could only refuse is better left untouched on the box. `header` is the service's own auth header, besides `Authorization`. It never carries a key or a key's format. An unknown, revoked or expired token gets 401. Agents fetch it at start and every few minutes. An agent decrypts only the listed hosts that Keystub's built-in catalog (`catalog/services.json`) gives that same service ID, or that its box allowed (a plain allowed host for a custom service only; a built-in service only on a host the box named it for, `--allow-host gitlab=gitlab.corp.example`): the server doesn't choose alone what a box decrypts. A server that serves a custom service should say so to whoever runs the agents. An agent checks each service as a server would (IDs are lowercased) and drops one that fails. For a built-in service, it takes `header`, `envVars` and `baseUrl` from the built-in catalog, not from this response; for a custom one it sets only variables named like `FOO_KEY`, `FOO_TOKEN`, `FOO_SECRET` or `FOO_PASSWORD` that no built-in service reads, and no base URL. A host the built-in catalog gives a service, or the box pinned to it, is decrypted only as that service, whatever else lists it. An agent also refuses, before forwarding, a request whose auth header carries a credential besides a proxy token (400), so a box's own credentials in auth headers never reach the server.

## `/gateway/…`: the remote proxy

A remote proxy (`keystub gateway`) serves many accounts' boxes, and asks the edge about each box's token before it tunnels or decrypts anything. Both routes take `POST`, the remote proxy's own credential in `Keystub-Gateway-Key`, and the box's token in `Keystub-Token`. A missing or wrong credential gets 401 with `"code": "gateway_credential"` in the error; a server with no credential configured doesn't serve the routes (404). An unknown, revoked or expired token gets 401 with `"code": "token_refused"`. The remote proxy takes only that as the token refused (it answers the box 407 and closes the token's tunnels); any other answer, a 401 or 403 without the code included (from something in front of the server, say), is a server problem that closes nothing. Neither counts anything against limits.

`POST /gateway/check` answers as `GET /catalog` does, plus the token's account:

```json
{"accountId": "acct_…",
 "token": {"id": "tk_…", "name": "ci", "env": "my-app/dev", "expiresAt": "…"},
 "services": [{"id": "openai", "name": "OpenAI", "hosts": ["api.openai.com"], "header": "Authorization"}]}
```

`POST /gateway/ca` returns the CA of the token's own account, made on first use, that the remote proxy signs that account's leaf certificates with:

```json
{"accountId": "acct_…", "certificate": "-----BEGIN CERTIFICATE-----\n…", "key": "<PKCS #8, base64>"}
```

There is no way to name an account: each answers only for the token's. The remote proxy refuses a CA whose `accountId` isn't the one the check named. The certificate is ECDSA P-256, self-signed, a CA with path length 0, with a subject key identifier, the account ID as its organizational unit. Boxes download the same certificate (never the key) from the account's dashboard. The hosted edge serves these routes; `keystub serve` doesn't yet.

## Machine linking

A self-hosted server links machines with a device-code flow, so `keystub run` can get a token per worktree with no admin token. These routes are on the same listener as `/s` and `/h`; send them over TLS.

`POST /link` starts it:

```json
{"name": "ada-mbp"}
→ {"deviceCode": "9f…", "userCode": "BCDF-2345", "expiresIn": 600, "interval": 2}
```

The CLI shows `userCode`; an admin types it on the dashboard's Machines page and ticks the environments the machine may use. Meanwhile the CLI polls every `interval` seconds with the secret `deviceCode`:

```json
POST /link/poll  {"deviceCode": "9f…"}
→ 202 while waiting
→ 200 {"machine": {"id": "m_…", "name": "ada-mbp", "envs": ["my-app/dev"]}, "credential": "skmach_…"}
→ 403 if turned down (the server remembers the last 100 turned down until they would have expired, and none after a restart: those get 404)
→ 404 if unknown or expired (after 10 minutes)
```

The credential is sent once; the request is gone after that. At most 10,000 requests wait at a time, 3 from one source and 10 from one network (429 beyond that): a source is an IPv4 address or an IPv6 /64, which one host can hold whole; a network is an IPv4 /24 or an IPv6 /48. The dashboard lists the first 50. The source is the connection's address, unless the server is told to trust a reverse proxy's header for it (`keystub serve --client-ip-header X-Real-IP`): name a header the proxy nearest the server sets to the client's address, such as `CF-Connecting-IP` or nginx's `X-Real-IP`. The last address in it is taken, so `X-Forwarded-For` works behind one proxy only: behind two it is the outer proxy's, and everyone coming through it shares one source. `Forwarded` is refused, since it holds `for=` pairs; without that, behind a proxy every request shares the proxy's. A turned-down request leaves the list at once and holds no slot. The admin types the code, sees the request's name, address and time, then approves it with environments or turns it down. A credential starts with `skmach_`, never a proxy token's prefix, so it is never swapped into a request or accepted as a token.

`POST /machine/tokens` returns the machine's live token with that name in that environment, creating it on first use:

```json
Authorization: Bearer skmach_…
{"env": "my-app/dev", "name": "my-worktree"}
→ {"id": "tk_…", "name": "ada-mbp/my-worktree", "env": "my-app/dev", "token": "sk-stub-…"}
```

`env` may be empty for the machine's first environment. The token carries principal `machine:<id>` and lasts 30 days, renewed for another 30 when it is asked for again with less than half of that left; `name` is at most 128 characters, and a machine holds at most 100 live tokens. Unknown or revoked credential → 401; an environment the machine may not use, or a name held by another token → 403. Revoking the machine on the dashboard revokes its credential and every token it was issued.

The hosted edge links machines through its own sign-in instead, and may not serve these routes.

## Errors

Keystub's own refusals are JSON, so clients can tell them from the service's:

```json
{"error": {"type": "keystub", "message": "daily limit reached for token ci"}}
```

| Status | Meaning |
| --- | --- |
| 400 | The token is in a header that isn't an auth header |
| 401 | No valid token, or it has expired |
| 403 | The token can't use this service |
| 404 | No such service or host in the catalog |
| 429 | A daily or per-minute limit is full; the message names which |
| 500 | The real key can't be decrypted |
| 502 | No saved key is linked for this service in the token's environment, or the service can't be reached |
