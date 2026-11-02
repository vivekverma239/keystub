---
title: Security
summary: What Keystub protects against, how, and what it doesn't cover.
---

# Security

A stolen proxy token is worth only what its environment, services, limits and lifetime allow, and it can be revoked at once. Real keys never reach a box.

## Threats and defences

| Threat | Defence |
| --- | --- |
| A box, sandbox or CI log leaks a proxy token | Scoped to one environment and optionally some services; limits; optional lifetime; revocable. Useless without a Keystub server |
| The token is used against a host outside its service | The proxy only decrypts catalog hosts; the edge only forwards to catalog hosts; the key is only added for the service the host belongs to |
| A box tries to read the real key back | The key is put only in `Authorization` and the service's own auth header. A token in any other header refuses the request, since a service may store or echo it. The Host header is always the service's, so a shared CDN can't route the key to another site |
| A proxy reachable from other machines | Every connection, tunnels and plain HTTP included, must carry a live token. Tunnels and plain HTTP can't reach loopback, private, link-local, carrier-grade NAT or NAT64 addresses (checked after DNS), so a token can't reach the server's dashboard or a cloud metadata service |
| A copy of the data folder or database | Real keys and tokens are sealed; tokens are looked up by hash. `keystub.db`, `state.json` and `master.key` are mode 0600 |
| The dashboard reached from a website | Admin token required; cross-site form posts refused; no framing; a strict content policy |
| Logs | Never hold headers, query strings or bodies |
| A stranger floods `keystub link` so real boxes can't link | 3 waiting requests per source (IPv4 address or IPv6 /64), 10 per network (/24 or /48), 10,000 in all, so filling the list takes a thousand networks; a turned-down request frees its slot at once. Behind a reverse proxy, trust a header the nearest proxy sets to the client's address with `--client-ip-header` (`X-Real-IP`, `CF-Connecting-IP`), or every request shares one source |
| A linked box's credential is read by another program | Revoke the machine: its credential and every token it was issued stop at once, even if marking each token fails |
| A forged certificate | The local CA's key stays on the box; leaf certificates last 24 hours and are only issued for the host the client asked the proxy for |
| The remote proxy used as an open relay | Every connection needs a live token, checked before the target is looked at; `CONNECT` only to port 443; never to loopback, private, link-local, carrier-grade NAT or NAT64 addresses (after DNS); no plain-HTTP proxying |
| One account's CA used on another account's traffic | Each account has its own CA. The edge hands the gateway a CA only for the account of a live token sent with the request, with no way to name an account, and the gateway refuses a CA for any account but the one the token check named |
| The remote proxy's CA keys | Made by the edge, stored in its database wrapped by the account key (bound to the account, its key version and the certificate, so a row moved to another account fails to open). The gateway gets one only over TLS from an authenticated route, keeps it in memory, and never writes or logs it. The control plane only ever sees the certificate |
| The remote proxy's own credential leaks | Alone it opens nothing: the CA route also needs a live token of the account. It can be rotated with no gap (an old value accepted alongside). With a token too, though, it gives that account's CA key: see below |
| A revoked token keeps a tunnel open through the remote proxy | Open connections' tokens are checked again every 30 seconds, 64 at once, and a refused token's connections are closed: within two check periods plus one pass, about a minute |
| A firewall or misrouted 401/403 in front of the edge closes every tunnel | The remote proxy takes a token as refused only on the edge's own refusal code (`token_refused`); anything else closes nothing and isn't remembered |
| A flood of made-up tokens at the remote proxy | Checks of new tokens are capped (503 past that); refusals are kept apart from live sessions; tokens that were live check again in slots a flood can't take |

## Not covered

- **A service that echoes its own auth header** (httpbin's `/headers`, a debugging endpoint) shows the key to whoever holds a token. Don't put such services behind Keystub.
- **Keys in query strings or bodies** aren't swapped, and a token there goes upstream unchanged (the token can leak to the provider, never the key).
- **The edge speaks plain HTTP.** Put TLS in front of it before exposing it beyond the machine.
- **Programs on a linked box.** The machine credential is in the user's login Keychain or a 0600 file, so any program running as that user can read it and get a token in each environment the admin ticked. The ticked environments are the only limit; the approve screen says so.
- **Machine tokens that expire stay** in the token list, as revoked ones do: there is no delete yet. Each `keystub run` after expiry makes a fresh one.
- **The remote proxy's credential plus any live token of an account** (even one scoped to one environment and service) gives that account's CA private key, which reaches every box of the account that trusts it, not just that token's. Guard the credential like the server's own secrets.
- **A leaked account CA key** lets whoever holds it intercept TLS from every box that trusts that CA, for any host, until the boxes stop trusting it: the CA isn't limited to the catalog's hosts (name constraints aren't built), and it lasts 5 years. CA rotation is planned but not built yet. Only the edge and the gateway's memory hold the key.
- **The remote proxy's token check trusts the server's token store**, as every route does: someone who can write token rows there and also holds the remote proxy's credential can get an account's CA key.
- **The remote proxy sees decrypted catalog traffic**, as the edge does: it is Keystub's, like the edge. It never sees a real key.
- **Tunnels through the remote proxy** carry whatever the box sends to public hosts on port 443. The token check bounds who can, not what.
- **A flood of made-up tokens can turn new boxes away** from the remote proxy (503) while it lasts. There's no limit per client address: behind a TLS-terminating load balancer the gateway doesn't see one (a load balancer that speaks the PROXY protocol would give it).
- **Trust in the server:** whoever runs the Keystub server holds the keys. With the hosted service that is Keystub (and Cloudflare); teams that can't accept that self-host.
