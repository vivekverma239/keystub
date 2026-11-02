---
title: Model
summary: Projects, environments, services, saved keys and links, proxy tokens and limits.
---

# Model

```
Saved keys (per service) ◄── link per service ── Environment ── Project
                                                     └── proxy tokens (environment or service kind)
                                                           └── (optional) issued to a machine
```

A request's token picks its environment; the service comes from the route or host; the environment's link for that service picks the saved key; the saved key holds the real key.

- **Project:** groups environments, e.g. `my-app`. Its ID is its name as a slug. A fresh install has `default`.
- **Environment:** `project/name`, e.g. `my-app/dev`. Its links decide which saved key each service uses, so dev can use a Stripe test key and prod a live one. A fresh install has `default/dev`.
- **Service:** a third-party API, from the catalog or custom. Custom services need only a name and hosts; the token is swapped in `Authorization` and the service's own header; a custom service that authenticates with another header names it. That header (default `Authorization: Bearer {key}`) is also how the key is sent when a request carries no token. A base-URL variable makes it usable in quick start.
- **Saved key:** a service's real key with a name (`team`, `personal`), saved once, encrypted and write-only. The dashboard, API and CLI can replace, rename, limit or delete it, never show it. Names are unique per service. Its version goes up by one each time the value is replaced. It can have its own limits, which then count across every environment it's linked in. A linked key can't be deleted.
- **Link:** an environment's choice of saved key for a service, at most one per service. One key can be linked into many environments, so replacing it once changes all of them, and no token changes. Switching a link to another key moves every token in that environment with it. Removing a service removes its links and saved keys; unlinking keeps the key.
- **Proxy token:** belongs to exactly one environment, and is one of two kinds (a token of any other kind can use nothing). An *environment token* may use every service linked in its environment. A *service token* may use one service, and only while it's linked there; a new link makes one by default (named after the service). Either can have daily and per-minute limits and a lifetime of up to 10 years, and be revoked. Tokens are flat; there is no parent/child tree. `keystub run` keeps one per worktree; sandboxes and CI jobs get their own.
- **Machine:** a box linked with `keystub link`: an ID, a name, the environments it may use, a hash of its credential, when it was last seen and when it was revoked. Machines are optional; a sandbox or CI job just uses a token. A machine may get tokens only in the environments the admin ticked when approving it (the environment open on the dashboard is ticked to start with); a request for any other is refused (403). A live machine's name is unique (a second "MacBook-Pro" becomes "MacBook-Pro-2"). Its tokens are named `<machine>/<worktree>`, at most 100 live at a time, last 30 days (renewed when `keystub run` or a running agent asks for one with less than half left; an expired one is replaced by a fresh one), may use every service, and carry principal `machine:<id>`, so the request log shows which machine made each call. Revoking the machine revokes its credential and all of its tokens at once: a token whose machine is revoked is refused wherever it is used, even before it is marked revoked itself.
- **What a machine may do:** the ticked environments are its only boundary. Its credential is in the user's login Keychain or a 0600 file, so any program running as that user on the box can read it and get a token in each of those environments. Tick a production environment only for a machine you would trust with its keys.
- **Limits:** daily requests and requests per minute, at project, environment, token and saved key. A request must fit every level; a request that is refused, for any reason, counts against none.
- **Usage:** each request is logged with its project, environment, token and saved key, so it adds up at any level.
- **Services can't be repointed by accident:** adding a service whose ID exists is refused, and a custom service can't take a catalog service's ID. A custom one's hosts and header change only while no saved key exists for it. Catalog services don't change.
- **`keystub run`'s tokens** carry principal `keystub-run`; only those are handed out again by name. A worktree whose name another token has gets 409, and `--name` picks another.
- **Deleting an environment** revokes its tokens, removes its links and takes it off every machine. Its saved keys stay.

## Data from before saved keys

Both stores convert older data on first start and keep the old copy (`state.json.v2` for the JSON store; SQLite converts in one transaction):

- Each real key set in an environment becomes a saved key named `<env> <service>` (`my-app/dev openai`), linked there. Nothing is shared, so every environment keeps the key it had.
- A token for every service becomes an environment token. One with no principal is marked as `keystub run`'s (`keystub-run`), so each worktree keeps its token; the conversion notices list the live ones marked, so a CI job's or a person's can be revoked and made again.
- A token limited to a single service becomes a service token for it.
- A token limited to several services can be neither kind without reaching more than it did, so it is **revoked**. Each one is named in the conversion notices: at start on stderr, on every dashboard page, in `keystub whoami` and in `GET /api/me`. They are kept in `conversion-notes.txt` in the data folder; delete that file once they're dealt with, and they stop showing at the next start. Make a service token for each service it used.
- **No going back:** a build from before saved keys refuses the converted data instead of running without the saved keys. The JSON file's `bindings` field becomes text; SQLite's `bindings` table becomes a view with no such columns. To go back, restore the kept copy (`state.json.v2`, or a backup of `keystub.db`). Converting again after that is clean: an environment that already links a key keeps it, and no stray key is made. A build reading a JSON file from a newer one refuses it too.
