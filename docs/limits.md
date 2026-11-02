---
title: Limits
summary: Daily and per-minute limits at project, environment, token and saved key, and what counts.
---

# Limits

A request goes ahead only if its project, its environment, its token and the saved key it uses all have room. A refused request counts against none of them.

## What can be limited

| Level | Set on | Example |
| --- | --- | --- |
| Project | Projects page, or `keystub projects limits` | `my-app`: 10,000 requests a day across all its environments |
| Environment | Projects page, or `keystub envs limits` | `my-app/prod`: 60 requests a minute |
| Token | Tokens page or `keystub tokens create`, when creating it | a CI job's token: 200 a day, 10 a minute |
| Saved key | Keys page, or `keystub keys limits` | the `team` OpenAI key: 5,000 a day, whichever environments it's linked in |

Each level has a daily limit and a per-minute limit. Empty or 0 means no limit at that level. Negative numbers are refused.

A saved key is counted only while it has a limit: one with none shows "Not counted" on the Keys page, and a limit added later counts from then. The other levels are always counted.

## Windows

- **Daily:** a calendar day in UTC. The count resets at 00:00 UTC.
- **Per minute:** a calendar minute in UTC (`10:04:00`–`10:04:59`), not a sliding window. A burst can therefore reach twice the limit across a minute boundary.

## What counts

Checks run in this order, and only a request that passes all of them is counted:

1. A token outside the auth headers → 400.
2. Unknown, revoked or expired token → 401; service not allowed → 403.
3. No saved key linked for the service in the token's environment → 502; the key can't be decrypted → 500.
4. Limits. If any level is full, the request gets 429 naming that level (`daily limit reached for token ci`, `per-minute limit reached for environment my-app/prod`, `daily limit reached for the saved key for openai`: the service, since the token's holder needn't know the key's name), and no level counts it.

A counted request whose upstream call then fails (an unreachable service, a 5xx from it) stays counted: it reached the service, or tried to.

## Where counts live

| Storage | Counts | After a restart |
| --- | --- | --- |
| `--storage json` (default) | In memory | Lost: every level starts again from 0 |
| `--storage sqlite` | In `keystub.db`, one transaction per request | Kept |
| Hosted | One counter per environment (its tokens' counts too), and one per project that has a limit | Kept, and exact across every location |

Several self-hosted instances each count on their own; shared counts need a shared limiter (Redis or Postgres, not built yet). Every limiter passes the same contract test, `internal/limit/limittest`.

The self-hosted Tokens page shows each token's count for today.

## Hosted differences

The hosted edge trades a little exactness for speed, so most requests skip a call to the counter, which lives in one region:

- **Only levels with a limit are counted.** A token, environment or project without one shows no count, and a limit added during the day counts from when it was set. Usage figures come from the request log instead.
- **Revocation takes effect within 1 second.** Where any level has a limit, it takes effect at once; otherwise each edge location may serve a revoked token for up to a second.
- **It fails closed.** If the counter can't be reached, the request is refused (500), never let through.
