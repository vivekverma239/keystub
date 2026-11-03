---
name: keystub
description: Moves real API keys out of .env files, code, sandboxes and coding agents with Keystub (keystub.app), a proxy that swaps a stand-in token (sk-stub-…) for the real key on the way out. Use when a project keeps API keys or secrets in .env (OPENAI_API_KEY, ANTHROPIC_API_KEY, GITHUB_TOKEN, STRIPE_API_KEY…), when a sandbox, CI job or agent needs credentials it shouldn't hold, when keys need rotating or tokens revoking, or when the user mentions Keystub, keystub, proxy tokens or sk-stub tokens.
---

# Keystub

Keystub keeps real API keys out of processes. A program gets a proxy token
(`sk-stub-…`) where its key used to be, and Keystub puts the real key in
on the way out, only for that service's hosts.

- A **saved key** is a service's real key, saved once under a name (`team`).
- An **environment** (`project/env`, e.g. `my-app/dev`) links one saved key per service.
- A **token** belongs to one environment: an environment token covers every
  service it links, a service token (`--service S`) one.

Do every step with the `keystub` CLI. Don't call Keystub's HTTP API
yourself, and don't edit `.env` files by hand to move keys or tokens: the
commands below read and write them.

If `keystub` isn't on the PATH (`keystub version` fails), ask the user
whether to install it, and on their yes run the installer, which checks
the download against the release's checksums:

```bash
curl -fsSL https://raw.githubusercontent.com/vivekverma239/keystub/main/install.sh | sh
```

It installs to `~/.local/bin`; if that isn't on the PATH yet, call
`~/.local/bin/keystub` until the user opens a new terminal.
Where Node is set up, `npm install -g keystub` installs the same binary
from npm instead.

## Rules

Follow these every time.

1. **Never see a real key's value.** Don't `cat` or open a `.env` file, don't
   `echo $OPENAI_API_KEY`, and don't run `env` or `printenv`. Keys reach
   Keystub with `--from-env VAR --env-file .env` (read from the file by
   the CLI), `--from-env VAR` (from the environment), or on stdin; never
   as an argument.
2. **Add `--json`** to every `keystub` command except `run` and `env`. The
   result is one JSON value on stdout; a failure is
   `{"error": {"message": …, "exitCode": n}}`.
3. **Never see a token either.** Make tokens with `--write-env FILE`, which
   writes the token into the file and doesn't print it. A token printed
   any other way is shown once: don't repeat it in chat, commits or files.
   Writing a `.env` file replaces the real keys in it, so **ask the user
   first**, every time; then pass `--yes`. The CLI copies the old file to
   `~/.keystub/backups` before it writes, and says where.
4. **Ask the user first** before deleting or revoking anything, and before
   unlinking a service. Deletes and revokes then need `--yes`: nothing
   prompts when stdin isn't a terminal, so without it they fail with exit
   code 2. `envs unlink` takes effect at once, with no `--yes`.
5. Never ask the user to paste a key or an API key into the chat.

Exit codes: 0 ok, 1 error, 2 usage (a bad command, or a delete without
`--yes`), 3 not signed in, 4 not found, 5 conflict (a name that is taken,
a key that is still linked).

## Sign in

Check first: `keystub whoami --json`. Exit code 3 means not signed in:

- **Hosted, a person at the keyboard:** run `keystub login --json` in the
  background (add `--server URL` when the user names a server): it opens
  the approval page in the browser and waits until the code is approved
  or expires. It prints the URL and the code on stderr; tell the user
  both, in case the browser didn't open. When it exits 0, check again with
  `keystub whoami --json`.
- **CI, sandboxes and agents with no browser:** the user sets
  `KEYSTUB_API_KEY` (an API key from the dashboard) and `KEYSTUB_SERVER`
  (its server, e.g. `https://app.keystub.app`) in the environment. The CLI
  won't send the key to a server that isn't named.
- **Self-hosted:** `keystub serve` on this machine needs no sign-in. For
  a server elsewhere, pass `--server URL` and set `KEYSTUB_API_KEY`.

`keystub logout --json` signs out.

## Set a project up

**The short way**, for a folder with a `.env` file. `init` reads `.env`
in this folder and uses the environment `<folder>/dev`; name others with
`--env-file FILE` and `PROJECT/ENV` (e.g. `keystub init my-app/dev --env-file .env.local`).

1. Show the plan, which changes nothing:
   `keystub init --dry-run --json`. Tell the user, in a few lines, which
   services and variables it moves, the environment, and which saved key
   each service gets (`key`). Where the account already has a key for a
   service, a teammate's say, init links it rather than saving the one in
   the file (`shared: true`); say so, since the file's key is then not used.
   `--key-name NAME` saves or uses that name instead. Say what it leaves alone.
2. On their yes: `keystub init --yes --json`. It adds the services, saves
   each key straight from the file, makes the environment and links the
   keys. The `.env` file isn't changed.
3. Ask whether to put a token in `.env` in place of the real keys. First
   `keystub init --write-env --base-urls --dry-run --json`: `writeVars` are
   the variables it would set (the key variables, and with `--base-urls`
   each SDK's base URL on the edge); tell the user which. Only on a yes:
   `keystub init --write-env --base-urls --yes --json`. It answers with
   the copy of the old file (`backup`); tell the user where it is.
4. Check it: `keystub doctor --json`. Each check is `ok`, `warn` or
   `fail`, with what to do in `detail`; exit code 1 means one failed.

The steps below do the same one at a time, for anything `init` leaves
alone (a key inside a template, a service the catalog doesn't have).

1. **Find the keys.** Look for `.env`, `.env.local`, `.env.development`,
   `.dev.vars` and similar, then scan each:

   ```bash
   keystub keys scan .env --json
   ```

   It lists each variable's name, never its value: `service` is the
   service that reads it (null for anything else, such as `PORT` or a
   database URL), `added` whether the account has that service, and
   `proxyToken` whether it already holds a token.

2. **Agree on the plan with the user** before changing anything: which
   variables move, the environment (`my-app/dev`), and the key name
   (`team`, `personal`).

3. **Add each service** with `added: false`. Exit code 5 means it is
   added already.

   ```bash
   keystub services add openai --json
   keystub services add acme --hosts api.acme.com --env-vars ACME_API_KEY --json
   ```

4. **Save each real key** from the file:

   ```bash
   keystub keys add openai --name team --from-env OPENAI_API_KEY --env-file .env --json
   ```

   Exit code 5 means a key of that name exists for the service: ask
   whether to replace its value
   (`keystub keys replace team --service openai --from-env OPENAI_API_KEY --env-file .env --json`)
   or to use another name. Exit code 2 about the value's quotes, a `#` or
   a `$` means dotenv loaders would read that line differently, so it isn't
   saved: tell the user what the message says and ask them to fix the line
   (single quotes usually do it); don't open the file yourself.

5. **Make the environment** (its project is made too). Exit code 5 means
   it exists already, which is fine.

   ```bash
   keystub envs add my-app/dev --json
   ```

6. **Link each saved key** into it. `--no-token` skips the service token a
   link makes otherwise; step 7 makes one token for all of them.

   ```bash
   keystub envs link my-app/dev openai team --no-token --json
   keystub envs links my-app/dev --json
   ```

7. **Make a token and write it where the real keys were**, if the user
   agrees (rule 3). `--write-env` sets every key variable of the services
   the token covers (the real keys' lines become the token; missing ones
   are added), copies the old file to `~/.keystub/backups` first, and
   prints the token's ID, never the token. `--base-urls` also points each
   SDK that takes a base URL at Keystub's edge (next section).

   ```bash
   keystub tokens create my-app/dev --name local-dev --write-env .env --base-urls --yes --json
   ```

   Add `--ttl 2h` for a token that expires, `--service openai` for one
   service only. Give each sandbox, CI job or worktree its own token.

8. **Send requests through Keystub** (next section), run the app or its
   tests, and check with `keystub doctor my-app/dev --json` and that the
   requests arrived:
   `keystub usage my-app/dev --range 24h --json`. Then
   `keystub keys scan .env --json` should show `proxyToken: true` for each
   moved variable.

9. Make sure the `.env` file is in `.gitignore`. A proxy token is still a
   credential.

## Send requests through Keystub

A proxy token works only on its way through Keystub. Pick one:

- **Base URLs, for SDKs that take one** (OpenAI, Anthropic, Gemini, Groq,
  OpenRouter and others): `--base-urls` in step 7 writes them, such as
  `OPENAI_BASE_URL`. This works with the hosted service and with no proxy
  or CA on the machine. `keystub setup my-app/dev --json` shows the same
  lines, with `<token>` where the token goes.
- **The proxy, for every client** (curl, git, any SDK):
  - On a machine running `keystub serve`, or linked to a server with
    `keystub link`, `keystub run -- npm run dev` gives the command this
    worktree's own token; `keystub run --env my-app/dev -- npm test` picks
    the environment.
  - Elsewhere, with a token in `$KEYSTUB_TOKEN`:
    `keystub run --remote https://keystub.example.com -- npm test`
    (a self-hosted server's edge). `--token` also works but shows in `ps`.
  - Hosted: `keystub setup my-app/dev --json` also returns
    `remoteProxyLines` (an `HTTPS_PROXY` and CA settings) when the account
    has a remote proxy; `keystub ca -o keystub-ca.pem --json` saves the CA.
- `eval "$(keystub env)"` sets the same variables in a shell or `.envrc`.

## Day to day

- **Rotate a key** everywhere it is linked; tokens keep working:
  `keystub keys replace team --service openai --from-env NEW_OPENAI_KEY --env-file .env.new --json`.
- **Switch an environment to another key:**
  `keystub envs link my-app/dev openai personal --no-token --json`.
- **Stop a service in one environment** (ask first):
  `keystub envs unlink my-app/dev openai --json`.
- **List and revoke tokens** (ask first):
  `keystub tokens list my-app/dev --json`, then
  `keystub tokens revoke tk_123 --yes --json`.
- **Limits** (a level not named keeps its value; `--clear` removes both):
  `keystub projects limits my-app --daily 10000 --json`,
  `keystub envs limits my-app/prod --per-minute 60 --json`,
  `keystub keys limits team --service openai --daily 1000 --per-minute 60 --json`;
  tokens take them when made:
  `keystub tokens create my-app/ci --name ci --daily 500 --write-env .env.ci --yes --json`.
  On hosted, project and environment limits need `keystub login`: with
  `KEYSTUB_API_KEY` they get 403 (exit 1), so ask the user to sign in or set
  them on the dashboard.
- **Usage:** `keystub usage my-app/dev --by service,key --range 7d --json`
  (`--by` also takes `token`, `model`, `operation`, `env` and `project`;
  `--range` takes `24h`, `7d` or `30d`).
- **See what exists:** `keystub keys list --json`, `keystub projects list --json`,
  `keystub envs list --json`,
  `keystub keys show team --service openai --json`.
- **Delete** (ask first): `keystub keys delete team --service openai --yes --json`
  fails with exit code 5 while the key is linked; unlink it first.
  `keystub envs delete my-app/dev --yes --json` revokes its tokens.

The full command guide is [references/cli-guide.md](references/cli-guide.md),
the same text `keystub help agents` prints.
