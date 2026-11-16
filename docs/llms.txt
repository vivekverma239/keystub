# Keystub: set it up from the command line

Keystub keeps real API keys out of your processes. A box holds a proxy
token (sk-stub-…); Keystub swaps in the real key on the way out. Every
step below is one `keystub` command, so an agent can do the whole setup.

Rules for agents:
- Add --json to any command for one JSON value on stdout: the result, or
  {"error": {"message": …, "exitCode": n}}.
- Exit codes: 0 ok, 1 error, 2 usage, 3 not signed in, 4 not found,
  5 conflict (a name that is taken, a key that is still linked).
- Nothing prompts when stdin isn't a terminal. Deletes need --yes.
- A real key's value goes in on stdin, with --from-env VAR, or with
  --from-env VAR --env-file .env (read from the file), never as an
  argument. Keystub never prints it back.
- A new token is printed once. Plain output puts it alone on stdout;
  with --json it is the "token" field. With --write-env FILE it goes into
  that .env file instead and isn't printed at all.
- Writing a .env file asks first (--yes when nothing can ask) and copies
  the old file to ~/.keystub/backups before changing it.
- Start with `keystub status --json`: who is signed in, this folder's
  environment, its services and live tokens, which variables in .env still
  hold a real key (names only), and "next", the command to run next.
- Send a token only where the service reads its key: Authorization, the
  service's own auth header, or for a service that takes its key in the URL
  (Google Maps, Telegram, Mapbox…) that query parameter or path. A token in
  another header or part of the URL is refused; bodies aren't checked, so
  never put a token in one.

The short way, for a project with a .env file:
   curl -fsSL https://raw.githubusercontent.com/vivekverma239/keystub/main/install.sh | sh
   (or, with Node: npm install -g keystub)
   keystub login --server https://app.keystub.app   (opens the browser; approve the code)
   keystub init --dry-run --json      (the plan: services, keys, secrets, the environment; changes nothing)
   keystub init --yes --json          (after the person agrees: saves the keys and secrets, links them)
   keystub setup --dry-run --json     (what setup would write into .env; "set", each with its protection)
   keystub setup --yes --json         (only if the person agrees: stand-ins in .env in place of
                                       the real keys, each SDK's base URL on the edge, and the
                                       secrets; a token for this folder, kept, never printed)
   keystub doctor --json              (checks sign-in, links, the .env file, and the token)
   keystub status --json              (what is set up here, and "next": what to do next)
   init reads .env in this folder (else .env.local, else the names in
   .env.example, else the variables the code reads) and uses the
   environment <folder>/dev, which it writes to .keystub.json for setup and
   doctor; name others with --env-file FILE and PROJECT/ENV. A variable no
   service reads but that holds a secret (a database URL, a deploy key) is
   saved as that environment's own secret, never shared with another. For a
   service the account already has a saved key for (a teammate's), init links
   that key, the one linked most, and doesn't save the file's; otherwise it
   saves the file's as "personal". --key-name NAME uses or saves that name
   instead. It leaves services the environment already links as they are.
   It never saves a long-lived AWS key from the file: Keystub mints short-lived
   AWS credentials from a key saved in the dashboard, so init links that key or
   says to add one. Where the account has a short-lived Fly.io or Cloudflare key
   saved, init links it instead of a stand-in.
The steps below do the same one at a time.

1. Sign in.
   Hosted:       keystub login            (opens the browser to approve a code; --no-browser prints it only)
   CI or agents: export KEYSTUB_API_KEY=… (an API key from the dashboard)
                 and KEYSTUB_SERVER=https://app.keystub.app (the key's server;
                 the CLI won't send the key without one named)
   Self-hosted:  run `keystub serve` on this machine; the CLI finds its admin
                 API key in ~/.keystub/admin.token, with no login. Elsewhere,
                 pass --server URL and set KEYSTUB_API_KEY to that key.
   Check:        keystub whoami   (also lists notices, e.g. tokens an upgrade revoked)

2. Add the services you call, from the catalog or your own.
   keystub keys scan .env        (which service reads each variable; names only)
   keystub services add openai
   keystub services add acme --hosts api.acme.com --env-vars ACME_API_KEY
   keystub services list

3. Save each real key once. Several per service is fine ("team", "personal").
   keystub keys add openai --name team --from-env OPENAI_API_KEY
   keystub keys add openai --name team --from-env OPENAI_API_KEY --env-file .env
   printf %s "$KEY" | keystub keys add anthropic --name team
   keystub keys list

4. Make an environment (its project is made if it doesn't exist).
   keystub envs add my-app/dev

5. Link a saved key into the environment, one per service. This also makes
   a service token for that one service and prints it once; --no-token skips it.
   keystub envs link my-app/dev openai team --no-token
   keystub envs links my-app/dev

6. Make a token for the sandbox. With no --service it covers every service
   the environment links; --service (repeat it, or a comma list) limits it to
   those; --ttl makes it expire.
   TOKEN=$(keystub tokens create my-app/dev --name sandbox-1 --ttl 2h)
   TOKEN=$(keystub tokens create my-app/dev --name ci --service openai --service anthropic --ttl 1d)
   or straight into a .env file, where the real keys were (and, with
   --base-urls, each SDK's base URL on the edge). It asks first, and copies
   the old file to ~/.keystub/backups:
   keystub tokens create my-app/dev --name local --write-env .env --base-urls --yes

7. Use it. Set the service's key variable to the token and send requests
   through Keystub, either through its proxy:
   keystub run --token "$TOKEN" -- npm test
   or, for SDKs with a base-URL setting, straight to the edge:
   keystub setup my-app/dev --print   (prints the .env lines; put the token in them)

In a sandbox or CI job:
   keystub tokens create my-app/dev --name ci --ttl 1d --delivery
                                      (on your machine: KEYSTUB_TOKEN, KEYSTUB_DELIVERY_KEY and
                                       KEYSTUB_EDGE, for the sandbox's environment)
   keystub setup --json               (in the sandbox: writes .env, ~/.keystub/env.sh, gcloud,
                                       and the AWS credentials file)
   Minted credentials (Google Cloud, AWS) and secrets come only with a token for
   every service and a delivery key; a token for some services gets stand-ins only.

Later:
- Rotate a key everywhere it is linked: keystub keys replace team --service openai --from-env NEW_KEY
- Point an environment at another key:  keystub envs link my-app/dev openai personal
  (its tokens move with it; nothing else changes)
- Stop a service in one environment:    keystub envs unlink my-app/dev openai
- Revoke a token:                       keystub tokens revoke tk_… --yes
- See usage:                            keystub usage my-app/dev --by service,key --range 7d
- Limits (a level you don't name keeps its value; --clear removes both):
    keystub projects limits my-app --daily 10000
    keystub envs limits my-app/prod --per-minute 60
    keystub keys limits team --service openai --daily 5000
    keystub projects list            (envs list and keys list show limits too)
  A token's limits are set when it's made: tokens create … --daily N --per-minute N
  On hosted, project and environment limits need a signed-in user (login, not an
  API key, which gets 403).
- The CA for the remote proxy:          keystub ca -o keystub-ca.pem
