# Set Keystub up for this project

You are a coding agent, and the person asked you to set Keystub up. Keystub
keeps real API keys out of `.env` files: the file holds a token, and
Keystub swaps in the real key on the way out. Work through these steps
with the `keystub` CLI. Never open or print a `.env` file or a key: the CLI
reads them itself. Add `--json` to every command.

1. **Install.** If `keystub version` fails, ask the person whether to
   install it, then run:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/vivekverma239/keystub/main/install.sh | sh
   ```

   Use `~/.local/bin/keystub` if `keystub` still isn't on the PATH. With
   Node and no `curl`, `npm install -g keystub` installs the same binary.

2. **Sign in.** If `keystub whoami --json` exits 3, run
   `keystub login --server {{SERVER}} --json` in the background. It opens
   the browser; tell the person the code it prints, and wait for it to exit 0.

3. **Plan.** In the project's folder, run
   `keystub init --dry-run --json` and tell the person, in a few lines,
   which keys and secrets it would save and link, and into which
   environment. It reads `.env` (or `.env.local`, or the names in
   `.env.example`, or, with none of those, the variables the code reads),
   and says what it leaves alone. Nothing changes yet.

4. **Save them.** On their yes: `keystub init --yes --json`.

5. **Write the stand-ins**, only if the person agrees. First
   `keystub setup --dry-run --json` and tell them what it would set
   (`set`, each with its `protection`). On their yes:
   `keystub setup --yes --json`. It writes `.env`: a base URL and a
   stand-in for each key, which never reaches the box, and each secret as
   it is. The old `.env` is copied to `~/.keystub/backups` first; tell
   them where (`backup`).

6. **Check.** `keystub doctor --json`, and tell the person what passed.

In a sandbox or CI job that was given `KEYSTUB_TOKEN`,
`KEYSTUB_DELIVERY_KEY` and `KEYSTUB_EDGE`, skip steps 2 to 5: run
`keystub setup --json` in the project's folder.

For more, `keystub help agents` prints the full guide, and
`keystub skill install` adds the Keystub skill for next time.
