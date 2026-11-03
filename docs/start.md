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

   Use `~/.local/bin/keystub` if `keystub` still isn't on the PATH.

2. **Sign in.** If `keystub whoami --json` exits 3, run
   `keystub login --server {{SERVER}} --json` in the background. It opens
   the browser; tell the person the code it prints, and wait for it to exit 0.

3. **Plan.** In the folder with the `.env` file, run
   `keystub init --dry-run --json` and tell the person, in a few lines,
   which keys it would save and link, and into which environment. Nothing
   changes yet.

4. **Set up.** On their yes: `keystub init --yes --json`.

5. **Swap the keys for a token**, only if the person agrees. First
   `keystub init --write-env --base-urls --dry-run --json` and tell them
   which variables it would set (`writeVars`). On their yes:
   `keystub init --write-env --base-urls --yes --json`. The old `.env` is
   copied to `~/.keystub/backups` first; tell them where.

6. **Check.** `keystub doctor --json`, and tell the person what passed.

For more, `keystub help agents` prints the full guide, and
`keystub skill install` adds the Keystub skill for next time.
