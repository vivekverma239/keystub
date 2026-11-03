# keystub

The [Keystub](https://github.com/vivekverma239/keystub) CLI, from npm. It
keeps real API keys out of `.env` files: the file holds a token, and
Keystub swaps in the real key on the way out.

```bash
npx keystub@latest init --dry-run   # what it would set up here; changes nothing
npm install -g keystub              # or keep it on the PATH
```

npm installs the prebuilt binary for your platform (macOS, Linux and
Windows, x64 and arm64) as an optional dependency; nothing is downloaded
when it runs. See the [README](https://github.com/vivekverma239/keystub#readme)
for the rest.
