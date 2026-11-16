#!/usr/bin/env node
// Runs the keystub binary from the platform package npm installed next to
// this one (one of optionalDependencies, picked by os and cpu), passing the
// arguments, stdio and exit status straight through.
"use strict";

const { spawnSync } = require("node:child_process");

const platforms = {
  "darwin arm64": "darwin-arm64",
  "darwin x64": "darwin-x64",
  "linux arm64": "linux-arm64",
  "linux x64": "linux-x64",
  "win32 arm64": "win32-arm64",
  "win32 x64": "win32-x64",
};

const target = platforms[`${process.platform} ${process.arch}`];
if (!target) {
  console.error(
    `keystub: no build for ${process.platform} ${process.arch}. ` +
      "Build it from source: go install github.com/vivekverma239/keystub/cmd/keystub@latest",
  );
  process.exit(1);
}

const pkg = `@keystub/cli-${target}`;
const exe = process.platform === "win32" ? "keystub.exe" : "keystub";
let bin;
try {
  bin = require.resolve(`${pkg}/bin/${exe}`);
} catch {
  console.error(
    `keystub: ${pkg} isn't installed. npm skips it when optional dependencies ` +
      "are turned off (--omit=optional or --no-optional); reinstall without that, " +
      "or use the installer: curl -fsSL https://raw.githubusercontent.com/vivekverma239/keystub/main/install.sh | sh",
  );
  process.exit(1);
}

const run = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (run.error) {
  console.error(`keystub: ${run.error.message}`);
  process.exit(1);
}
if (run.signal) {
  process.kill(process.pid, run.signal);
}
process.exit(run.status ?? 1);
