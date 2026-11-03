#!/bin/sh
# Lays out the npm packages for a release: keystub (the bin wrapper) and one
# @keystub/cli-<os>-<cpu> package per platform holding that binary.
#
#   npm/build.sh VERSION BUILD_DIR OUT_DIR
#
# BUILD_DIR holds the release workflow's keystub_<goos>_<goarch> folders.
# Platforms whose folder is missing are skipped, so a local build of one
# platform can be packed and tried.
set -eu

version=${1#v}
build=$2
out=$3
here=$(cd "$(dirname "$0")" && pwd)

rm -rf "$out"
mkdir -p "$out"
optional=""

for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/arm64 windows/amd64; do
  goos=${target%/*}; goarch=${target#*/}
  src="$build/keystub_${goos}_${goarch}"
  [ -d "$src" ] || continue
  os=$goos; [ "$os" = windows ] && os=win32
  cpu=$goarch; [ "$cpu" = amd64 ] && cpu=x64
  exe=keystub; [ "$os" = win32 ] && exe=keystub.exe
  name="@keystub/cli-$os-$cpu"
  dir="$out/cli-$os-$cpu"

  mkdir -p "$dir/bin"
  cp "$src/$exe" "$dir/bin/$exe"
  chmod 755 "$dir/bin/$exe"
  cp "$here/../LICENSE" "$here/../NOTICE" "$dir/"
  cat > "$dir/package.json" <<EOF
{
  "name": "$name",
  "version": "$version",
  "description": "The keystub binary for $os $cpu; installed by the keystub package.",
  "license": "Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/vivekverma239/keystub.git" },
  "os": ["$os"],
  "cpu": ["$cpu"],
  "files": ["bin", "LICENSE", "NOTICE"],
  "preferUnplugged": true
}
EOF
  optional="$optional${optional:+,}
    \"$name\": \"$version\""
done

[ -n "$optional" ] || { echo "no keystub_<os>_<arch> folders in $build" >&2; exit 1; }

dir="$out/keystub"
mkdir -p "$dir/bin"
cp "$here/keystub/bin/keystub.js" "$dir/bin/"
cp "$here/keystub/README.md" "$here/../LICENSE" "$here/../NOTICE" "$dir/"
cat > "$dir/package.json" <<EOF
{
  "name": "keystub",
  "version": "$version",
  "description": "Keep real API keys out of .env files: a token there, the real key swapped in on the way out.",
  "license": "Apache-2.0",
  "homepage": "https://keystub.app",
  "repository": { "type": "git", "url": "git+https://github.com/vivekverma239/keystub.git" },
  "keywords": ["api-keys", "secrets", "proxy", "dotenv", "agents"],
  "bin": { "keystub": "bin/keystub.js" },
  "files": ["bin", "README.md", "LICENSE", "NOTICE"],
  "engines": { "node": ">=18" },
  "optionalDependencies": {$optional
  }
}
EOF
echo "npm packages for $version in $out"
