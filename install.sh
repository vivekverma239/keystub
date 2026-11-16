#!/bin/sh
# Installs the keystub CLI from the latest GitHub release:
#
#   curl -fsSL https://raw.githubusercontent.com/vivekverma239/keystub/main/install.sh | sh
#
# It downloads the binary for this machine, checks it against the
# release's checksums, puts it in ~/.local/bin (or $KEYSTUB_INSTALL_DIR),
# and adds that folder to PATH in your shell's rc file if it isn't there.
# It then offers to install the Keystub skill for coding agents, or
# refreshes a copy installed before (KEYSTUB_SKILL=yes or no answers
# without asking). Set KEYSTUB_VERSION=v0.1.0 for a given release. macOS and Linux; on
# Windows, download the zip from the releases page.
set -eu

REPO=vivekverma239/keystub
DIR=${KEYSTUB_INSTALL_DIR:-$HOME/.local/bin}

say() { printf '%s\n' "$*" >&2; }
fail() { say "keystub install: $*"; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "no build for $(uname -s); see https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "no build for $(uname -m); see https://github.com/$REPO/releases" ;;
esac

if [ -n "${KEYSTUB_DOWNLOAD_BASE:-}" ]; then # a mirror, or a test
  base=$KEYSTUB_DOWNLOAD_BASE
elif [ -n "${KEYSTUB_VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/$KEYSTUB_VERSION"
else
  base="https://github.com/$REPO/releases/latest/download"
fi
name="keystub_${os}_${arch}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
say "Downloading $name…"
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz" || fail "couldn't download $base/$name.tar.gz"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || fail "couldn't download the checksums"

want=$(awk -v f="$name.tar.gz" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || fail "$name.tar.gz isn't in the release's checksums"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{ print $1 }')
fi
[ "$got" = "$want" ] || fail "checksum mismatch for $name.tar.gz; nothing installed"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$DIR"
mv "$tmp/$name/keystub" "$DIR/keystub.new"
chmod 755 "$DIR/keystub.new"
mv "$DIR/keystub.new" "$DIR/keystub"
say "Installed $("$DIR/keystub" version) to $DIR/keystub"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) rc="$HOME/.zshrc" ;;
      */bash) [ "$os" = darwin ] && rc="$HOME/.bash_profile" || rc="$HOME/.bashrc" ;;
      *) rc="" ;;
    esac
    line="export PATH=\"$DIR:\$PATH\""
    if [ -n "$rc" ]; then
      if ! grep -qsF "$line" "$rc"; then
        printf '\n# Added by the keystub installer\n%s\n' "$line" >> "$rc"
        say "Added $DIR to PATH in $rc; open a new terminal, or run: $line"
      fi
    else
      say "Add $DIR to your PATH: $line"
    fi
    ;;
esac

# The Agent Skill teaches coding agents (Claude Code, Codex, Cursor) to use
# Keystub safely. A copy installed earlier is refreshed to match this
# release; otherwise ask, or follow KEYSTUB_SKILL=yes|no when set.
refreshed=""
for parent in "$HOME/.claude/skills" "$HOME/.agents/skills" "$HOME/.cursor/skills"; do
  if grep -qs '^name: keystub$' "$parent/keystub/SKILL.md"; then
    "$DIR/keystub" skill install --dir "$parent" >/dev/null && say "Updated the Keystub skill in $parent/keystub"
    refreshed=1
  fi
done
if [ -z "$refreshed" ]; then
  answer=${KEYSTUB_SKILL:-}
  if [ -z "$answer" ] && [ -r /dev/tty ] && [ -w /dev/tty ] && (: </dev/tty) 2>/dev/null; then
    printf 'Install the Keystub skill for coding agents (Claude Code, Codex, Cursor)? [Y/n] ' >/dev/tty
    read -r answer </dev/tty || answer=n
    answer=${answer:-y}
  fi
  case "$answer" in
    [Yy]*)
      "$DIR/keystub" skill install >&2 || say "Couldn't install the skill; later: keystub skill install"
      ;;
    "")
      say "To teach coding agents to use Keystub: keystub skill install"
      ;;
    *)
      say "Skipped the skill; later: keystub skill install"
      ;;
  esac
fi

say "Next: keystub login"
