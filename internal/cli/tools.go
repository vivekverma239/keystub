package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// keystub tools: the CLIs a project's deploys need, which keystub setup
// signs in but doesn't install. `tools check` says which are here; `tools
// install` installs the named ones (or every one the code and the
// delivered credentials need) for this user, under ~/.local, from each
// vendor's own download.

const toolsUsage = "tools check|install [gcloud|fly|wrangler|aws ...] [--dir DIR] [--env-file FILE]"

// toolScripts install each CLI for this user. $BIN is ~/.local/bin; each
// script is fixed text, run with sh, never built from input.
var toolScripts = map[string]string{
	"gcloud": `set -e
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) f=linux-x86_64 ;; Linux-aarch64|Linux-arm64) f=linux-arm ;;
  Darwin-arm64) f=darwin-arm ;; Darwin-x86_64) f=darwin-x86_64 ;;
  *) echo "no gcloud download for $(uname -sm)" >&2; exit 1 ;;
esac
mkdir -p "$HOME/.local" "$BIN"
curl -fsSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-$f.tar.gz" | tar -xz -C "$HOME/.local"
"$HOME/.local/google-cloud-sdk/install.sh" --quiet --usage-reporting=false --path-update=false --command-completion=false >/dev/null
for b in gcloud gsutil bq; do ln -sf "$HOME/.local/google-cloud-sdk/bin/$b" "$BIN/$b"; done`,
	"fly": `set -e
mkdir -p "$BIN"
curl -fsSL https://fly.io/install.sh | FLYCTL_INSTALL="$HOME/.fly" sh >/dev/null
ln -sf "$HOME/.fly/bin/flyctl" "$BIN/fly"
ln -sf "$HOME/.fly/bin/flyctl" "$BIN/flyctl"`,
	"wrangler": `set -e
command -v npm >/dev/null || { echo "wrangler needs Node.js and npm" >&2; exit 1; }
mkdir -p "$HOME/.local" "$BIN"
npm install -g --prefix "$HOME/.local" wrangler >/dev/null 2>&1`,
	"aws": `set -e
mkdir -p "$BIN"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) f=x86_64 ;; Linux-aarch64|Linux-arm64) f=aarch64 ;;
  Darwin-*) command -v brew >/dev/null && { brew install awscli >/dev/null; exit 0; }
            echo "install the AWS CLI with Homebrew (brew install awscli) or Apple's installer" >&2; exit 1 ;;
  *) echo "no AWS CLI download for $(uname -sm)" >&2; exit 1 ;;
esac
command -v unzip >/dev/null || { echo "the AWS CLI's installer needs unzip" >&2; exit 1; }
t=$(mktemp -d)
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$f.zip" -o "$t/aws.zip"
unzip -q "$t/aws.zip" -d "$t"
"$t/aws/install" -i "$HOME/.local/aws-cli" -b "$BIN" --update >/dev/null
rm -rf "$t"`,
}

type toolState struct {
	Name      string `json:"name"`
	For       string `json:"for,omitempty"`
	Installed bool   `json:"installed"`
	Done      string `json:"done,omitempty"` // installed now, or why not
}

func (c *ctx) tools(args []string) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "install") {
		return usageErr("usage: keystub %s", toolsUsage)
	}
	sub := args[0]
	p, err := parse(args[1:], []string{"dir", "env-file"}, nil)
	if err != nil {
		return err
	}
	file := p.flags["env-file"]
	if file == "" {
		file = ".env"
	}
	dir := p.flags["dir"]
	if dir == "" {
		dir = filepath.Dir(file)
	}
	need := map[string]string{}
	if len(p.args) > 0 {
		for _, a := range p.args {
			for _, n := range strings.Split(a, ",") {
				n = strings.TrimSpace(n)
				if n == "flyctl" {
					n = "fly"
				}
				if _, ok := toolScripts[n]; !ok {
					return usageErr("no tool %q: keystub installs gcloud, fly, wrangler and aws", n)
				}
				need[n] = "named"
			}
		}
	} else {
		need = c.neededTools(dir, file)
	}
	names := make([]string, 0, len(need))
	for n := range need {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []toolState{}
	home := c.homeDir()
	bin := filepath.Join(home, ".local", "bin")
	failed := false
	for _, n := range names {
		st := toolState{Name: n, For: need[n], Installed: toolHere(n, home)}
		if sub == "install" && !st.Installed {
			var log strings.Builder
			env := append(os.Environ(), "HOME="+home, "BIN="+bin, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if err := c.Exec(nil, &log, &log, env, "sh", "-c", toolScripts[n]); err != nil {
				st.Done = "failed: " + lastLine(firstNonEmpty(log.String(), err.Error()))
				failed = true
			} else {
				st.Installed, st.Done = true, "installed in "+bin
			}
		}
		out = append(out, st)
	}
	res := map[string]any{"tools": out, "bin": bin}
	if sub == "install" && !onPath(bin, c.Getenv("PATH")) {
		res["next"] = "put " + bin + " on the PATH (export PATH=\"" + bin + ":$PATH\")"
	}
	err = c.emit(res, func(w io.Writer) {
		if len(out) == 0 {
			fmt.Fprintln(w, "No CLIs needed: nothing here deploys to Google Cloud, Fly.io, Cloudflare or AWS.")
		}
		for _, t := range out {
			state := "installed"
			if !t.Installed {
				state = "missing"
			}
			line := fmt.Sprintf("%-9s %s", t.Name, state)
			if t.For != "" && t.For != "named" {
				line += " (for " + t.For + ")"
			}
			if t.Done != "" {
				line += ": " + t.Done
			}
			fmt.Fprintln(w, line)
		}
		if n, ok := res["next"].(string); ok {
			fmt.Fprintln(w, "Next:", n)
		}
	})
	if err == nil && failed {
		return &Error{Code: ExitError, Message: "some tools didn't install"}
	}
	return err
}

// neededTools is each CLI the code's deploys and the delivered credentials
// need, and why.
func (c *ctx) neededTools(dir, file string) map[string]string {
	need := map[string]string{}
	vars := c.verifyVars(file)
	g := detectGoogle(dir)
	if vars["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] != "" || g.run || g.appEngine || g.build {
		need["gcloud"] = "Google Cloud"
	}
	if vars["AWS_SHARED_CREDENTIALS_FILE"] != "" {
		need["aws"] = "AWS"
	}
	for _, d := range detectDeploys(dir) {
		switch d.Kind {
		case "fly":
			need["fly"] = "Fly.io deploys"
		case "cloudflare":
			need["wrangler"] = "Cloudflare deploys"
		}
	}
	return need
}

func onPath(dir, path string) bool {
	for _, p := range filepath.SplitList(path) {
		if filepath.Clean(p) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

// hostOS is this machine's GOOS/GOARCH, for sandbox to know whether its
// own binary runs in a Linux container.
var hostOS = runtime.GOOS + "/" + runtime.GOARCH
