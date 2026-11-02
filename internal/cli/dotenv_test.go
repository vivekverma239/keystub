package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
)

const sampleEnv = `# keys
OPENAI_API_KEY=old-value
export OPENAI_API_KEY = "sk-real-openai"  # the team's
ANTHROPIC_API_KEY='sk-ant-real'
GROQ_API_KEY=gsk_real # comment
PEM="-----BEGIN KEY-----
abc\"def
NOT_A_VAR=inside
-----END KEY-----"
ESCAPES="a\nb\\c"
COMMENT_ONLY= # nothing here
HASH=abc#def
TRAILING="sk-fa"ke
BACKTICK=` + "`sk-tick`" + `
DOLLAR=${REAL_KEY}
DOLLAR_LITERAL='a$b'
OPEN="no end
PORT=3000
`

func TestDotenvValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	_ = os.WriteFile(path, []byte(sampleEnv), 0o600)
	for name, want := range map[string]string{
		"OPENAI_API_KEY":    "sk-real-openai", // the last definition
		"ANTHROPIC_API_KEY": "sk-ant-real",
		"GROQ_API_KEY":      "gsk_real",
		"PEM":               "-----BEGIN KEY-----\nabc\"def\nNOT_A_VAR=inside\n-----END KEY-----",
		"ESCAPES":           "a\nb\\c",
		"BACKTICK":          "sk-tick",
		"DOLLAR_LITERAL":    "a$b",
		"PORT":              "3000", // its own line after an unclosed quote
	} {
		if got, err := dotenvValue(path, name); err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"COMMENT_ONLY", "HASH", "TRAILING", "DOLLAR", "OPEN", "MISSING", "NOT_A_VAR"} {
		if _, err := dotenvValue(path, name); err == nil {
			t.Errorf("%s: want an error", name)
		} else if e, ok := err.(*Error); !ok || e.Code != ExitUsage {
			t.Errorf("%s: want a usage error, got %v", name, err)
		}
	}
	names, _, _ := dotenvNames(path)
	if got := strings.Join(names, " "); got != "OPENAI_API_KEY ANTHROPIC_API_KEY GROQ_API_KEY PEM ESCAPES COMMENT_ONLY HASH TRAILING BACKTICK DOLLAR DOLLAR_LITERAL OPEN PORT" {
		t.Errorf("names %s", got)
	}
}

func TestSetDotenv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	_ = os.WriteFile(path, []byte(`# keys
OPENAI_API_KEY=sk-real
export OPENAI_API_KEY="sk-real-2"
PEM="-----BEGIN
X=1
-----END"
GITHUB_TOKEN="multi
line"
PORT=3000`), 0o640)
	link := filepath.Join(dir, "link.env")
	_ = os.Symlink(path, link)
	if err := setDotenv(link, []envVar{
		{"OPENAI_API_KEY", "sk-stub-abc"}, {"GITHUB_TOKEN", "sk-stub-abc"},
		{"CONVEX_DEPLOY_KEY", "prod:my-app|skstubabc"}, {"OPENAI_BASE_URL", "https://edge.example/s/openai/v1"},
	}); err != nil {
		t.Fatal(err)
	}
	want := `# keys
OPENAI_API_KEY=sk-stub-abc
export OPENAI_API_KEY=sk-stub-abc
PEM="-----BEGIN
X=1
-----END"
GITHUB_TOKEN=sk-stub-abc
PORT=3000
CONVEX_DEPLOY_KEY="prod:my-app|skstubabc"
OPENAI_BASE_URL=https://edge.example/s/openai/v1
`
	if got, _ := os.ReadFile(path); string(got) != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640 kept", st.Mode().Perm())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".*keystub*")); len(m) > 0 {
		t.Errorf("left temporary files: %v", m)
	}
	// A quote that never closes, or closes with text after it, is its
	// first line alone: writing over it keeps every line after it.
	broken := filepath.Join(dir, "broken.env")
	_ = os.WriteFile(broken, []byte("OPENAI_API_KEY=\"sk-fake\r\nOTHER=\"keep\"\r\nDB_URL=postgres://x\r\n"), 0o600)
	if err := setDotenv(broken, []envVar{{"OPENAI_API_KEY", "sk-stub-t"}, {"NEW", "1"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(broken); string(b) != "OPENAI_API_KEY=sk-stub-t\r\nOTHER=\"keep\"\r\nDB_URL=postgres://x\r\nNEW=1\r\n" {
		t.Errorf("broken file became %q", b)
	}
	if _, err := dotenvValue(broken, "OTHER"); err != nil {
		t.Error(err)
	}

	noEnd := filepath.Join(dir, "noend.env")
	_ = os.WriteFile(noEnd, []byte("A=1\r\nB=2"), 0o600)
	if err := setDotenv(noEnd, []envVar{{"A", "new"}, {"Z", "z"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(noEnd); string(b) != "A=new\r\nB=2\r\nZ=z\r\n" {
		t.Errorf("CRLF file with no last line end became %q", b)
	}

	fresh := filepath.Join(dir, "new.env")
	if err := setDotenv(fresh, []envVar{{"A", "b"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(fresh); string(b) != "A=b\n" {
		t.Errorf("new file %q", b)
	}
	if st, _ := os.Stat(fresh); st.Mode().Perm() != 0o600 {
		t.Errorf("a new file should be 0600, is %v", st.Mode().Perm())
	}
}

// The whole setup from a .env file, through the CLI alone: scan it, save
// its keys from it, link them, and write a token back in their place.
// No value is ever an argument or printed.
func TestSetupFromDotenv(t *testing.T) {
	r := newRig(t)
	path := filepath.Join(t.TempDir(), ".env")
	_ = os.WriteFile(path, []byte("OPENAI_API_KEY=\"sk-real-openai\"\nANTHROPIC_API_KEY=sk-ant-real\nPORT=3000\n"), 0o600)

	r.must("", "services", "add", "openai")
	res := r.must("", "keys", "scan", path, "--json")
	if strings.Contains(res.stdout, "sk-real") || strings.Contains(res.stdout, "sk-ant") {
		t.Fatal("scan printed a value")
	}
	vars := res.json(t)["variables"].([]any)
	want := []string{"OPENAI_API_KEY openai true false", "ANTHROPIC_API_KEY anthropic false false", "PORT <nil> false false"}
	for i, v := range vars {
		m := v.(map[string]any)
		svc := "<nil>"
		if s, ok := m["service"].(string); ok {
			svc = s
		}
		if got := strings.Join([]string{m["var"].(string), svc, fmtBool(m["added"]), fmtBool(m["proxyToken"])}, " "); got != want[i] {
			t.Errorf("scan row %d: %s, want %s", i, got, want[i])
		}
	}

	r.must("", "services", "add", "anthropic")
	for _, s := range []string{"openai", "anthropic"} {
		v := strings.ToUpper(s) + "_API_KEY"
		res := r.must("", "keys", "add", s, "--name", "team", "--from-env", v, "--env-file", path, "--json")
		if strings.Contains(res.stdout+res.stderr, "sk-") {
			t.Fatal("a value was printed")
		}
	}
	if res := r.run("", "keys", "add", "openai", "--name", "x", "--env-file", path); res.code != ExitUsage || !strings.Contains(res.stderr, "--from-env") {
		t.Errorf("--env-file alone: %d %s", res.code, res.stderr)
	}
	if res := r.run("", "keys", "add", "openai", "--name", "x", "--from-env", "PORTX", "--env-file", path); res.code != ExitUsage {
		t.Errorf("a missing variable: %d %s", res.code, res.stderr)
	}
	r.must("", "envs", "add", "my-app/dev")
	r.must("", "envs", "link", "my-app/dev", "openai", "team", "--no-token")
	r.must("", "envs", "link", "my-app/dev", "anthropic", "team", "--no-token")
	if got, _ := r.engine.RealKey(context.Background(), "my-app/dev", "openai"); got != "sk-real-openai" {
		t.Fatalf("saved %q", got)
	}

	res = r.must("", "tokens", "create", "my-app/dev", "--name", "local", "--write-env", path, "--base-urls", "--json")
	if strings.Contains(res.stdout+res.stderr, core.TokenPrefix) {
		t.Fatalf("the token was printed: %s %s", res.stdout, res.stderr)
	}
	out := res.json(t)
	if out["file"] != path || out["token"].(map[string]any)["id"] == "" {
		t.Errorf("answer %v", out)
	}
	b, _ := os.ReadFile(path)
	text := string(b)
	if strings.Contains(text, "sk-real") || strings.Contains(text, "sk-ant-real") || !strings.Contains(text, "PORT=3000") {
		t.Fatalf("file:\n%s", text)
	}
	tok, _ := dotenvValue(path, "OPENAI_API_KEY")
	if ant, _ := dotenvValue(path, "ANTHROPIC_API_KEY"); !strings.HasPrefix(tok, core.TokenPrefix) || ant != tok {
		t.Fatalf("keys in the file: %q %q", tok, ant)
	}
	if base, _ := dotenvValue(path, "OPENAI_BASE_URL"); base != r.edge.URL+"/s/openai/v1" {
		t.Errorf("OPENAI_BASE_URL=%q", base)
	}
	if code, real := r.call("openai", tok); code != 200 || real != "sk-real-openai" {
		t.Errorf("the token from the file: %d %q", code, real)
	}
	if res := r.must("", "keys", "scan", path, "--json"); !strings.Contains(res.stdout, `"proxyToken": true`) {
		t.Errorf("scan after: %s", res.stdout)
	}

	// A service token writes only its service's variables.
	other := filepath.Join(t.TempDir(), ".env")
	r.must("", "tokens", "create", "my-app/dev", "--name", "only-openai", "--service", "openai", "--write-env", other)
	if b, _ := os.ReadFile(other); strings.Contains(string(b), "ANTHROPIC") || !strings.Contains(string(b), "OPENAI_API_KEY=sk-stub-") {
		t.Errorf("service token file:\n%s", b)
	}
	for _, args := range [][]string{
		{"--name", "y", "--base-urls"},
		{"--name", "y", "--write-env", ""},
		{"--name", "y", "--write-env=", "--json"},
		{"--name", "y", "--write-env", filepath.Join(t.TempDir(), "no-dir", ".env")},
	} {
		res := r.run("", append([]string{"tokens", "create", "my-app/dev"}, args...)...)
		if res.code != ExitUsage || strings.Contains(res.stdout+res.stderr, core.TokenPrefix) {
			t.Errorf("%v: %d %s %s", args, res.code, res.stdout, res.stderr)
		}
	}
	if n := len(r.must("", "tokens", "list", "my-app/dev", "--json").json(t)["tokens"].([]any)); n != 2 {
		t.Errorf("%d tokens; a refused --write-env made one", n)
	}
	// Nothing to write: no token is made.
	r.must("", "envs", "add", "my-app/empty")
	before := len(r.must("", "tokens", "list", "my-app/empty", "--json").json(t)["tokens"].([]any))
	if res := r.run("", "tokens", "create", "my-app/empty", "--name", "z", "--write-env", other); res.code != ExitUsage {
		t.Errorf("an environment with no links: %d %s", res.code, res.stderr)
	}
	if after := len(r.must("", "tokens", "list", "my-app/empty", "--json").json(t)["tokens"].([]any)); after != before {
		t.Error("a token was made that nobody has")
	}
}

func fmtBool(v any) string {
	if b, _ := v.(bool); b {
		return "true"
	}
	return "false"
}
