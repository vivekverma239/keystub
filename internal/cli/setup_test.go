package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// noGcloud keeps a test off the machine's own gcloud.
func noGcloud(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	look, run := lookGcloud, runGcloud
	lookGcloud = func() (string, error) { return "", errors.New("not installed") }
	runGcloud = func(_ string, args ...string) ([]byte, error) { calls = append(calls, args); return nil, nil }
	t.Cleanup(func() { lookGcloud, runGcloud = look, run })
	return &calls
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetupOnALaptop(t *testing.T) {
	noGcloud(t)
	r := newRig(t)
	path := writeDotenv(t, "shop", "OPENAI_API_KEY=sk-real-openai\nPORT=3000\n")
	r.must("", "init", "--env-file", path, "--yes", "--json")

	// A dry run with no token yet names what would be set, and makes nothing.
	plan := r.must("", "setup", "--env-file", path, "--dry-run", "--json").json(t)
	if plan["env"] != "shop/dev" || plan["dryRun"] != true {
		t.Fatalf("plan %v", plan)
	}
	if got := names(plan["set"]); got != "OPENAI_API_KEY,OPENAI_BASE_URL" {
		t.Fatalf("dry run sets %s", got)
	}
	if toks := r.must("", "tokens", "list", "shop/dev", "--json").json(t)["tokens"].([]any); len(toks) != 0 {
		t.Fatalf("a dry run made a token: %v", toks)
	}

	// The file holds the real key, so setup asks first.
	if res := r.run("", "setup", "--env-file", path, "--json"); res.code != ExitUsage || !strings.Contains(res.stdout, "OPENAI_API_KEY") {
		t.Fatalf("setup over a real key without --yes: %d %s", res.code, res.stdout)
	}
	res := r.must("", "setup", "--env-file", path, "--yes", "--json")
	if strings.Contains(res.stdout+res.stderr, "sk-stub-") || strings.Contains(res.stdout, "sk-real") {
		t.Fatal("setup printed a value")
	}
	out := res.json(t)
	// The token was made by the run that asked, and kept for this one.
	if out["backup"] == nil || out["token"].(map[string]any)["name"] != "testbox/shop" {
		t.Fatalf("result %v", out)
	}
	text := readFile(t, path)
	if !strings.Contains(text, "OPENAI_BASE_URL="+r.edge.URL+"/s/openai/v1") || !strings.Contains(text, "OPENAI_API_KEY=sk-stub-") || !strings.Contains(text, "PORT=3000") || strings.Contains(text, "sk-real") {
		t.Fatalf(".env:\n%s", text)
	}
	if readProjectFile(filepath.Dir(path)) != "shop/dev" {
		t.Fatal("no .keystub.json")
	}
	// The stand-in works through the edge.
	tok := strings.TrimPrefix(dotenvLine(text, "OPENAI_API_KEY"), "OPENAI_API_KEY=")
	if code, _ := r.call("openai", tok); code != 200 {
		t.Fatalf("stand-in through the edge: %d", code)
	}

	// Again, from the folder's .keystub.json: the same token, nothing to ask.
	again := r.must("", "setup", "--env-file", path, "--json").json(t)
	if again["token"].(map[string]any)["made"] != false || again["backup"] != nil {
		t.Fatalf("second setup: %v", again)
	}
	if toks := r.must("", "tokens", "list", "shop/dev", "--json").json(t)["tokens"].([]any); len(toks) != 1 {
		t.Fatalf("tokens after two setups: %d", len(toks))
	}
	// Its access file is the owner's alone.
	entries, _ := os.ReadDir(filepath.Join(r.home, "access"))
	if len(entries) != 1 {
		t.Fatalf("access files: %v", entries)
	}
	if st, _ := os.Stat(filepath.Join(r.home, "access", entries[0].Name())); st.Mode().Perm() != 0o600 {
		t.Fatalf("access file mode %v", st.Mode())
	}
}

func TestSetupNeedsAnEnvironment(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "nothing-here", "PORT=3000\n")
	res := r.run("", "setup", "--env-file", path, "--json")
	if res.code != ExitNotFound || !strings.Contains(res.stdout, "keystub init") {
		t.Fatalf("%d %s", res.code, res.stdout)
	}
}

// fakeEdge serves /catalog and /provision as the hosted edge does.
func fakeEdge(t *testing.T, token, delivery string) *httptest.Server {
	t.Helper()
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/catalog":
			if req.Header.Get("Keystub-Token") != token {
				http.Error(w, `{"error":{"message":"no"}}`, 401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": map[string]any{"id": "tk_1", "name": "ci-main", "env": "knowsis/dev", "expiresAt": expires},
				"services": []any{
					map[string]any{"id": "anthropic", "name": "Anthropic", "hosts": []string{"api.anthropic.com"}, "envVars": []string{"ANTHROPIC_API_KEY"}, "baseUrl": map[string]string{"var": "ANTHROPIC_BASE_URL", "path": ""}},
					map[string]any{"id": "exa", "name": "Exa", "hosts": []string{"api.exa.ai"}, "envVars": []string{"EXA_API_KEY"}},
				},
			})
		case "/provision":
			if req.Method != "POST" || req.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, `{"error":{"message":"no"}}`, 401)
				return
			}
			if req.Header.Get("Keystub-Delivery-Key") != delivery {
				http.Error(w, `{"error":{"message":"no"}}`, 403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"variables": []any{
					map[string]any{"name": "DATABASE_URL", "service": "postgres", "value": "postgres://u:p@db/app", "secret": true},
					map[string]any{"name": "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "service": "google-cloud", "file": "google-cloud/access-token", "secret": false},
					map[string]any{"name": "CLOUDSDK_CORE_PROJECT", "service": "google-cloud", "value": "acme-dev", "secret": false},
				},
				"files": []any{map[string]any{"path": "google-cloud/access-token", "service": "google-cloud", "content": "ya29.minted"}},
				"items": []any{
					map[string]any{"service": "postgres", "name": "Postgres", "kind": "secret", "protection": "on-box", "variables": []string{"DATABASE_URL"}},
					map[string]any{"service": "google-cloud", "name": "Google Cloud", "kind": "minted", "protection": "short-lived", "variables": []string{"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_CORE_PROJECT"}, "expiresAt": expires, "refreshAfter": expires},
					map[string]any{"service": "convex", "name": "Convex", "kind": "secret", "protection": "on-box", "error": "the saved key was deleted"},
				},
			})
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestSetupInASandbox(t *testing.T) {
	calls := noGcloud(t)
	lookGcloud = func() (string, error) { return "/usr/bin/gcloud", nil }
	r := newRig(t)
	const tok = "sk-stub-0123456789abcdef0123456789abcdef"
	edge := fakeEdge(t, tok, "sk-dlv-abc")
	home := t.TempDir()
	r.home = filepath.Join(home, ".keystub")
	r.env = map[string]string{"KEYSTUB_TOKEN": tok, "KEYSTUB_DELIVERY_KEY": "sk-dlv-abc", "KEYSTUB_EDGE": edge.URL, "HOME": home}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	res := r.must("", "setup", "--env-file", path, "--json")
	if strings.Contains(res.stdout, tok) || strings.Contains(res.stdout, "postgres://") || strings.Contains(res.stdout, "ya29") {
		t.Fatal("setup printed a value")
	}
	out := res.json(t)
	if out["env"] != "knowsis/dev" {
		t.Fatalf("result %v", out)
	}
	if got := names(out["set"]); got != "ANTHROPIC_API_KEY,ANTHROPIC_BASE_URL,CLOUDSDK_AUTH_ACCESS_TOKEN_FILE,CLOUDSDK_CORE_PROJECT,DATABASE_URL" {
		t.Fatalf("set %s", got)
	}
	prot := map[string]string{}
	for _, v := range out["set"].([]any) {
		m := v.(map[string]any)
		prot[m["name"].(string)] = m["protection"].(string)
	}
	if prot["ANTHROPIC_API_KEY"] != neverOnBox || prot["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] != shortLived || prot["DATABASE_URL"] != onBox {
		t.Fatalf("protection %v", prot)
	}
	if s := mustJSON(t, out["skipped"]); !strings.Contains(s, "EXA_API_KEY") {
		t.Fatalf("skipped %s", s)
	}
	if s := mustJSON(t, out["failed"]); !strings.Contains(s, "Convex") {
		t.Fatalf("failed %s", s)
	}

	text := readFile(t, path)
	tokenFile := filepath.Join(r.home, "files", "knowsis-dev", "google-cloud", "access-token")
	for _, want := range []string{"ANTHROPIC_BASE_URL=" + edge.URL + "/s/anthropic", "ANTHROPIC_API_KEY=" + tok, "DATABASE_URL=postgres://u:p@db/app", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=" + tokenFile} {
		if !strings.Contains(text, want) {
			t.Fatalf(".env lacks %s:\n%s", want, text)
		}
	}
	if readFile(t, tokenFile) != "ya29.minted" {
		t.Fatal("token file")
	}
	if st, _ := os.Stat(tokenFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", st.Mode())
	}
	// No .keystub.json in a sandbox: the token decides the environment.
	if _, err := os.Stat(filepath.Join(dir, projectFileName)); err == nil {
		t.Fatal("wrote .keystub.json in a sandbox")
	}

	// The CLIs: every variable exported for shells, the profile sources it,
	// and gcloud gets its own configuration.
	sh := readFile(t, filepath.Join(r.home, "env.sh"))
	if !strings.Contains(sh, "export DATABASE_URL='postgres://u:p@db/app'") {
		t.Fatalf("env.sh:\n%s", sh)
	}
	for _, rc := range []string{".profile", ".bashrc"} {
		if !strings.Contains(readFile(t, filepath.Join(home, rc)), profileLine) {
			t.Fatalf("%s doesn't source env.sh", rc)
		}
	}
	if s := mustJSON(t, *calls); !strings.Contains(s, "auth/access_token_file") || !strings.Contains(s, "acme-dev") {
		t.Fatalf("gcloud calls %s", s)
	}

	// Again: the profile line isn't added twice, and nothing needs a yes.
	r.must("", "setup", "--env-file", path, "--json")
	if n := strings.Count(readFile(t, filepath.Join(home, ".profile")), profileLine); n != 1 {
		t.Fatalf("profile line %d times", n)
	}

	// A token for another environment, a wrong delivery key, no edge.
	if res := r.run("", "setup", "other/dev", "--env-file", path, "--json"); res.code != ExitUsage {
		t.Fatalf("other env: %d %s", res.code, res.stdout)
	}
	r.env["KEYSTUB_DELIVERY_KEY"] = "sk-dlv-wrong"
	if res := r.run("", "setup", "--env-file", path, "--json"); res.code != ExitNoAuth || !strings.Contains(res.stdout, "delivery key") {
		t.Fatalf("wrong delivery key: %d %s", res.code, res.stdout)
	}
	delete(r.env, "KEYSTUB_EDGE")
	if res := r.run("", "setup", "--env-file", path, "--json"); res.code != ExitUsage || !strings.Contains(res.stdout, "KEYSTUB_EDGE") {
		t.Fatalf("no edge: %d %s", res.code, res.stdout)
	}
}

func TestSetupWithoutDeliveryKey(t *testing.T) {
	noGcloud(t)
	r := newRig(t)
	const tok = "sk-stub-0123456789abcdef0123456789abcdef"
	edge := fakeEdge(t, tok, "sk-dlv-abc")
	r.env = map[string]string{"KEYSTUB_TOKEN": tok, "KEYSTUB_EDGE": edge.URL}
	path := filepath.Join(t.TempDir(), ".env")
	out := r.must("", "setup", "--env-file", path, "--no-cli", "--json").json(t)
	if got := names(out["set"]); got != "ANTHROPIC_API_KEY,ANTHROPIC_BASE_URL" {
		t.Fatalf("set %s", got)
	}
	if !strings.Contains(mustJSON(t, out["skipped"]), "KEYSTUB_DELIVERY_KEY") {
		t.Fatalf("skipped %v", out["skipped"])
	}
	if _, err := os.Stat(filepath.Join(r.home, "env.sh")); err == nil {
		t.Fatal("--no-cli wrote env.sh")
	}
}

func TestTokensCreateDelivery(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "shop", "OPENAI_API_KEY=sk-real-openai\n")
	r.must("", "init", "--env-file", path, "--yes", "--json")
	res := r.must("", "tokens", "create", "shop/dev", "--name", "ci", "--ttl", "1h", "--delivery")
	if !strings.Contains(res.stdout, "KEYSTUB_TOKEN=sk-stub-") || !strings.Contains(res.stdout, "KEYSTUB_EDGE="+r.edge.URL) {
		t.Fatalf("stdout %s", res.stdout)
	}
	// This server makes no delivery key, and says so.
	if strings.Contains(res.stdout, "KEYSTUB_DELIVERY_KEY") || !strings.Contains(res.stderr, "no delivery key") {
		t.Fatalf("stdout %s stderr %s", res.stdout, res.stderr)
	}
	if res := r.run("", "tokens", "create", "shop/dev", "--name", "x", "--delivery", "--service", "openai"); res.code != ExitUsage {
		t.Fatalf("--delivery --service: %d", res.code)
	}
}

func names(v any) string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return strings.Join(out, ",")
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dotenvLine(text, name string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, name+"=") {
			return l
		}
	}
	return ""
}
