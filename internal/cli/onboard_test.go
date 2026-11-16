package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
)

// writeDotenv makes a project folder named dir with a .env in it.
func writeDotenv(t *testing.T, dir, text string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d, ".env")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInit(t *testing.T) {
	r := newRig(t)
	const text = "OPENAI_API_KEY=sk-real-openai\nANTHROPIC_API_KEY=sk-ant-real\nPORT=3000\n"
	path := writeDotenv(t, "My App", text)

	// The plan changes nothing, and names the folder's project.
	res := r.must("", "init", "--env-file", path, "--dry-run", "--json")
	if strings.Contains(res.stdout, "sk-real") || strings.Contains(res.stdout, "sk-ant") {
		t.Fatal("the plan printed a value")
	}
	plan := res.json(t)
	if plan["env"] != "my-app/dev" || plan["makeEnv"] != true || plan["changes"] != true || plan["writeEnv"] != false {
		t.Fatalf("plan %v", plan)
	}
	steps := plan["steps"].([]any)
	if len(steps) != 2 {
		t.Fatalf("steps %v", steps)
	}
	for _, s := range steps {
		st := s.(map[string]any)
		if st["saveKey"] != true || st["link"] != true || st["addService"] != true {
			t.Errorf("step %v", st)
		}
	}
	if strings.Contains(r.must("", "envs", "list", "--json").stdout, "my-app/dev") {
		t.Fatal("--dry-run made the environment")
	}

	// Nothing is done until the person says yes.
	if res := r.run("", "init", "--env-file", path, "--json"); res.code != ExitUsage || !strings.Contains(res.stdout, "--yes") {
		t.Fatalf("init without --yes: %d %s", res.code, res.stdout)
	}

	res = r.must("", "init", "--env-file", path, "--yes", "--json")
	if strings.Contains(res.stdout+res.stderr, "sk-real") {
		t.Fatal("init printed a value")
	}
	for svc, want := range map[string]string{"openai": "sk-real-openai", "anthropic": "sk-ant-real"} {
		if got, _ := r.engine.RealKey(context.Background(), "my-app/dev", svc); got != want {
			t.Errorf("%s: %q", svc, got)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != text {
		t.Fatalf("init changed the file without --write-env:\n%s", b)
	}
	if !strings.Contains(res.stdout, "keystub setup my-app/dev") || !strings.Contains(res.stdout, "keystub doctor") {
		t.Errorf("next steps: %s", res.stdout)
	}
	if readProjectFile(filepath.Dir(path)) != "my-app/dev" {
		t.Error("init wrote no .keystub.json")
	}

	// Again: nothing left to do, and an existing link is left alone.
	if again := r.must("", "init", "--env-file", path, "--json").json(t); again["changes"] != false {
		t.Fatalf("second init: %v", again)
	}

	// Doctor, before the file has a token: the keys are still real.
	res = r.must("", "doctor", "--env-file", path, "--json")
	if doc := res.json(t); doc["ok"] != true || !strings.Contains(res.stdout, "still the real openai key") {
		t.Fatalf("doctor: %s", res.stdout)
	}

	// The --write-env plan names every variable it would set.
	plan = r.must("", "init", "--env-file", path, "--write-env", "--base-urls", "--dry-run", "--json").json(t)
	if got := strings.Join(toStrings(plan["writeVars"]), ","); got != "ANTHROPIC_BASE_URL,ANTHROPIC_API_KEY,OPENAI_BASE_URL,OPENAI_API_KEY" {
		t.Errorf("writeVars %s", got)
	}
	if res := r.run("", "init", "--env-file", path, "--base-urls", "--json"); res.code != ExitUsage {
		t.Errorf("--base-urls alone: %d", res.code)
	}

	// With --write-env: a token in the file, after a copy is kept.
	res = r.must("", "init", "--env-file", path, "--write-env", "--base-urls", "--yes", "--json")
	if strings.Contains(res.stdout+res.stderr, core.TokenPrefix) {
		t.Fatal("init printed the token")
	}
	out := res.json(t)
	backup, _ := out["backup"].(string)
	if b, _ := os.ReadFile(backup); string(b) != text || filepath.Dir(backup) != filepath.Join(r.home, "backups") {
		t.Fatalf("backup %q:\n%s", backup, b)
	}
	tok, _ := dotenvValue(path, "OPENAI_API_KEY")
	if !strings.HasPrefix(tok, core.TokenPrefix) {
		t.Fatalf("OPENAI_API_KEY=%q", tok)
	}
	if base, _ := dotenvValue(path, "OPENAI_BASE_URL"); base != r.edge.URL+"/s/openai/v1" {
		t.Errorf("OPENAI_BASE_URL=%q", base)
	}
	if code, real := r.call("openai", tok); code != 200 || real != "sk-real-openai" {
		t.Errorf("the token from the file: %d %q", code, real)
	}

	// Doctor, after: the token works through the edge.
	res = r.must("", "doctor", "--env-file", path, "--json")
	if strings.Contains(res.stdout, core.TokenPrefix) {
		t.Fatal("doctor printed the token")
	}
	doc := res.json(t)
	if doc["ok"] != true || !strings.Contains(res.stdout, "the token works") || !strings.Contains(res.stdout, "points at Keystub") {
		t.Fatalf("doctor after: %s", res.stdout)
	}

	// Once the file holds tokens, init has nothing more to suggest writing,
	// and a --write-env plan has nothing to write.
	if again := r.must("", "init", "--env-file", path, "--json"); strings.Contains(again.stdout, "--write-env") {
		t.Errorf("suggests --write-env again: %s", again.stdout)
	}
	if again := r.must("", "init", "--env-file", path, "--write-env", "--dry-run", "--json").json(t); again["writeVars"] != nil || again["changes"] != false {
		t.Errorf("--write-env plan after: %v", again)
	}

	// A token for a service the environment doesn't link fails, as one
	// JSON value on stdout.
	r.must("", "envs", "unlink", "my-app/dev", "anthropic")
	res = r.run("", "doctor", "--env-file", path, "--json")
	if res.code != ExitError || !strings.Contains(res.stdout, "doesn't link anthropic") {
		t.Fatalf("doctor, unlinked: %d %s", res.code, res.stdout)
	}
	if e, _ := res.json(t)["error"].(map[string]any); e == nil || e["checks"] == nil {
		t.Errorf("doctor's failure: %s", res.stdout)
	}
	if res := r.run("", "doctor", "my-app/dev", "--env-file", path+".missing", "--json"); res.code != ExitError {
		t.Errorf("doctor, no file: %d %s", res.code, res.stdout)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestInitLeavesUnclearValues(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "app", "OPENAI_API_KEY=sk-real\nANTHROPIC_API_KEY=sk-ant$x\n")
	res := r.must("", "init", "--env-file", path, "--key-name", "work", "--yes", "--json")
	out := res.json(t)
	if len(out["steps"].([]any)) != 1 || len(out["skipped"].([]any)) != 1 || strings.Contains(res.stdout, "sk-ant") {
		t.Fatalf("init: %s", res.stdout)
	}
	if got, _ := r.engine.RealKey(context.Background(), "app/dev", "openai"); got != "sk-real" {
		t.Errorf("openai: %q", got)
	}
	// The next step is setup, which needs no key name.
	if !strings.Contains(res.stdout, "keystub setup app/dev") {
		t.Errorf("next steps: %s", res.stdout)
	}
}

func TestInitRefusals(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "app", "PORT=3000\n")
	if res := r.run("", "init", "--env-file", path, "--json"); res.code != ExitNotFound {
		t.Errorf("no keys: %d %s", res.code, res.stdout)
	}
	if res := r.run("", "init", "--env-file", filepath.Join(t.TempDir(), ".env")); res.code == 0 {
		t.Error("a missing file")
	}
	path = writeDotenv(t, "app", "OPENAI_API_KEY=sk-stub-abc\n")
	if res := r.run("", "init", "--env-file", path, "--json"); res.code != ExitError || !strings.Contains(res.stdout, "already a Keystub token") {
		t.Errorf("only a token: %d %s", res.code, res.stdout)
	}
	if res := r.run("", "doctor", "--env-file", path, "--json"); res.code != ExitError || !strings.Contains(res.stdout, "keystub init") {
		t.Errorf("doctor, no environment: %d %s", res.code, res.stdout)
	}
}

func TestInitUsesTheAccountsKey(t *testing.T) {
	r := newRig(t)
	// A teammate saved the team's OpenAI key and linked it.
	r.must("", "services", "add", "openai")
	r.must("sk-team-openai", "keys", "add", "openai", "--name", "team")
	r.must("", "envs", "add", "web/dev")
	r.must("", "envs", "link", "web/dev", "openai", "team", "--no-token")
	path := writeDotenv(t, "api", "OPENAI_API_KEY=sk-mine\n")

	plan := r.must("", "init", "--env-file", path, "--dry-run", "--json")
	if !strings.Contains(plan.stdout, `"key": "team"`) || !strings.Contains(plan.stdout, `"shared": true`) || !strings.Contains(plan.stdout, `"saveKey": false`) {
		t.Fatalf("plan: %s", plan.stdout)
	}
	r.must("", "init", "--env-file", path, "--yes")
	if got, _ := r.engine.RealKey(context.Background(), "api/dev", "openai"); got != "sk-team-openai" {
		t.Errorf("linked %q, want the team's key", got)
	}
	if n := len(r.must("", "keys", "list", "--service", "openai", "--json").json(t)["keys"].([]any)); n != 1 {
		t.Errorf("%d openai keys: init saved a copy", n)
	}

	// A copied .env.example, with no key of the teammate's own, still
	// gets the team's.
	path = writeDotenv(t, "worker", "OPENAI_API_KEY=\n")
	r.must("", "init", "--env-file", path, "--yes")
	if got, _ := r.engine.RealKey(context.Background(), "worker/dev", "openai"); got != "sk-team-openai" {
		t.Errorf("empty value: linked %q", got)
	}

	// Named, the file's key is saved under that name instead.
	path = writeDotenv(t, "cli", "OPENAI_API_KEY=sk-mine\n")
	r.must("", "init", "--env-file", path, "--key-name", "mine", "--yes")
	if got, _ := r.engine.RealKey(context.Background(), "cli/dev", "openai"); got != "sk-mine" {
		t.Errorf("--key-name linked %q", got)
	}
}

func TestInitExplainsSkippedKeys(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "app", "OPENAI_API_KEY=sk-a$b\n")
	res := r.run("", "init", "--env-file", path, "--dry-run", "--json")
	if res.code != ExitError || !strings.Contains(res.stdout, "OPENAI_API_KEY") || !strings.Contains(res.stdout, "skipped") || strings.Contains(res.stdout, "sk-a") {
		t.Fatalf("all skipped: %d %s", res.code, res.stdout)
	}
	// A suggested command quotes what needs it.
	if got := shellQuote("/x/My App/.env"); got != `'/x/My App/.env'` {
		t.Errorf("shellQuote = %s", got)
	}
}

func TestBackupOfALongPath(t *testing.T) {
	r := newRig(t)
	dir := filepath.Join(t.TempDir(), strings.Repeat("a", 120), strings.Repeat("b", 120))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".env")
	_ = os.WriteFile(path, []byte("X=1\n"), 0o600)
	c := &ctx{Env: Env{Home: r.home}}
	b, err := c.backupDotenv(path)
	if err != nil || len(filepath.Base(b)) > 120 {
		t.Fatalf("backup %q: %v", b, err)
	}
}

func TestDefaultEnv(t *testing.T) {
	for in, want := range map[string]string{
		"/x/My App/.env":         "my-app/dev",
		"/x/agentic_search/.env": "agentic-search/dev",
		"/x/--/.env":             "app/dev",
	} {
		if got := defaultEnv(in); got != want {
			t.Errorf("defaultEnv(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStatus(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "Shop", "OPENAI_API_KEY=sk-real-openai\nANTHROPIC_API_KEY=sk-ant-real\nPORT=3000\n")
	r.env["HOME"] = r.home

	// Before anything is set up: the environment isn't made, init is next.
	st := r.must("", "status", "--env-file", path, "--json").json(t)
	if st["signedIn"] != true || st["envExists"] != false || st["env"] != "shop/dev" {
		t.Fatalf("status: %v", st)
	}
	file := st["file"].(map[string]any)
	if got := strings.Join(toStrings(file["realKeys"]), ","); got != "ANTHROPIC_API_KEY,OPENAI_API_KEY" {
		t.Errorf("realKeys %s", got)
	}
	if next := strings.Join(toStrings(st["next"]), "\n"); !strings.Contains(next, "keystub init") || !strings.Contains(next, "--dry-run") {
		t.Errorf("next: %s", next)
	}

	// After init, the keys are linked but still in the file: setup is next.
	r.must("", "init", "--env-file", path, "--yes", "--json")
	res := r.must("", "status", "--env-file", path, "--json")
	if strings.Contains(res.stdout, "sk-real") || strings.Contains(res.stdout, "sk-ant") {
		t.Fatal("status printed a value")
	}
	st = res.json(t)
	if st["envExists"] != true || len(st["services"].([]any)) != 2 {
		t.Fatalf("status after init: %v", st)
	}
	if next := strings.Join(toStrings(st["next"]), "\n"); !strings.Contains(next, "keystub setup") || strings.Contains(next, "keystub init") {
		t.Errorf("next after init: %s", next)
	}

	// A token for some services shows what it covers.
	r.must("", "tokens", "create", "shop/dev", "--name", "pair", "--service", "openai,anthropic", "--json")
	st = r.must("", "status", "--env-file", path, "--json").json(t)
	toks := st["tokens"].([]any)
	var pair map[string]any
	for _, x := range toks {
		if m := x.(map[string]any); m["name"] == "pair" {
			pair = m
		}
	}
	if pair == nil || len(pair["covers"].([]any)) != 2 {
		t.Fatalf("tokens: %v", toks)
	}

	// Signed out: no error, and the next step is to sign in.
	delete(r.env, "KEYSTUB_API_KEY")
	res = r.run("", "status", "--env-file", path, "--json")
	if res.code != 0 {
		t.Fatalf("signed out: exit %d %s", res.code, res.stdout+res.stderr)
	}
	if st = res.json(t); st["signedIn"] != false || !strings.Contains(strings.Join(toStrings(st["next"]), ""), "keystub login") {
		t.Errorf("signed out: %v", st)
	}
	if f := st["file"].(map[string]any); f["realKeys"] != nil {
		t.Errorf("signed out, realKeys should be unknown (null): %v", f["realKeys"])
	}

	// A server that doesn't answer: still a report, with the reason.
	r.env["KEYSTUB_API_KEY"] = "admintoken"
	r.env["KEYSTUB_SERVER"] = "http://127.0.0.1:1"
	res = r.run("", "status", "--env-file", path, "--json")
	if st = res.json(t); res.code != 0 || st["signedIn"] != false || st["signInError"] == nil {
		t.Errorf("unreachable server: %d %v", res.code, st)
	}
}

func TestStatusNamesANonDefaultEnvironment(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "Shop", "OPENAI_API_KEY=sk-real-openai\n")
	r.env["HOME"] = r.home
	r.must("", "init", "shop/staging", "--env-file", path, "--yes", "--json")
	st := r.must("", "status", "--env-file", path, "--json").json(t)
	if st["env"] != "shop/staging" {
		t.Fatalf("env %v", st["env"])
	}
	next := strings.Join(toStrings(st["next"]), "\n")
	if !strings.Contains(next, "shop/staging") || strings.Contains(next, "keystub init") {
		t.Errorf("next after init of shop/staging: %s", next)
	}
}

func TestStatusServiceWithNoBaseURL(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "Tool", "GITHUB_TOKEN=ghp_realrealreal\n")
	r.env["HOME"] = r.home
	r.must("", "init", "--env-file", path, "--yes", "--json")
	st := r.must("", "status", "--env-file", path, "--json").json(t)
	next := strings.Join(toStrings(st["next"]), "\n")
	if strings.Contains(next, "keystub setup") || strings.Contains(next, "keystub init") || !strings.Contains(next, "--service github --write-env") {
		t.Fatalf("next for a key with no base URL: %s", next)
	}
	// Following it leaves nothing to do but check.
	r.must("", "tokens", "create", "tool/dev", "--name", "local", "--service", "github", "--write-env", path, "--yes", "--json")
	st = r.must("", "status", "--env-file", path, "--json").json(t)
	if next = strings.Join(toStrings(st["next"]), "\n"); !strings.Contains(next, "keystub doctor") || strings.Contains(next, "tokens create") {
		t.Fatalf("next after the token: %s", next)
	}
}
