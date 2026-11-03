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
	if !strings.Contains(res.stdout, "--write-env") || !strings.Contains(res.stdout, "keystub doctor") {
		t.Errorf("next steps: %s", res.stdout)
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

	// Once the file holds tokens, init has nothing more to suggest writing.
	if again := r.must("", "init", "--env-file", path, "--json"); strings.Contains(again.stdout, "--write-env") {
		t.Errorf("suggests --write-env again: %s", again.stdout)
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
	// The next steps keep the key name.
	if !strings.Contains(res.stdout, "--key-name work") {
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
	if res := r.run("", "init", "--env-file", path, "--json"); res.code != ExitNotFound || !strings.Contains(res.stdout, "keys scan") {
		t.Errorf("only a token: %d %s", res.code, res.stdout)
	}
	if res := r.run("", "doctor", "--env-file", path, "--json"); res.code != ExitError || !strings.Contains(res.stdout, "keystub init") {
		t.Errorf("doctor, no environment: %d %s", res.code, res.stdout)
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
