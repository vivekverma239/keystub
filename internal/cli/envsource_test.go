package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindEnvSource(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env.example"), "OPENAI_API_KEY=sk-your-key-here\n")
	src, err := findEnvSource(dir)
	if err != nil || src.Kind != "example" || len(src.Names) != 1 || src.Values["OPENAI_API_KEY"] != "" {
		t.Fatalf("example: %+v %v", src, err)
	}
	// A real file comes first, values and all.
	write(t, filepath.Join(dir, ".env.local"), "OPENAI_API_KEY=sk-real\n")
	if src, _ := findEnvSource(dir); src.Kind != "file" || src.Values["OPENAI_API_KEY"] != "sk-real" || filepath.Base(src.File) != ".env.local" {
		t.Fatalf("local: %+v", src)
	}
}

func TestScanCode(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "src", "ai.ts"), "const k = process.env.OPENAI_API_KEY;\nconst u = process.env['DATABASE_URL'];\nif (process.env.NODE_ENV) {}\nimport.meta.env.VITE_SITE\n")
	write(t, filepath.Join(dir, "worker", "main.py"), "import os\nos.environ.get(\"STRIPE_SECRET_KEY\")\nos.getenv('REDIS_URL')\n")
	write(t, filepath.Join(dir, "cmd", "main.go"), "x := os.Getenv(\"RESEND_API_KEY\")\n")
	write(t, filepath.Join(dir, "node_modules", "dep", "index.js"), "process.env.SHOULD_NOT_APPEAR\n")
	write(t, filepath.Join(dir, ".hidden", "x.js"), "process.env.HIDDEN_TOO\n")
	names, found := scanCode(dir)
	got := strings.Join(names, ",")
	if got != "DATABASE_URL,OPENAI_API_KEY,REDIS_URL,RESEND_API_KEY,STRIPE_SECRET_KEY,VITE_SITE" {
		t.Fatalf("names %s", got)
	}
	if found["STRIPE_SECRET_KEY"] != filepath.Join("worker", "main.py") {
		t.Fatalf("found in %v", found)
	}
}

func TestLooksSecret(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        bool
	}{
		{"DATABASE_URL", "postgres://u:p@h/db", true},
		{"DIRECT_URL", "postgres://u:p@h/db", true},
		{"CONVEX_DEPLOY_KEY", "prod:abc", true},
		{"STRIPE_WEBHOOK_SECRET", "whsec_1", true},
		{"JWT_SIGNING_KEY", "x", true},
		{"REDIS_URL", "redis://h:6379", true},
		{"SMTP_PASSWORD", "x", true},
		{"NEXT_PUBLIC_STRIPE_KEY", "pk_live", false},
		{"VITE_API_TOKEN", "x", false},
		{"PORT", "3000", false},
		{"APP_URL", "https://example.com", false},
		{"NEXTAUTH_URL", "http://localhost:3000", false},
		{"FEATURE_FLAGS", "a,b", false},
		{"KEYBOARD_LAYOUT", "us", false},
	} {
		if got := looksSecret(c.name, c.value); got != c.want {
			t.Errorf("looksSecret(%s) = %v", c.name, got)
		}
	}
}

func TestInitFromAnExample(t *testing.T) {
	r := newRig(t)
	// The account has an OpenAI key already, from another project.
	other := writeDotenv(t, "other", "OPENAI_API_KEY=sk-real-openai\n")
	r.must("", "init", "--env-file", other, "--yes", "--json")

	dir := filepath.Join(t.TempDir(), "shop")
	write(t, filepath.Join(dir, ".env.example"), "OPENAI_API_KEY=sk-your-key\nANTHROPIC_API_KEY=\nDATABASE_URL=postgres://user:pass@localhost/shop\n")
	t.Chdir(dir)
	plan := r.must("", "init", "--dry-run", "--json").json(t)
	if plan["source"] != "example" || plan["env"] != "shop/dev" {
		t.Fatalf("plan %v", plan)
	}
	steps := mustJSON(t, plan["steps"])
	if !strings.Contains(steps, `"service":"openai"`) || !strings.Contains(steps, `"saveKey":false`) || strings.Contains(steps, "sk-your-key") {
		t.Fatalf("steps %s", steps)
	}
	skips := mustJSON(t, plan["skipped"])
	if !strings.Contains(skips, "ANTHROPIC_API_KEY") || !strings.Contains(skips, "only in") {
		t.Fatalf("skipped %s", skips)
	}
	// This server can't hold secrets, and an example's value is no value.
	if strings.Contains(skips, "DATABASE_URL") {
		t.Fatalf("an example's DATABASE_URL reported: %s", skips)
	}
	if res := r.run("", "init", "--write-env", "--yes", "--json"); res.code != ExitUsage || !strings.Contains(res.stdout, "keystub setup") {
		t.Fatalf("--write-env from an example: %d %s", res.code, res.stdout)
	}
	r.must("", "init", "--yes", "--json")
	if readProjectFile(dir) != "shop/dev" {
		t.Fatal("no .keystub.json")
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.example")); err != nil {
		t.Fatal(err)
	}
}

func TestInitFromTheCode(t *testing.T) {
	r := newRig(t)
	dir := filepath.Join(t.TempDir(), "api")
	write(t, filepath.Join(dir, "src", "index.ts"), "new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\nconst flag = process.env.FEATURE_X;\n")
	t.Chdir(dir)
	res := r.run("", "init", "--dry-run", "--json")
	// No value anywhere: nothing init can save, and it says what's missing.
	if res.code != ExitError || !strings.Contains(res.stdout, "OPENAI_API_KEY") || !strings.Contains(res.stdout, filepath.Join("src", "index.ts")) {
		t.Fatalf("%d %s", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "FEATURE_X") && !strings.Contains(res.stdout, "not a key or secret") {
		t.Fatalf("FEATURE_X: %s", res.stdout)
	}
}

func TestInitLeavesSecretsTheServerCantHold(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "app", "OPENAI_API_KEY=sk-real-openai\nCONVEX_DEPLOY_KEY=dev:abc\nPORT=3000\n")
	plan := r.must("", "init", "--env-file", path, "--dry-run", "--json").json(t)
	if s := mustJSON(t, plan["skipped"]); !strings.Contains(s, "CONVEX_DEPLOY_KEY") || !strings.Contains(s, "can't hold") || strings.Contains(s, "PORT") {
		t.Fatalf("skipped %s", s)
	}
}
