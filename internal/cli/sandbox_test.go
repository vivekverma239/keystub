package cli

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker answers the docker commands sandbox runs, as Docker would.
type fakeDocker struct {
	mu        sync.Mutex
	running   map[string]bool
	files     map[string]string // what was copied into /workspace
	appended  string            // what --copy-env appended to .env
	envFile   string            // the --env-file's content, read when run
	calls     [][]string
	failSetup bool
}

func (d *fakeDocker) exec(stdin io.Reader, stdout, stderr io.Writer, _ []string, name string, args ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name != "docker" {
		return errors.New("only docker here")
	}
	d.calls = append(d.calls, args)
	switch args[0] {
	case "info":
		_, _ = io.WriteString(stdout, "29.0\n")
	case "run":
		for i, a := range args {
			if a == "--env-file" {
				b, _ := os.ReadFile(args[i+1])
				d.envFile = string(b)
			}
			if a == "--name" {
				d.running[args[i+1]] = true
			}
		}
		_, _ = io.WriteString(stdout, "abc123\n")
	case "cp":
	case "port":
		_, _ = io.WriteString(stdout, "127.0.0.1:49153\n")
	case "rm":
		delete(d.running, args[len(args)-1])
	case "inspect":
		_, _ = io.WriteString(stdout, "running\n")
	case "exec":
		line := strings.Join(args, " ")
		switch {
		case strings.Contains(line, "tar -x"):
			tr := tar.NewReader(stdin)
			for {
				h, err := tr.Next()
				if err != nil {
					break
				}
				b, _ := io.ReadAll(tr)
				d.files[h.Name] = string(b)
			}
		case strings.Contains(line, "cat >>"):
			b, _ := io.ReadAll(stdin)
			d.appended += string(b)
		case strings.Contains(line, "keystub setup --json"):
			if d.failSetup {
				_, _ = io.WriteString(stdout, "keystub: the edge refused KEYSTUB_TOKEN\n")
				return errors.New("exit 1")
			}
			_, _ = io.WriteString(stdout, "a notice on stderr\n"+`{"set":[{"name":"OPENAI_API_KEY","service":"openai","protection":"never-on-box"},{"name":"OPENAI_BASE_URL","service":"openai","protection":"never-on-box"}],"skipped":[{"var":"EXA_API_KEY","reason":"no base URL"}],"failed":[]}`+"\n")
		case strings.Contains(line, "keystub tools install --json"):
			_, _ = io.WriteString(stdout, "Downloading…\n{\n  \"tools\": [\n    {\n      \"name\": \"fly\",\n      \"installed\": true\n    }\n  ]\n}\n")
		case strings.Contains(line, `exec keystub run --remote "$KEYSTUB_EDGE" -- "$@"`), strings.Contains(line, `exec "$@"`):
			_, _ = io.WriteString(stdout, "ran\n")
		}
	}
	return nil
}

// fakeTokens is a hosted Keystub that makes and revokes environment tokens.
type fakeTokens struct {
	mu      sync.Mutex
	srv     *httptest.Server
	made    []map[string]any
	revoked []string
}

func newFakeTokens(t *testing.T) *fakeTokens {
	f := &fakeTokens{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/environments/acme/dev/setup", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"edgeUrl":"https://edge.example"}`)
	})
	mux.HandleFunc("POST /api/environments/acme/dev/tokens", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.made = append(f.made, body)
		f.mu.Unlock()
		exp := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
		_, _ = io.WriteString(w, `{"token":{"id":"tk_1","name":"`+body["name"].(string)+`","env":"acme/dev","token":"sk-stub-faketoken0000","expiresAt":"`+exp+`","deliveryKey":"dk_fake"}}`)
	})
	mux.HandleFunc("POST /api/tokens/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PathValue("id"))
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTokens) run(t *testing.T, home string, d *fakeDocker, cmd string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := map[string]string{"KEYSTUB_SERVER": f.srv.URL, "KEYSTUB_API_KEY": "skcli_abc", "HOME": home}
	code := Main(Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return env[k] }, Home: filepath.Join(home, ".keystub"), Hostname: "testbox",
		Sleep: func(time.Duration) {}, Exec: d.exec,
	}, cmd, args)
	return result{code, out.String(), errb.String()}
}

func TestSandbox(t *testing.T) {
	f := newFakeTokens(t)
	d := &fakeDocker{running: map[string]bool{}, files: map[string]string{}}
	home, dir := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"acme"}`)
	writeFile(t, filepath.Join(dir, "src", "index.ts"), "console.log(1)\n")
	writeFile(t, filepath.Join(dir, ".env"), "OPENAI_API_KEY=sk-real-key-never-copied\nAPI_URL=https://api.acme.test\nSTRIPE_SECRET=sk_test_fake\nPORT=3000\n")
	writeFile(t, filepath.Join(dir, ".env.local"), "X=1\n")
	writeFile(t, filepath.Join(dir, ".env.example"), "OPENAI_API_KEY=\n")
	writeFile(t, filepath.Join(dir, "node_modules", "x", "index.js"), "")
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref\n")
	writeFile(t, filepath.Join(dir, "runner", "fly.toml"), "app = \"acme-runner\"\n")

	r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--dir", dir, "--name", "t1", "--port", "3000", "--copy-env", "API_URL", "--keystub", "/tmp/keystub-linux", "--json")
	if r.code != 0 {
		t.Fatalf("start: %d %s %s", r.code, r.stdout, r.stderr)
	}
	res := r.json(t)
	// The code, without history, dependencies or a .env file but the example.
	for _, want := range []string{"package.json", "src/index.ts", ".env.example", "runner/fly.toml"} {
		if _, ok := d.files[want]; !ok {
			t.Errorf("%s wasn't copied: %v", want, d.files)
		}
	}
	for n := range d.files {
		if strings.HasPrefix(n, ".git") || strings.HasPrefix(n, "node_modules") || n == ".env" || n == ".env.local" {
			t.Errorf("copied %s", n)
		}
	}
	// The token went in through a file, which is gone now; it isn't printed.
	if !strings.Contains(d.envFile, "KEYSTUB_TOKEN=sk-stub-faketoken0000") || !strings.Contains(d.envFile, "KEYSTUB_DELIVERY_KEY=dk_fake") {
		t.Errorf("env file %q", d.envFile)
	}
	if _, err := os.Stat(filepath.Join(home, ".keystub", "sandboxes", ".t1.env")); err == nil {
		t.Error("the access file was left behind")
	}
	if strings.Contains(r.stdout+r.stderr, "sk-stub-faketoken0000") || strings.Contains(r.stdout+r.stderr, "sk-real-key") {
		t.Error("printed a token or key")
	}
	if len(f.made) != 1 || f.made[0]["name"] != "sandbox-t1" || f.made[0]["ttl"] != "2h" || f.made[0]["delivery"] != true {
		t.Errorf("token %v", f.made)
	}
	// Only the variable named is copied in; the rest are reported.
	if d.appended != "API_URL=https://api.acme.test\n" {
		t.Errorf("appended %q", d.appended)
	}
	nis, _ := res["notInSandbox"].(map[string]any)
	if s, _ := json.Marshal(nis); string(s) != `{"config":["PORT"],"secrets":["STRIPE_SECRET"]}` {
		t.Errorf("notInSandbox %s", s)
	}
	if p, _ := res["ports"].(map[string]any); p["3000"] != "http://127.0.0.1:49153" {
		t.Errorf("ports %v", res["ports"])
	}
	if tl, _ := res["tools"].([]any); len(tl) != 1 {
		t.Errorf("tools %v", res["tools"])
	}

	// Commands run through Keystub's proxy, unless --direct.
	d.calls = nil
	if r := f.run(t, home, d, "sandbox", "exec", "t1", "--", "npm", "test"); r.code != 0 || !strings.Contains(r.stdout, "ran") {
		t.Fatalf("exec: %d %s %s", r.code, r.stdout, r.stderr)
	}
	last := strings.Join(d.calls[len(d.calls)-1], " ")
	if !strings.Contains(last, "keystub run --remote") || !strings.HasSuffix(last, "bash npm test") {
		t.Errorf("exec ran %q", last)
	}
	_ = f.run(t, home, d, "sandbox", "exec", "t1", "--direct", "--", "ls")
	if last := strings.Join(d.calls[len(d.calls)-1], " "); strings.Contains(last, "keystub run") {
		t.Errorf("--direct ran %q", last)
	}

	if r := f.run(t, home, d, "sandbox", "list", "--json"); !strings.Contains(r.stdout, `"name": "t1"`) {
		t.Errorf("list %s", r.stdout)
	}
	if r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--dir", dir, "--name", "t1", "--json"); r.code != ExitConflict {
		t.Errorf("a second t1: %d", r.code)
	}
	if r := f.run(t, home, d, "sandbox", "stop", "t1", "--json"); r.code != 0 {
		t.Fatalf("stop: %d %s", r.code, r.stderr)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "tk_1" || len(d.running) != 0 {
		t.Errorf("revoked %v, running %v", f.revoked, d.running)
	}
	if r := f.run(t, home, d, "sandbox", "exec", "t1", "--", "ls"); r.code != ExitNotFound {
		t.Errorf("exec after stop: %d", r.code)
	}
}

func TestSandboxFailures(t *testing.T) {
	f := newFakeTokens(t)
	home, dir := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "API_URL=x\n")

	// --copy-env of a name the file doesn't set: nothing is left running.
	d := &fakeDocker{running: map[string]bool{}, files: map[string]string{}}
	r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--dir", dir, "--name", "t2", "--copy-env", "NOPE", "--keystub", "/k", "--json")
	if r.code != ExitNotFound || len(d.running) != 0 || len(f.made) != 0 {
		t.Errorf("bad --copy-env: %d running %v made %v (%s)", r.code, d.running, f.made, r.stdout)
	}
	if _, err := os.Stat(filepath.Join(home, ".keystub", "sandboxes", "t2.json")); err == nil {
		t.Error("state left for a sandbox that's gone")
	}
	// Docker not running: no token is made.
	before := len(f.made)
	noDocker := func(io.Reader, io.Writer, io.Writer, []string, string, ...string) error {
		return errors.New("Cannot connect to the Docker daemon")
	}
	var out bytes.Buffer
	code := Main(Env{Stdout: &out, Stderr: &out, Stdin: strings.NewReader(""), Getenv: func(k string) string {
		return map[string]string{"KEYSTUB_SERVER": f.srv.URL, "KEYSTUB_API_KEY": "skcli_abc"}[k]
	}, Home: filepath.Join(home, ".keystub"), Exec: noDocker}, "sandbox", []string{"start", "acme/dev", "--dir", dir, "--json"})
	if code != ExitError || len(f.made) != before || !strings.Contains(out.String(), "Docker isn't running") {
		t.Errorf("no docker: %d %s", code, out.String())
	}
	// A variable Keystub gives can't be copied in: that's the real key.
	d = &fakeDocker{running: map[string]bool{}, files: map[string]string{}}
	writeFile(t, filepath.Join(dir, ".env"), "API_URL=x\nOPENAI_API_KEY=sk-real\n")
	r = f.run(t, home, d, "sandbox", "start", "acme/dev", "--dir", dir, "--name", "t3", "--copy-env", "OPENAI_API_KEY", "--keystub", "/k", "--json")
	if r.code != ExitError || d.appended != "" || len(d.running) != 0 || !strings.Contains(r.stdout, "Keystub gives") {
		t.Errorf("copying a given key: %d appended %q (%s)", r.code, d.appended, r.stdout)
	}
	if _, err := os.Stat(filepath.Join(home, ".keystub", "sandboxes", "t3.json")); err == nil {
		t.Error("state left after a failed start")
	}
	// --copy-env with no env file to read.
	if r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--dir", t.TempDir(), "--copy-env", "API_URL", "--json"); r.code != ExitNotFound {
		t.Errorf("no env file: %d", r.code)
	}
	if r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--port", "99999", "--json"); r.code != ExitUsage {
		t.Errorf("port 99999: %d", r.code)
	}
	if r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--name", "Bad_Name", "--json"); r.code != ExitUsage {
		t.Errorf("bad name: %d", r.code)
	}
	if r := f.run(t, home, d, "sandbox", "start", "acme/dev", "--port", "http", "--json"); r.code != ExitUsage {
		t.Errorf("bad port: %d", r.code)
	}
}
