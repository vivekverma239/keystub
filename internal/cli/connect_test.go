package cli

import (
	"bytes"
	"encoding/json"
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

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDetectDeploys(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "runner", "fly.toml"), "# x\napp = \"acme-runner\"\nprimary_region = 'iad'\n")
	writeFile(t, filepath.Join(dir, "worker", "fly.toml"), "app = 'acme-worker'\n")
	writeFile(t, filepath.Join(dir, "wrangler.jsonc"), "{\n  // the web app\n  \"name\": \"acme-web\",\n  \"account_id\": \"49ED8E403F061C8E058A965CBF3ABB6C\",\n  \"routes\": [{\"pattern\": \"x\"}]\n}\n")
	writeFile(t, filepath.Join(dir, "convex", "schema.ts"), "export default {}\n")
	writeFile(t, filepath.Join(dir, ".env.cloud"), "CONVEX_DEPLOYMENT=prod:happy-animal-123\nCONVEX_URL=https://happy-animal-123.convex.cloud\n")
	writeFile(t, filepath.Join(dir, ".env.local"), "CONVEX_DEPLOYMENT=dev:quiet-otter-1\n")
	// Never searched: dependencies, and too deep.
	writeFile(t, filepath.Join(dir, "node_modules", "x", "fly.toml"), "app = \"theirs\"\n")
	writeFile(t, filepath.Join(dir, "a", "b", "c", "d", "fly.toml"), "app = \"deep\"\n")

	got := map[string]deployTarget{}
	for _, d := range detectDeploys(dir) {
		got[d.Kind] = d
	}
	if len(got) != 3 {
		t.Fatalf("found %v", got)
	}
	if f := got["fly"]; f.Target != "acme-runner" || f.File != filepath.Join("runner", "fly.toml") || len(f.Others) != 1 || f.Others[0] != "acme-worker" {
		t.Errorf("fly %+v", f)
	}
	if c := got["cloudflare"]; c.Target != "acme-web" || c.Account != "49ed8e403f061c8e058a965cbf3abb6c" || c.Service != "cloudflare-minted" {
		t.Errorf("cloudflare %+v", c)
	}
	if c := got["convex"]; c.Target != "happy-animal-123" || c.Service != "convex" {
		t.Errorf("convex %+v", c)
	}

	// A deploy key names its deployment before |; nothing after it is read.
	dir2 := t.TempDir()
	writeFile(t, filepath.Join(dir2, "convex", "_generated", "api.d.ts"), "")
	writeFile(t, filepath.Join(dir2, ".env"), "export CONVEX_DEPLOY_KEY='prod:brave-fox-9|secretpart'\n")
	writeFile(t, filepath.Join(dir2, "wrangler.toml"), "name = \"site\"\n[vars]\nname = \"not-this\"\n")
	for _, d := range detectDeploys(dir2) {
		if d.Kind == "convex" && d.Target != "brave-fox-9" {
			t.Errorf("convex %+v", d)
		}
		if d.Kind == "cloudflare" && (d.Target != "site" || d.Account != "") {
			t.Errorf("cloudflare %+v", d)
		}
	}
	if len(detectDeploys(t.TempDir())) != 0 {
		t.Error("found something in an empty folder")
	}
}

// fakeDeployHosted is a hosted Keystub (the routes connect uses) plus
// Convex's and Cloudflare's APIs.
type fakeDeployHosted struct {
	mu       sync.Mutex
	srv      *httptest.Server
	services map[string]bool
	keys     []map[string]string // id, service, name, value
	links    map[string]string   // service -> key id
	envMade  bool
}

func newFakeDeployHosted(t *testing.T, envExists bool) *fakeDeployHosted {
	f := &fakeDeployHosted{services: map[string]bool{"openai": true}, links: map[string]string{}, envMade: envExists}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer skcli_abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/environments/acme/dev/links", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.envMade {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"type":"not_found","message":"no such environment"}}`)
			return
		}
		var ls []map[string]any
		for s, k := range f.links {
			ls = append(ls, map[string]any{"env": "acme/dev", "service": s, "key": map[string]string{"id": k, "name": "acme-dev"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"links": ls})
	})
	mux.HandleFunc("GET /api/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"projects":[]}`)
	})
	mux.HandleFunc("POST /api/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"project":{"id":"acme"}}`)
	})
	mux.HandleFunc("POST /api/environments", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.envMade = true
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"environment":{"id":"acme/dev"}}`)
	})
	mux.HandleFunc("GET /api/services", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var ss []map[string]string
		for id := range f.services {
			ss = append(ss, map[string]string{"id": id})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"services": ss})
	})
	mux.HandleFunc("POST /api/services", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.services[in["catalog"]] = true
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"service":{"id":"`+in["catalog"]+`"}}`)
	})
	mux.HandleFunc("GET /api/keys", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var ks []map[string]any
		for _, k := range f.keys {
			ks = append(ks, map[string]any{"id": k["id"], "service": k["service"], "name": k["name"]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks})
	})
	mux.HandleFunc("POST /api/keys", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		in["id"] = "key_" + in["service"]
		f.keys = append(f.keys, in)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]string{"id": in["id"], "service": in["service"], "name": in["name"]}})
	})
	mux.HandleFunc("PUT /api/keys/{id}/value", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		for _, k := range f.keys {
			if k["id"] == r.PathValue("id") {
				k["value"] = in["value"]
			}
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]string{"id": r.PathValue("id")}})
	})
	mux.HandleFunc("PUT /api/environments/acme/dev/links/{svc}", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["serviceToken"] != false {
			t.Errorf("link made a service token: %v", in)
		}
		f.mu.Lock()
		f.links[r.PathValue("svc")] = in["key"].(string)
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"link":{}}`)
	})
	// Convex: the CLI login may make deploy keys for happy-animal-123 only.
	mux.HandleFunc("GET /convex/deployments/{d}/list_deploy_keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer convex-cli-token" || r.PathValue("d") != "happy-animal-123" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `[]`)
	})
	// Cloudflare: one account on wrangler's login; only the account token verifies.
	mux.HandleFunc("GET /cf/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wrangler-oauth" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"success":false}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"49ed8e403f061c8e058a965cbf3abb6c","name":"Acme"}]}`)
	})
	mux.HandleFunc("GET /cf/accounts/{a}/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-account-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || r.PathValue("a") != "49ed8e403f061c8e058a965cbf3abb6c" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":{"status":"active"}}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	oldConvex, oldCF, oldLook, oldRun := convexAPI, cloudflareAPI, lookFly, runFly
	convexAPI, cloudflareAPI = f.srv.URL+"/convex", f.srv.URL+"/cf"
	t.Cleanup(func() { convexAPI, cloudflareAPI, lookFly, runFly = oldConvex, oldCF, oldLook, oldRun })
	return f
}

func (f *fakeDeployHosted) value(service string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k["service"] == service {
			var v map[string]string
			_ = json.Unmarshal([]byte(k["value"]), &v)
			return v
		}
	}
	return nil
}

type connectRun struct {
	home     string
	terminal bool
	stdin    string
	secret   string
	opened   []string
}

func (f *fakeDeployHosted) run(t *testing.T, cr *connectRun, cmd string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := map[string]string{"KEYSTUB_SERVER": f.srv.URL, "KEYSTUB_API_KEY": "skcli_abc", "HOME": cr.home}
	code := Main(Env{
		Stdin: strings.NewReader(cr.stdin), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return env[k] }, Home: filepath.Join(cr.home, ".keystub"), Hostname: "testbox",
		Sleep: func(time.Duration) {}, StdinTerminal: cr.terminal,
		ReadSecret: func(string) (string, error) { return cr.secret, nil },
		OpenURL:    func(u string) error { cr.opened = append(cr.opened, u); return nil },
	}, cmd, args)
	return result{code, out.String(), errb.String()}
}

func deployProject(t *testing.T) string {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "runner", "fly.toml"), "app = \"acme-runner\"\n")
	writeFile(t, filepath.Join(dir, "wrangler.jsonc"), "{ \"name\": \"acme-web\" }\n")
	writeFile(t, filepath.Join(dir, "convex", "schema.ts"), "")
	writeFile(t, filepath.Join(dir, ".env.cloud"), "CONVEX_DEPLOYMENT=prod:happy-animal-123\n")
	return dir
}

func TestConnect(t *testing.T) {
	f := newFakeDeployHosted(t, false)
	dir := deployProject(t)
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".convex", "config.json"), `{"accessToken":"convex-cli-token"}`)
	writeFile(t, filepath.Join(home, "Library", "Preferences", ".wrangler", "config", "default.toml"), "oauth_token = \"wrangler-oauth\"\n")
	var flyArgs []string
	lookFly = func() (string, error) { return "/bin/fly", nil }
	runFly = func(_ string, a ...string) ([]byte, error) {
		flyArgs = a
		return []byte("FlyV1 fm2_abcdefghijklmnopqrstuvwxyz0123\n"), nil
	}

	// The plan changes nothing.
	cr := &connectRun{home: home}
	res := f.run(t, cr, "connect", "acme/dev", "--dir", dir, "--dry-run", "--json")
	if res.code != 0 || !strings.Contains(res.stdout, `"acme-runner"`) || !strings.Contains(res.stdout, `"happy-animal-123"`) || len(f.keys) != 0 {
		t.Fatalf("dry run: %d %s %s", res.code, res.stdout, res.stderr)
	}
	// With no terminal and no --yes, nothing is asked or done.
	res = f.run(t, cr, "connect", "acme/dev", "--dir", dir)
	if res.code != 0 || len(f.keys) != 0 || f.envMade {
		t.Fatalf("unasked: %d %s %s", res.code, res.stdout, res.stderr)
	}

	// At a terminal: yes to each; a personal Cloudflare token first, refused.
	cr = &connectRun{home: home, terminal: true, stdin: "y\ny\ny\n", secret: "personal-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	res = f.run(t, cr, "connect", "acme/dev", "--dir", dir)
	if res.code != 0 {
		t.Fatalf("connect: %d %s %s", res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stdout+res.stderr, "fm2_") || strings.Contains(res.stdout+res.stderr, "convex-cli-token") {
		t.Fatal("connect printed a token")
	}
	if strings.Join(flyArgs, " ") != "tokens create deploy -a acme-runner -n Keystub -x 8760h" {
		t.Errorf("fly %v", flyArgs)
	}
	if v := f.value("fly-minted"); v["app"] != "acme-runner" || v["token"] != "FlyV1 fm2_abcdefghijklmnopqrstuvwxyz0123" {
		t.Errorf("fly key %v", v)
	}
	if v := f.value("convex"); v["deployment"] != "happy-animal-123" || v["token"] != "convex-cli-token" {
		t.Errorf("convex key %v", v)
	}
	if f.value("cloudflare-minted") != nil || !strings.Contains(res.stdout, "Cloudflare not linked: Cloudflare doesn't take that as an account token") {
		t.Errorf("personal token saved, or not said: %s", res.stdout)
	}
	if len(cr.opened) != 1 || cr.opened[0] != "https://dash.cloudflare.com/49ed8e403f061c8e058a965cbf3abb6c/api-tokens/create" {
		t.Errorf("opened %v", cr.opened)
	}
	if !f.envMade || f.links["fly-minted"] == "" || f.links["convex"] == "" || f.links["cloudflare-minted"] != "" {
		t.Errorf("links %v, env made %v", f.links, f.envMade)
	}
	if !f.services["fly-minted"] || !f.services["convex"] {
		t.Errorf("services %v", f.services)
	}

	// Again: only Cloudflare is asked, and the account token is saved.
	cr = &connectRun{home: home, terminal: true, stdin: "y\n", secret: "cf-account-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	res = f.run(t, cr, "connect", "acme/dev", "--dir", dir)
	if res.code != 0 || strings.Count(res.stderr, "? [y/N]") != 1 || !strings.Contains(res.stderr, "already linked in acme/dev") {
		t.Fatalf("again: %d %s %s", res.code, res.stdout, res.stderr)
	}
	if v := f.value("cloudflare-minted"); v["accountId"] != "49ed8e403f061c8e058a965cbf3abb6c" || v["token"] != "cf-account-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("cloudflare key %v", v)
	}
	if !strings.Contains(res.stdout, "Cloudflare linked: each session gets a short-lived CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID") {
		t.Errorf("said %s", res.stdout)
	}
}

func TestConnectFailures(t *testing.T) {
	f := newFakeDeployHosted(t, true)
	dir := deployProject(t)
	home := t.TempDir() // no Convex login, no wrangler login
	lookFly = func() (string, error) { return "", os.ErrNotExist }

	cr := &connectRun{home: home, terminal: true, stdin: "y\ny\n"}
	res := f.run(t, cr, "connect", "acme/dev", "--dir", dir, "--only", "fly,convex")
	if res.code != 0 || len(f.keys) != 0 {
		t.Fatalf("%d %s %s", res.code, res.stdout, res.stderr)
	}
	for _, want := range []string{"the fly CLI isn't installed", "the Convex CLI isn't signed in here"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("missing %q in %s", want, res.stdout)
		}
	}
	// A deployment the login can't reach is refused before anything is saved.
	writeFile(t, filepath.Join(home, ".convex", "config.json"), `{"accessToken":"convex-cli-token"}`)
	writeFile(t, filepath.Join(dir, ".env.cloud"), "CONVEX_DEPLOYMENT=prod:other-thing-4\n")
	cr = &connectRun{home: home, terminal: true, stdin: "y\n"}
	res = f.run(t, cr, "connect", "acme/dev", "--dir", dir, "--only", "convex")
	if len(f.keys) != 0 || !strings.Contains(res.stdout, "can't make deploy keys for other-thing-4 (status 403)") {
		t.Errorf("%s", res.stdout)
	}
	if res := f.run(t, cr, "connect", "acme/dev", "--dir", t.TempDir()); res.code != ExitNotFound {
		t.Errorf("empty folder: %d", res.code)
	}
	if res := f.run(t, cr, "connect", "acme/dev", "--only", "heroku"); res.code != ExitUsage {
		t.Errorf("--only heroku: %d", res.code)
	}
}

func TestInitPointsAtConnect(t *testing.T) {
	r := newRig(t)
	path := writeDotenv(t, "My App", "OPENAI_API_KEY=sk-real-openai\n")
	writeFile(t, filepath.Join(filepath.Dir(path), "fly.toml"), "app = \"my-app\"\n")
	// --yes answers init's own question only: connecting makes tokens, so it's named, not done.
	res := r.must("", "init", "--env-file", path, "--yes", "--json")
	if !strings.Contains(res.stderr, "this code deploys to Fly.io: to let sessions deploy, run keystub connect my-app/dev") {
		t.Errorf("stderr: %s", res.stderr)
	}
	var plan map[string]any
	if err := json.Unmarshal([]byte(res.stdout), &plan); err != nil {
		t.Fatalf("stdout isn't one JSON value: %v\n%s", err, res.stdout)
	}
}
