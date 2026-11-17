package cli

import (
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

// fakeClouds answers as Google, Fly.io, Cloudflare and Convex do, for the
// fake credentials below.
type fakeClouds struct {
	mu       sync.Mutex
	srv      *httptest.Server
	granted  []string // permissions the service account holds
	services map[string]int
	workers  map[string]bool
	calls    []string
}

const (
	fakeGoogleToken = "ya29.fake-google-token"
	fakeFlyToken    = "FlyV1 fm2_fake-fly-token"
	fakeCFToken     = "cf-fake-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fakeConvexKey   = "prod:happy-animal-123|fake-convex-key"
	fakeAccount     = "49ed8e403f061c8e058a965cbf3abb6c"
)

func newFakeClouds(t *testing.T) *fakeClouds {
	f := &fakeClouds{services: map[string]int{}, workers: map[string]bool{}}
	mux := http.NewServeMux()
	google := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+fakeGoogleToken }
	mux.HandleFunc("POST /tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("access_token") != fakeGoogleToken {
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, `{"azp":"1150914","expires_in":"3500"}`)
	})
	mux.HandleFunc("GET /iam/projects/-/serviceAccounts/1150914", func(w http.ResponseWriter, r *http.Request) {
		if !google(r) {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, `{"email":"deployer@acme-prod.iam.gserviceaccount.com"}`)
	})
	mux.HandleFunc("POST /crm/projects/{p}", func(w http.ResponseWriter, r *http.Request) {
		if !google(r) || r.PathValue("p") != "acme-prod:testIamPermissions" {
			w.WriteHeader(403)
			return
		}
		var in struct {
			Permissions []string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		var has []string
		for _, p := range in.Permissions {
			for _, g := range f.granted {
				if p == g {
					has = append(has, p)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"permissions": has})
	})
	mux.HandleFunc("/run/projects/acme-prod/locations/{region}/services/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" run "+r.PathValue("region")+" "+r.PathValue("rest")+r.URL.RawQuery)
		if !google(r) {
			w.WriteHeader(401)
			return
		}
		name := r.PathValue("rest")
		switch r.Method {
		case "POST":
			id := r.URL.Query().Get("serviceId")
			f.services[id] = 0
			_, _ = io.WriteString(w, `{"name":"operations/1"}`)
		case "GET":
			f.services[name]++
			if f.services[name] < 2 {
				_, _ = io.WriteString(w, `{"reconciling":true}`)
				return
			}
			_, _ = io.WriteString(w, `{"uri":"https://`+name+`.run.app","reconciling":false,"terminalCondition":{"state":"CONDITION_SUCCEEDED"}}`)
		case "DELETE":
			delete(f.services, name)
			_, _ = io.WriteString(w, `{"name":"operations/2"}`)
		}
	})
	mux.HandleFunc("GET /fly/apps/{app}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != fakeFlyToken {
			w.WriteHeader(401)
			return
		}
		if r.PathValue("app") != "acme-runner" {
			w.WriteHeader(404)
			return
		}
		_, _ = io.WriteString(w, `{"name":"acme-runner"}`)
	})
	mux.HandleFunc("GET /cf/accounts/{a}/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeCFToken || r.PathValue("a") != fakeAccount {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"success":false}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":{"status":"active"}}`)
	})
	mux.HandleFunc("/cf/accounts/{a}/workers/scripts/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" worker "+r.PathValue("name"))
		if r.Header.Get("Authorization") != "Bearer "+fakeCFToken {
			w.WriteHeader(401)
			return
		}
		if r.Method == "PUT" {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				w.WriteHeader(400)
				return
			}
			f.workers[r.PathValue("name")] = true
		} else {
			delete(f.workers, r.PathValue("name"))
		}
		_, _ = io.WriteString(w, `{"success":true}`)
	})
	mux.HandleFunc("GET /convex/{name}/api/check_admin_key", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Convex "+fakeConvexKey {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	old := []string{googleAPI, googleRunAPI, googleIAM, googleToken, flyAPI, cloudflareAPI, convexCloud}
	googleAPI, googleRunAPI, googleIAM, googleToken = f.srv.URL+"/crm", f.srv.URL+"/run", f.srv.URL+"/iam", f.srv.URL+"/tokeninfo"
	flyAPI, cloudflareAPI, convexCloud = f.srv.URL+"/fly", f.srv.URL+"/cf", f.srv.URL+"/convex/%s"
	oldLook, oldPoll := lookTool, pollEvery
	lookTool = func(n string) (string, error) {
		if n == "gcloud" {
			return "/usr/bin/gcloud", nil
		}
		return "", os.ErrNotExist
	}
	pollEvery = time.Millisecond
	t.Cleanup(func() {
		googleAPI, googleRunAPI, googleIAM, googleToken, flyAPI, cloudflareAPI, convexCloud = old[0], old[1], old[2], old[3], old[4], old[5], old[6]
		lookTool, pollEvery = oldLook, oldPoll
	})
	return f
}

type ranProgram struct {
	name string
	args []string
}

// runCLI runs a command with no sign-in, in a fake home, recording the
// programs it runs.
func runCLI(t *testing.T, home string, programs *[]ranProgram, cmd string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string {
			if k == "HOME" {
				return home
			}
			return ""
		},
		Home: filepath.Join(home, ".keystub"), Hostname: "testbox", Sleep: func(time.Duration) {},
		Exec: func(_ io.Reader, stdout, _ io.Writer, _ []string, name string, args ...string) error {
			if programs != nil {
				*programs = append(*programs, ranProgram{name, args})
			}
			return errors.New("not in tests")
		},
	}, cmd, args)
	return result{code, out.String(), errb.String()}
}

func verifyProject(t *testing.T) (dir, home string) {
	dir, home = t.TempDir(), t.TempDir()
	tokFile := filepath.Join(home, ".keystub", "files", "acme-dev", "google-cloud", "access-token")
	writeFile(t, tokFile, fakeGoogleToken+"\n")
	writeFile(t, filepath.Join(dir, ".env"), strings.Join([]string{
		"PORT=3000",
		"FLY_API_TOKEN='" + fakeFlyToken + "'",
		"FLY_APP=acme-runner",
		"CLOUDFLARE_API_TOKEN=" + fakeCFToken,
		"CLOUDFLARE_ACCOUNT_ID=" + fakeAccount,
		"CONVEX_DEPLOY_KEY='" + fakeConvexKey + "'",
	}, "\n")+"\n")
	// What setup exports for the shell: Google Cloud's sign-in.
	writeFile(t, filepath.Join(home, ".keystub", "env.sh"), "# Written by keystub setup.\nexport CLOUDSDK_AUTH_ACCESS_TOKEN_FILE="+shSingle(tokFile)+"\nexport CLOUDSDK_CORE_PROJECT='acme-prod'\n")
	writeFile(t, filepath.Join(dir, "scripts", "deploy.sh"), "#!/bin/sh\ngcloud builds submit --tag x\ngcloud run deploy api --image x --region europe-west1\n")
	writeFile(t, filepath.Join(dir, "runner", "fly.toml"), "app = \"acme-runner\"\n")
	return dir, home
}

func checksByName(t *testing.T, out string) (map[string]check, []string) {
	t.Helper()
	var res struct {
		Checks []check   `json:"checks"`
		Fixes  []string  `json:"fixes"`
		Error  *struct{} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if res.Checks == nil {
		// A failure: the checks are inside the error.
		var e struct {
			Error struct {
				Checks []check  `json:"checks"`
				Fixes  []string `json:"fixes"`
			} `json:"error"`
		}
		_ = json.Unmarshal([]byte(out), &e)
		res.Checks, res.Fixes = e.Error.Checks, e.Error.Fixes
	}
	m := map[string]check{}
	for _, c := range res.Checks {
		m[c.Name] = c
	}
	return m, res.Fixes
}

func TestVerify(t *testing.T) {
	f := newFakeClouds(t)
	dir, home := verifyProject(t)
	f.granted = []string{"resourcemanager.projects.get", "run.services.list", "run.services.create", "run.services.update", "iam.serviceAccounts.actAs", "artifactregistry.repositories.uploadArtifacts"}

	r := runCLI(t, home, nil, "verify", "--env-file", filepath.Join(dir, ".env"), "--json")
	if r.code != ExitError {
		t.Fatalf("exit %d, want 1 (Cloud Build is missing): %s %s", r.code, r.stdout, r.stderr)
	}
	checks, fixes := checksByName(t, r.stdout)
	g := checks["google cloud"]
	if g.Status != "fail" || !strings.Contains(g.Detail, "deployer@acme-prod.iam.gserviceaccount.com lacks cloudbuild.builds.create") {
		t.Errorf("google %+v", g)
	}
	want := "gcloud projects add-iam-policy-binding acme-prod --member=serviceAccount:deployer@acme-prod.iam.gserviceaccount.com --role=roles/cloudbuild.builds.editor --condition=None"
	if len(fixes) == 0 || fixes[0] != want {
		t.Errorf("fixes %q", fixes)
	}
	if c := checks["fly.io"]; c.Status != "ok" || !strings.Contains(c.Detail, "acme-runner") {
		t.Errorf("fly %+v", c)
	}
	if c := checks["cloudflare"]; c.Status != "ok" || !strings.Contains(c.Detail, fakeAccount) {
		t.Errorf("cloudflare %+v", c)
	}
	if c := checks["convex"]; c.Status != "ok" || !strings.Contains(c.Detail, "happy-animal-123") {
		t.Errorf("convex %+v", c)
	}
	if c := checks["gcloud"]; c.Status != "ok" {
		t.Errorf("gcloud %+v", c)
	}
	if c := checks["fly"]; c.Status != "warn" {
		t.Errorf("the fly CLI isn't here: %+v", c)
	}
	if !strings.Contains(strings.Join(fixes, "\n"), "keystub tools install fly") {
		t.Errorf("no install fix: %q", fixes)
	}
	// No credential value is ever printed.
	for _, s := range []string{fakeGoogleToken, "fake-fly-token", fakeCFToken, "fake-convex-key"} {
		if strings.Contains(r.stdout+r.stderr, s) {
			t.Errorf("printed %q", s)
		}
	}

	// With Cloud Build granted, everything passes; --deploy rehearses on
	// Cloud Run (in the region the deploy script names) and Cloudflare,
	// and deletes both.
	f.granted = append(f.granted, "cloudbuild.builds.create")
	r = runCLI(t, home, nil, "verify", "--env-file", filepath.Join(dir, ".env"), "--deploy", "--json")
	checks, _ = checksByName(t, r.stdout)
	if c := checks["deploy cloud run"]; c.Status != "ok" || !strings.Contains(c.Detail, "acme-prod/europe-west1") {
		t.Errorf("cloud run rehearsal %+v (%s)", c, r.stderr)
	}
	if c := checks["deploy cloudflare"]; c.Status != "ok" {
		t.Errorf("worker rehearsal %+v", c)
	}
	if c := checks["deploy fly.io"]; c.Status != "warn" {
		t.Errorf("fly rehearsal %+v", c)
	}
	if len(f.services) != 0 || len(f.workers) != 0 {
		t.Errorf("left behind: %v %v", f.services, f.workers)
	}
	if c := checks["google cloud"]; c.Status != "ok" || !strings.Contains(c.Detail, "can deploy to Cloud Run") {
		t.Errorf("google %+v", c)
	}
}

func TestVerifyNothing(t *testing.T) {
	newFakeClouds(t)
	dir, home := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(dir, ".env"), "PORT=3000\n")
	r := runCLI(t, home, nil, "verify", "--env-file", filepath.Join(dir, ".env"), "--json")
	checks, fixes := checksByName(t, r.stdout)
	if r.code != ExitError || checks["credentials"].Status != "fail" || len(fixes) == 0 || !strings.HasPrefix(fixes[0], "keystub setup") {
		t.Errorf("exit %d %v %q", r.code, checks, fixes)
	}
	// An expired Google token: refresh with setup.
	dir, home = verifyProject(t)
	writeFile(t, filepath.Join(home, ".keystub", "files", "acme-dev", "google-cloud", "access-token"), "ya29.expired\n")
	r = runCLI(t, home, nil, "verify", "--env-file", filepath.Join(dir, ".env"), "--json")
	checks, _ = checksByName(t, r.stdout)
	if c := checks["google cloud"]; c.Status != "fail" || !strings.Contains(c.Detail, "keystub setup again") {
		t.Errorf("expired %+v", c)
	}
}

func TestDetectGoogle(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"scripts":{"deploy":"gcloud run deploy web --source . --region=asia-south1"}}`)
	writeFile(t, filepath.Join(dir, ".github", "workflows", "ci.yml"), "steps:\n  - run: gcloud builds submit\n")
	writeFile(t, filepath.Join(dir, "node_modules", "x", "app.yaml"), "runtime: nodejs\n")
	g := detectGoogle(dir)
	if !g.run || !g.build || g.appEngine || g.region != "asia-south1" {
		t.Errorf("%+v", g)
	}
	if g := detectGoogle(t.TempDir()); g.run || g.build || g.appEngine || g.firebase {
		t.Errorf("empty: %+v", g)
	}
}

func TestToolsInstall(t *testing.T) {
	newFakeClouds(t) // lookTool: only gcloud is here
	dir, home := verifyProject(t)
	var ran []ranProgram
	r := runCLI(t, home, &ran, "tools", "check", "--dir", dir, "--env-file", filepath.Join(dir, ".env"), "--json")
	if r.code != 0 || len(ran) != 0 || !strings.Contains(r.stdout, `"name": "fly"`) {
		t.Fatalf("check: %d %s %v", r.code, r.stdout, ran)
	}
	r = runCLI(t, home, &ran, "tools", "install", "fly", "--json")
	if r.code != ExitError || len(ran) != 1 || ran[0].name != "sh" || !strings.Contains(strings.Join(ran[0].args, " "), "fly.io/install.sh") {
		t.Errorf("install: %d %v %s", r.code, ran, r.stdout)
	}
	if r := runCLI(t, home, nil, "tools", "install", "kubectl", "--json"); r.code != ExitUsage {
		t.Errorf("unknown tool: %d", r.code)
	}
}

func TestSecretFile(t *testing.T) {
	for name, want := range map[string]bool{".env": true, ".env.local": true, ".env.production": true, ".dev.vars": true, ".env.example": false, ".env.sample": false, "env.ts": false, ".envrc": true} {
		if secretFile(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}
