package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/dashboard"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

// rig is a self-hosted server in-process: the engine, its API, and an
// edge whose every upstream is a test server that records the
// Authorization header it gets.
type rig struct {
	t       *testing.T
	engine  *core.Engine
	api     *httptest.Server
	edge    *httptest.Server
	home    string
	env     map[string]string
	mu      sync.Mutex
	gotAuth string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, home: t.TempDir()}
	r.engine, _ = coretest.Engine(t, "")
	lg, _ := reqlog.Open("", 50)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"), 0o644)

	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.gotAuth = req.Header.Get("Authorization")
		r.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	ed := proxy.NewEdge(r.engine, lg)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	addr := up.Listener.Addr().String()
	ed.Upstream = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	r.edge = httptest.NewServer(ed)
	t.Cleanup(r.edge.Close)

	edgeAddr := strings.TrimPrefix(r.edge.URL, "http://")
	d, err := dashboard.New(&dashboard.Server{Core: r.engine, Log: lg, Token: "admintoken", EdgeAddr: edgeAddr, CAPath: caPath})
	if err != nil {
		t.Fatal(err)
	}
	r.api = httptest.NewServer(d)
	t.Cleanup(r.api.Close)
	r.env = map[string]string{"KEYSTUB_SERVER": r.api.URL, "KEYSTUB_API_KEY": "admintoken"}
	return r
}

type result struct {
	code           int
	stdout, stderr string
}

func (r result) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &m); err != nil {
		t.Fatalf("stdout isn't JSON: %v\n%s", err, r.stdout)
	}
	return m
}

// run runs a command with stdin as given (not a terminal).
func (r *rig) run(stdin string, args ...string) result {
	r.t.Helper()
	var out, errb bytes.Buffer
	code := Main(Env{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return r.env[k] }, Home: r.home, Hostname: "testbox",
		Sleep: func(time.Duration) {},
	}, args[0], args[1:])
	return result{code, out.String(), errb.String()}
}

func (r *rig) must(stdin string, args ...string) result {
	r.t.Helper()
	res := r.run(stdin, args...)
	if res.code != 0 {
		r.t.Fatalf("%v: exit %d\nstdout: %s\nstderr: %s", args, res.code, res.stdout, res.stderr)
	}
	return res
}

// call sends a request through the edge's quick-start route with token
// and returns the status and the real key the service saw.
func (r *rig) call(service, token string) (int, string) {
	r.t.Helper()
	r.mu.Lock()
	r.gotAuth = ""
	r.mu.Unlock()
	req, _ := http.NewRequest("GET", r.edge.URL+"/s/"+service+"/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	resp.Body.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	return resp.StatusCode, strings.TrimPrefix(r.gotAuth, "Bearer ")
}

// The done-when case: one saved key linked into two environments works
// from both; replacing it changes both with no token changes. All of it
// is set up through the CLI alone.
func TestOneKeyTwoEnvironmentsEndToEnd(t *testing.T) {
	r := newRig(t)
	r.must("", "services", "add", "echo", "--hosts", "api.echo.test", "--env-vars", "ECHO_KEY")
	r.must("", "services", "add", "other", "--hosts", "api.other.test")
	add := r.must("real-one\n", "keys", "add", "echo", "--name", "team", "--json")
	keyID := add.json(t)["key"].(map[string]any)["id"].(string)
	r.must("", "envs", "add", "app/dev")
	r.must("", "envs", "add", "app/prod", "--json")

	dev := r.must("", "envs", "link", "app/dev", "echo", "team")
	devToken := strings.TrimSpace(dev.stdout)
	if !strings.HasPrefix(devToken, core.TokenPrefix) || !strings.Contains(dev.stderr, "isn't shown again") {
		t.Fatalf("link printed %q / %q", dev.stdout, dev.stderr)
	}
	prod := r.must("", "envs", "link", "app/prod", "echo", keyID, "--json").json(t)
	prodTok := prod["token"].(map[string]any)
	prodToken := prodTok["token"].(string)
	if prodTok["kind"] != "service" || prodTok["service"] != "echo" || prod["link"].(map[string]any)["version"].(float64) != 1 {
		t.Fatalf("link JSON = %v", prod)
	}
	sandbox := strings.TrimSpace(r.must("", "tokens", "create", "app/dev", "--name", "sandbox-1", "--ttl", "2h").stdout)

	for name, tok := range map[string]string{"dev service token": devToken, "prod service token": prodToken, "dev environment token": sandbox} {
		if st, got := r.call("echo", tok); st != 200 || got != "real-one" {
			t.Fatalf("%s: %d %q", name, st, got)
		}
	}
	keys := r.must("", "keys", "show", "team", "--json").json(t)["key"].(map[string]any)
	if li := keys["linkedIn"].([]any); len(li) != 2 || li[0] != "app/dev" || li[1] != "app/prod" {
		t.Fatalf("linkedIn = %v", keys["linkedIn"])
	}

	rep := r.must("real-two", "keys", "replace", "team", "--json").json(t)["key"].(map[string]any)
	if rep["version"].(float64) != 2 {
		t.Fatalf("replace = %v", rep)
	}
	for name, tok := range map[string]string{"dev": devToken, "prod": prodToken, "sandbox": sandbox} {
		if st, got := r.call("echo", tok); st != 200 || got != "real-two" {
			t.Fatalf("%s after replace: %d %q", name, st, got)
		}
	}
	if strings.Contains(r.must("", "keys", "list", "--json").stdout, "real-") {
		t.Fatal("keys list shows a value")
	}

	// A service token works only for its service; the environment token
	// for every linked service, and none that isn't linked.
	r.env["OTHER"] = "real-other"
	r.must("", "keys", "add", "other", "--name", "team", "--from-env", "OTHER")
	if st, _ := r.call("other", sandbox); st != http.StatusBadGateway {
		t.Fatalf("other not linked yet: %d", st)
	}
	r.must("", "envs", "link", "app/dev", "other", "team", "--no-token")
	if st, got := r.call("other", sandbox); st != 200 || got != "real-other" {
		t.Fatalf("environment token, other: %d %q", st, got)
	}
	if st, _ := r.call("other", devToken); st != http.StatusForbidden {
		t.Fatalf("echo's service token used for other: %d", st)
	}

	// Switching dev's echo link to another key moves its tokens; prod stays.
	r.must("real-three", "keys", "add", "echo", "--name", "personal")
	sw := r.must("", "envs", "link", "app/dev", "echo", "personal", "--json").json(t)
	if sw["token"] != nil || sw["link"].(map[string]any)["version"].(float64) != 2 {
		t.Fatalf("switch made a token or kept the version: %v", sw)
	}
	if _, got := r.call("echo", devToken); got != "real-three" {
		t.Fatalf("dev after switch: %q", got)
	}
	if _, got := r.call("echo", prodToken); got != "real-two" {
		t.Fatalf("prod after dev's switch: %q", got)
	}

	// Unlinking refuses the environment's tokens for that service.
	r.must("", "envs", "unlink", "app/prod", "echo")
	if st, _ := r.call("echo", prodToken); st != http.StatusBadGateway {
		t.Fatalf("after unlink: %d", st)
	}
	links := r.must("", "envs", "links", "app/dev", "--json").json(t)["links"].([]any)
	if len(links) != 2 {
		t.Fatalf("links = %v", links)
	}
}

func TestExitCodesAndJSONErrors(t *testing.T) {
	r := newRig(t)
	r.must("", "services", "add", "openai")
	r.must("sk-real", "keys", "add", "openai", "--name", "team")
	r.must("", "envs", "add", "app/dev")
	r.must("", "envs", "link", "app/dev", "openai", "team", "--no-token")

	res := r.run("", "keys", "delete", "team", "--yes", "--json")
	e, _ := res.json(t)["error"].(map[string]any)
	if res.code != ExitConflict || e == nil || e["exitCode"].(float64) != ExitConflict {
		t.Fatalf("delete a linked key: %d %s", res.code, res.stdout)
	}
	if li, _ := e["linkedIn"].([]any); len(li) != 1 || li[0] != "app/dev" {
		t.Fatalf("linkedIn = %v", e["linkedIn"])
	}
	if res := r.run("", "keys", "delete", "team"); res.code != ExitUsage || !strings.Contains(res.stderr, "--yes") {
		t.Fatalf("delete without --yes: %d %s", res.code, res.stderr)
	}
	if res := r.run("", "keys", "show", "nope"); res.code != ExitNotFound {
		t.Fatalf("missing key: %d", res.code)
	}
	if res := r.run("", "tokens", "list", "app/nope"); res.code != ExitNotFound {
		t.Fatalf("missing env: %d", res.code)
	}
	if res := r.run("x", "keys", "add", "openai", "--name", "team"); res.code != ExitConflict {
		t.Fatalf("name taken: %d %s", res.code, res.stderr)
	}
	if res := r.run("", "tokens", "create", "app/dev", "--name", "x", "--service", "github"); res.code != ExitNotFound {
		t.Fatalf("service token for a service that doesn't exist: %d %s", res.code, res.stderr)
	}
	r.must("", "services", "add", "github")
	if res := r.run("", "tokens", "create", "app/dev", "--name", "x", "--service", "github"); res.code != ExitConflict {
		t.Fatalf("service token for a service not linked: %d %s", res.code, res.stderr)
	}
	if res := r.run("", "tokens", "frobnicate"); res.code != ExitUsage {
		t.Fatalf("unknown subcommand: %d", res.code)
	}
	if res := r.run("", "tokens", "list", "app/dev", "--bogus"); res.code != ExitUsage {
		t.Fatalf("unknown flag: %d", res.code)
	}
	r.env["KEYSTUB_API_KEY"] = "wrong"
	if res := r.run("", "keys", "list"); res.code != ExitNoAuth {
		t.Fatalf("bad key: %d", res.code)
	}
	delete(r.env, "KEYSTUB_API_KEY")
	if res := r.run("", "keys", "list", "--json"); res.code != ExitNoAuth || !strings.Contains(res.stdout, "keystub login") {
		t.Fatalf("no credentials: %d %s", res.code, res.stdout)
	}
}

func TestSecretValuesNeverInArgumentsOrOutput(t *testing.T) {
	r := newRig(t)
	r.must("", "services", "add", "openai")
	for _, args := range [][]string{
		{"keys", "add", "openai", "--name", "team", "sk-in-argv"},
		{"keys", "add", "openai", "--name", "team", "--value", "sk-in-argv"},
		{"keys", "add", "openai", "--name", "team", "--value=sk-in-argv"},
	} {
		res := r.run("", args...)
		if res.code != ExitUsage || !strings.Contains(res.stderr, "never goes in an argument") || strings.Contains(res.stderr, "sk-in-argv") {
			t.Fatalf("%v: %d %s", args, res.code, res.stderr)
		}
	}
	if len(r.engine.Keys()) != 0 {
		t.Fatal("a key was saved from an argument")
	}
	if res := r.run("", "keys", "add", "openai", "--name", "team"); res.code != ExitUsage || !strings.Contains(res.stderr, "stdin") {
		t.Fatalf("empty stdin: %d %s", res.code, res.stderr)
	}
	res := r.must("  sk-secret-value\n", "keys", "add", "openai", "--name", "team", "--json")
	if strings.Contains(res.stdout+res.stderr, "sk-secret-value") {
		t.Fatal("the value was printed back")
	}
	if got, _ := r.engine.RealKey(context.Background(), core.DefaultEnv, "openai"); got != "" {
		t.Fatal("linked without asking")
	}
	k := r.engine.Keys()[0]
	r.must("", "envs", "link", core.DefaultEnv, "openai", k.ID, "--no-token")
	if got, _ := r.engine.RealKey(context.Background(), core.DefaultEnv, "openai"); got != "sk-secret-value" {
		t.Fatalf("stored %q", got)
	}
}

func TestKeyNamesAreResolvedPerService(t *testing.T) {
	r := newRig(t)
	r.must("", "services", "add", "openai")
	r.must("", "services", "add", "anthropic")
	r.must("a", "keys", "add", "openai", "--name", "team")
	r.must("b", "keys", "add", "anthropic", "--name", "team")
	if res := r.run("", "keys", "show", "team"); res.code != ExitUsage || !strings.Contains(res.stderr, "--service") {
		t.Fatalf("ambiguous name: %d %s", res.code, res.stderr)
	}
	show := r.must("", "keys", "show", "team", "--service", "anthropic", "--json").json(t)["key"].(map[string]any)
	if show["service"] != "anthropic" {
		t.Fatalf("show = %v", show)
	}
	r.must("", "keys", "rename", "team", "claude", "--service", "anthropic")
	r.must("", "keys", "limits", "claude", "--daily", "100")
	k := r.must("", "keys", "show", "claude", "--json").json(t)["key"].(map[string]any)
	if l := k["limits"].(map[string]any); l["dailyRequests"].(float64) != 100 {
		t.Fatalf("limits = %v", k["limits"])
	}
	r.must("", "keys", "limits", "claude", "--clear")
	if k := r.must("", "keys", "show", "claude", "--json").json(t)["key"].(map[string]any); k["limits"] != nil {
		t.Fatalf("cleared limits = %v", k["limits"])
	}
	openai := r.engine.Keys()[1]
	if openai.ServiceID != "openai" {
		t.Fatalf("keys = %+v", r.engine.Keys())
	}
	if res := r.run("", "keys", "show", openai.ID, "--service", "anthropic"); res.code != ExitUsage || !strings.Contains(res.stderr, "is for openai") {
		t.Fatalf("an ID for another service: %d %s", res.code, res.stderr)
	}
	r.must("", "keys", "delete", "claude", "--yes")
	if len(r.engine.Keys()) != 1 {
		t.Fatal("not deleted")
	}
}

func TestTokensListRevokeAndEnvsDelete(t *testing.T) {
	r := newRig(t)
	r.must("", "envs", "add", "shop/ci", "--daily", "50")
	tok := r.must("", "tokens", "create", "shop/ci", "--name", "job-1", "--json").json(t)
	if tok["kind"] != "environment" || tok["service"] != nil || !strings.HasPrefix(tok["token"].(string), core.TokenPrefix) {
		t.Fatalf("token = %v", tok)
	}
	list := r.must("", "tokens", "list", "shop/ci", "--json")
	if strings.Contains(list.stdout, tok["token"].(string)) {
		t.Fatal("list shows the token's value")
	}
	r.must("", "tokens", "revoke", tok["id"].(string), "--yes")
	ts := r.must("", "tokens", "list", "shop/ci", "--json").json(t)["tokens"].([]any)
	if ts[0].(map[string]any)["state"] != "revoked" {
		t.Fatalf("tokens = %v", ts)
	}
	envs := r.must("", "envs", "list", "--json").stdout
	if !strings.Contains(envs, `"shop/ci"`) {
		t.Fatalf("envs = %s", envs)
	}
	r.must("", "envs", "delete", "shop/ci", "--yes")
	if _, ok := r.engine.Environment("shop/ci"); ok {
		t.Fatal("not deleted")
	}
	if res := r.run("", "envs", "add", "no-slash"); res.code != ExitUsage {
		t.Fatalf("bad env: %d", res.code)
	}
}

func TestUsageSetupAndCA(t *testing.T) {
	r := newRig(t)
	r.must("", "services", "add", "openai")
	r.must("k", "keys", "add", "openai", "--name", "team")
	r.must("", "envs", "link", core.DefaultEnv, "openai", "team", "--no-token")
	setup := r.must("", "setup", core.DefaultEnv, "--json").json(t)
	lines, _ := setup["envLines"].([]any)
	joined := ""
	for _, l := range lines {
		joined += l.(string) + "\n"
	}
	if !strings.Contains(joined, "OPENAI_BASE_URL="+r.edge.URL+"/s/openai/v1") || !strings.Contains(joined, "OPENAI_API_KEY=<token>") || setup["gatewayUrl"] != nil {
		t.Fatalf("setup = %v", setup)
	}
	if res := r.must("", "usage", core.DefaultEnv, "--by", "service,key", "--range", "7d", "--json"); !strings.Contains(res.stdout, `"rows"`) {
		t.Fatalf("usage = %s", res.stdout)
	}
	if res := r.run("", "usage", "--range", "1y"); res.code != ExitError {
		t.Fatalf("bad range: %d", res.code)
	}
	if res := r.must("", "ca"); !strings.Contains(res.stdout, "BEGIN CERTIFICATE") {
		t.Fatalf("ca = %q", res.stdout)
	}
	out := filepath.Join(t.TempDir(), "ca.pem")
	r.must("", "ca", "-o", out)
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatal("ca -o wrote nothing")
	}
}

// With no server or key given, the CLI uses the keystub serve on this
// machine and its admin API key, and sends that key nowhere else.
func TestLocalServerAndAdminKey(t *testing.T) {
	r := newRig(t)
	r.env = map[string]string{}
	addr := strings.TrimPrefix(r.api.URL, "http://")
	_ = os.WriteFile(filepath.Join(r.home, "serve.json"), []byte(`{"dashboardAddr":"`+addr+`"}`), 0o600)
	_ = os.WriteFile(filepath.Join(r.home, "admin.token"), []byte("admintoken\n"), 0o600)
	who := r.must("", "whoami", "--json").json(t)
	if who["server"] != "self-hosted" || who["serverUrl"] != r.api.URL {
		t.Fatalf("whoami = %v", who)
	}
	if res := r.must("", "login"); !strings.Contains(res.stdout, "nothing to sign in to") {
		t.Fatalf("login on the local server: %s", res.stdout)
	}

	var sawAuth string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sawAuth = req.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer other.Close()
	if res := r.run("", "keys", "list", "--server", other.URL); res.code != ExitNoAuth || sawAuth != "" {
		t.Fatalf("another server: %d, it saw %q", res.code, sawAuth)
	}
	if res := r.run("", "keys", "list", "--server", "http://example.com"); res.code != ExitUsage {
		t.Fatalf("plain http to another machine: %d", res.code)
	}

	// $KEYSTUB_API_KEY with no server named goes nowhere.
	r.env["KEYSTUB_API_KEY"] = "skacct_x"
	if res := r.run("", "keys", "list"); res.code != ExitUsage || !strings.Contains(res.stderr, "KEYSTUB_SERVER") {
		t.Fatalf("key with no server: %d %s", res.code, res.stderr)
	}
	delete(r.env, "KEYSTUB_API_KEY")

	// serve.json left from an earlier run, and something else on its port:
	// the admin key isn't sent.
	_ = os.WriteFile(filepath.Join(r.home, "serve.json"), []byte(`{"dashboardAddr":"`+strings.TrimPrefix(other.URL, "http://")+`"}`), 0o600)
	sawAuth = ""
	if res := r.run("", "keys", "list"); res.code != ExitNoAuth || sawAuth != "" || !strings.Contains(res.stderr, "doesn't answer as Keystub") {
		t.Fatalf("stale serve.json: %d %s, it saw %q", res.code, res.stderr, sawAuth)
	}
}

// A dashboard bound to this machine's LAN address is reached over plain
// http when serve.json names it; the same address typed by hand isn't.
func TestLocalServerOnALANAddress(t *testing.T) {
	var ip string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			ip = n.IP.String()
			break
		}
	}
	if ip == "" {
		t.Skip("no LAN address")
	}
	if !ownAddress(ip) || ownAddress("192.0.2.1") {
		t.Fatalf("ownAddress(%s) wrong", ip)
	}
	r := newRig(t)
	r.env = map[string]string{}
	_ = os.WriteFile(filepath.Join(r.home, "serve.json"), []byte(`{"dashboardAddr":"`+ip+`:1"}`), 0o600)
	_ = os.WriteFile(filepath.Join(r.home, "admin.token"), []byte("admintoken\n"), 0o600)
	// Nothing listens there, so it can't be checked, but the URL is taken.
	if res := r.run("", "keys", "list"); res.code == ExitUsage {
		t.Fatalf("serve.json on a LAN address: %d %s", res.code, res.stderr)
	}
	if res := r.run("", "keys", "list", "--server", "http://"+ip+":2"); res.code != ExitUsage {
		t.Fatalf("plain http to an address serve.json doesn't name: %d", res.code)
	}
}

func TestSelfHostedLoginRoutesSayToUseAKey(t *testing.T) {
	r := newRig(t)
	resp, err := http.Post(r.api.URL+"/api/cli/login", "application/json", strings.NewReader(`{"name":"x"}`))
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("login route: %v %v", resp, err)
	}
	resp.Body.Close()
	// A self-hosted server named with --server, not the local one.
	r.env = map[string]string{}
	if res := r.run("", "login", "--server", r.api.URL); res.code != ExitNoAuth || !strings.Contains(res.stderr, "KEYSTUB_API_KEY") {
		t.Fatalf("login: %d %s", res.code, res.stderr)
	}
}

// fakeHosted serves the hosted CLI login routes: pending twice, then the
// token, or the final status. A refusing one sends no interval. Logout
// ends the token.
func fakeHosted(t *testing.T, final int) *httptest.Server {
	var polls int
	var ended bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/cli/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["name"] != "testbox" || r.Header.Get("Authorization") != "" {
			t.Errorf("login start: %v %q", in, r.Header.Get("Authorization"))
		}
		interval := `,"interval":5`
		if final != 200 {
			interval = ""
		}
		_, _ = io.WriteString(w, `{"code":"ABCD-EFGH","url":"https://app.example/cli?code=ABCD-EFGH","poll":"p_1"`+interval+`,"expiresIn":600}`)
	})
	mux.HandleFunc("POST /api/cli/login/poll", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["poll"] != "p_1" {
			t.Errorf("poll = %v", in)
		}
		polls++
		switch {
		case polls < 3:
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"pending":true}`)
		case final != 200:
			w.WriteHeader(final)
		default:
			_, _ = io.WriteString(w, `{"token":"skcli_abc","account":{"id":"acc_1","name":"Acme"},"user":{"id":"u_1","name":"Ada"}}`)
		}
	})
	mux.HandleFunc("POST /api/cli/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer skcli_abc" || ended {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ended = true
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer skcli_abc" || ended {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"type":"keystub","message":"no valid API key"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"user":{"id":"u_1","name":"Ada"},"account":{"id":"acc_1","name":"Acme","role":"admin"}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDeviceLogin(t *testing.T) {
	srv := fakeHosted(t, 200)
	r := &rig{t: t, home: t.TempDir(), env: map[string]string{}}
	var slept []time.Duration
	var opened []string
	var out, errb bytes.Buffer
	code := Main(Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Getenv: func(k string) string { return r.env[k] },
		Home: r.home, Hostname: "testbox", Sleep: func(d time.Duration) { slept = append(slept, d) },
		OpenURL: func(u string) error { opened = append(opened, u); return nil }}, "login", []string{"--server", srv.URL, "--json"})
	if code != 0 || !strings.Contains(errb.String(), "ABCD-EFGH") || len(slept) != 2 || slept[0] != 5*time.Second {
		t.Fatalf("login: %d %s %s %v", code, out.String(), errb.String(), slept)
	}
	// The approval page opens by itself, with the code on it.
	if len(opened) != 1 || !strings.Contains(opened[0], "ABCD-EFGH") || !strings.Contains(errb.String(), "opened in your browser") {
		t.Fatalf("opened %v; stderr %s", opened, errb.String())
	}
	if strings.Contains(out.String(), "skcli_abc") {
		t.Fatal("login printed the token")
	}
	path := filepath.Join(r.home, "cli.json")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cli.json: %v %v", st, err)
	}
	// Signed in, the server and token come from cli.json.
	who := r.must("", "whoami", "--json").json(t)
	if who["serverUrl"] != srv.URL || who["user"].(map[string]any)["name"] != "Ada" {
		t.Fatalf("whoami = %v", who)
	}
	// $KEYSTUB_API_KEY isn't sent to the server the login saved, which it
	// may not be for; named, that server gets it in place of the login.
	r.env["KEYSTUB_API_KEY"] = "skacct_other"
	if res := r.run("", "whoami"); res.code != ExitUsage || !strings.Contains(res.stderr, "KEYSTUB_SERVER") {
		t.Fatalf("env key, login's server: %d %s", res.code, res.stderr)
	}
	if res := r.run("", "whoami", "--server", srv.URL); res.code != ExitNoAuth {
		t.Fatalf("env key, named server: %d", res.code)
	}
	delete(r.env, "KEYSTUB_API_KEY")
	// Logout ends the session on the server it came from, even with
	// another server named.
	if out := r.must("", "logout", "--json", "--server", "http://127.0.0.1:1").json(t); out["ended"] != true {
		t.Fatalf("logout = %v", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("logout kept cli.json")
	}
	if res := r.run("", "whoami", "--server", srv.URL); res.code != ExitNoAuth {
		t.Fatalf("after logout: %d", res.code)
	}
	// A server that can't be reached: signed out here, and told to revoke it.
	if err := os.WriteFile(path, []byte(`{"server":"http://127.0.0.1:1","token":"skcli_abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.must("", "logout"); !strings.Contains(res.stdout, "revoke it") {
		t.Fatalf("unconfirmed logout: %s", res.stdout)
	}
}

func TestDeviceLoginDenied(t *testing.T) {
	srv := fakeHosted(t, http.StatusGone)
	r := &rig{t: t, home: t.TempDir(), env: map[string]string{"KEYSTUB_SERVER": srv.URL}}
	var slept []time.Duration
	var out, errb bytes.Buffer
	opened := false
	code := Main(Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, Getenv: func(k string) string { return r.env[k] },
		Home: r.home, Hostname: "testbox", Sleep: func(d time.Duration) { slept = append(slept, d) },
		OpenURL: func(string) error { opened = true; return nil }}, "login", []string{"--no-browser"})
	if opened {
		t.Error("--no-browser opened the browser")
	}
	if code != ExitNoAuth || !strings.Contains(errb.String(), "expired or was turned down") {
		t.Fatalf("denied: %d %s", code, errb.String())
	}
	// No interval given: it waits the default, never polls in a loop.
	if len(slept) != 2 || slept[0] != 5*time.Second {
		t.Fatalf("slept %v", slept)
	}
	if _, err := os.Stat(filepath.Join(r.home, "cli.json")); !os.IsNotExist(err) {
		t.Fatal("saved credentials for a denied login")
	}
}

func TestDeletesNeedConfirmation(t *testing.T) {
	r := newRig(t)
	r.must("", "envs", "add", "app/dev")
	var out, errb bytes.Buffer
	run := func(answer string) int {
		out.Reset()
		errb.Reset()
		return Main(Env{Stdin: strings.NewReader(answer), Stdout: &out, Stderr: &errb, StdinTerminal: true,
			Getenv: func(k string) string { return r.env[k] }, Home: r.home}, "envs", []string{"delete", "app/dev"})
	}
	if code := run("n\n"); code != ExitError {
		t.Fatalf("answered no: %d", code)
	}
	if _, ok := r.engine.Environment("app/dev"); !ok {
		t.Fatal("deleted without a yes")
	}
	if code := run("y\n"); code != 0 {
		t.Fatalf("answered yes: %d %s", code, errb.String())
	}
	if _, ok := r.engine.Environment("app/dev"); ok {
		t.Fatal("not deleted")
	}
}

// Hosted deletes an environment or a service over several requests,
// answering how many changes it has left; the CLI asks until none are.
func TestDeletesFinishWhatRemains(t *testing.T) {
	r := newRig(t)
	var calls []string
	left := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		n := left[req.URL.Path]
		if n > 0 {
			left[req.URL.Path] = n - 1
		}
		fmt.Fprintf(w, `{"ok":true,"remaining":%d}`, n)
	}))
	defer srv.Close()
	r.env["KEYSTUB_SERVER"] = srv.URL
	r.env["KEYSTUB_API_KEY"] = "skacct_test"

	left["/api/environments/app/dev"] = 3
	left["/api/environments/app/dev/resync"] = 2
	r.must("", "envs", "delete", "app/dev", "--yes")
	want := "DELETE /api/environments/app/dev,POST /api/environments/app/dev/resync,POST /api/environments/app/dev/resync,POST /api/environments/app/dev/resync"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("envs delete calls:\n%s\nwant\n%s", got, want)
	}

	calls = nil
	left["/api/services/acme"] = 2
	r.must("", "services", "remove", "acme", "--yes")
	if len(calls) != 3 || calls[2] != "DELETE /api/services/acme" {
		t.Fatalf("services remove calls: %v", calls)
	}

	// An edge that never catches up ends in an error, not a loop.
	calls = nil
	left["/api/services/stuck"] = 1 << 30
	if res := r.run("", "services", "remove", "stuck", "--yes"); res.code != ExitError || !strings.Contains(res.stderr, "still to reach the edge") || len(calls) != maxRounds {
		t.Fatalf("stuck: %d %s %d calls", res.code, res.stderr, len(calls))
	}
}

func TestWhoamiShowsNotices(t *testing.T) {
	r := newRig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, `{"server":"self-hosted","account":{"id":"local","name":"This server"},"notices":["token two (tk_two) in app/prod was revoked"]}`)
	}))
	defer srv.Close()
	r.env["KEYSTUB_SERVER"] = srv.URL
	if res := r.must("", "whoami"); !strings.Contains(res.stdout, "tk_two") {
		t.Fatalf("whoami: %s", res.stdout)
	}
}

func TestProjectAndEnvironmentLimits(t *testing.T) {
	r := newRig(t)
	r.must("", "services", "add", "echo", "--hosts", "api.echo.test")
	r.must("real-one", "keys", "add", "echo", "--name", "team")
	r.must("", "envs", "add", "shop/ci")
	tok := strings.TrimSpace(r.must("", "envs", "link", "shop/ci", "echo", "team").stdout)
	projectLimits := func() core.Limits {
		for _, p := range r.engine.Projects() {
			if p.ID == "shop" {
				return p.Limits
			}
		}
		t.Fatal("no project shop")
		return core.Limits{}
	}
	envLimits := func() core.Limits {
		e, _ := r.engine.Environment("shop/ci")
		return e.Limits
	}

	// A level not named keeps its value.
	got := r.must("", "projects", "limits", "shop", "--per-minute", "30", "--json").json(t)["project"].(map[string]any)
	if got["limits"].(map[string]any)["perMinute"].(float64) != 30 {
		t.Fatalf("projects limits JSON = %v", got)
	}
	r.must("", "projects", "limits", "shop", "--daily", "2")
	if l := projectLimits(); l.DailyRequests != 2 || l.PerMinute != 30 {
		t.Fatalf("project limits = %+v", l)
	}
	if list := r.must("", "projects", "list").stdout; !strings.Contains(list, "2/day, 30/min") {
		t.Fatalf("projects list = %s", list)
	}
	for i, want := range []int{200, 200, 429} {
		if st, _ := r.call("echo", tok); st != want {
			t.Fatalf("call %d: %d, want %d", i+1, st, want)
		}
	}
	r.must("", "projects", "limits", "shop", "--clear")
	if l := projectLimits(); l != (core.Limits{}) {
		t.Fatalf("cleared project limits = %+v", l)
	}

	r.must("", "envs", "limits", "shop/ci", "--daily", "100", "--per-minute", "10")
	env := r.must("", "envs", "limits", "shop/ci", "--per-minute", "5", "--json").json(t)["environment"].(map[string]any)
	if l := envLimits(); l.DailyRequests != 100 || l.PerMinute != 5 || env["limits"].(map[string]any)["dailyRequests"].(float64) != 100 {
		t.Fatalf("env limits = %+v, JSON %v", l, env)
	}
	r.must("", "envs", "limits", "shop/ci", "--clear")
	if l := envLimits(); l != (core.Limits{}) {
		t.Fatalf("cleared env limits = %+v", l)
	}

	r.must("", "keys", "limits", "team", "--daily", "50", "--per-minute", "5")
	k := r.must("", "keys", "limits", "team", "--daily", "60", "--json").json(t)["key"].(map[string]any)["limits"].(map[string]any)
	if k["dailyRequests"].(float64) != 60 || k["perMinute"].(float64) != 5 {
		t.Fatalf("key limits = %v", k)
	}

	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"projects", "limits", "shop"}, ExitUsage},
		{[]string{"projects", "limits", "shop", "--daily", "1", "--clear"}, ExitUsage},
		{[]string{"projects", "limits", "shop", "--daily", "-1"}, ExitUsage},
		{[]string{"projects", "limits", "nope", "--daily", "1"}, ExitNotFound},
		{[]string{"envs", "limits", "shop/nope", "--daily", "1"}, ExitNotFound},
		{[]string{"envs", "limits", "no-slash", "--daily", "1"}, ExitUsage},
		{[]string{"projects", "nope"}, ExitUsage},
	} {
		if res := r.run("", c.args...); res.code != c.code {
			t.Fatalf("%v: exit %d, want %d (%s)", c.args, res.code, c.code, res.stderr)
		}
	}
}

func TestLimitsKeepLevelsNotNamed(t *testing.T) {
	// A level the command doesn't name keeps its value, including when the
	// server sends no limits at all (null, as hosted does).
	p := parsed{flags: map[string]string{"daily": "0"}, set: map[string]bool{"daily": true}}
	if got := keepUnset(&limits{}, &limits{DailyRequests: 9, PerMinute: 5}, p); *got != (limits{0, 5}) {
		t.Fatalf("--daily 0 = %+v", got)
	}
	if got := keepUnset(&limits{DailyRequests: 3}, nil, p); *got != (limits{3, 0}) {
		t.Fatalf("no current limits = %+v", got)
	}
	if got := keepUnset(nil, &limits{DailyRequests: 9}, p); got != nil {
		t.Fatalf("--clear = %+v", got)
	}

	r := newRig(t)
	r.must("", "services", "add", "echo", "--hosts", "api.echo.test")
	r.must("real-one", "keys", "add", "echo", "--name", "team", "--daily", "50", "--per-minute", "5")
	r.must("", "keys", "limits", "team", "--daily", "0")
	k := r.must("", "keys", "show", "team", "--json").json(t)["key"].(map[string]any)["limits"].(map[string]any)
	if k["dailyRequests"].(float64) != 0 || k["perMinute"].(float64) != 5 {
		t.Fatalf("after --daily 0: %v", k)
	}
	r.must("", "keys", "limits", "team", "--clear")
	if k := r.must("", "keys", "show", "team", "--json").json(t)["key"].(map[string]any)["limits"]; k != nil {
		if m := k.(map[string]any); m["dailyRequests"].(float64) != 0 || m["perMinute"].(float64) != 0 {
			t.Fatalf("after --clear: %v", k)
		}
	}

	// Projects by ID or name; list JSON shape; text output.
	r.must("", "envs", "add", "shop/ci")
	r.must("", "projects", "limits", "SHOP", "--daily", "7")
	ps := r.must("", "projects", "list", "--json").json(t)["projects"].([]any)
	found := false
	for _, x := range ps {
		m := x.(map[string]any)
		if m["id"] == "shop" {
			found = m["limits"].(map[string]any)["dailyRequests"].(float64) == 7
		}
	}
	if !found {
		t.Fatalf("projects list = %v", ps)
	}
	if out := r.must("", "envs", "limits", "shop/ci", "--per-minute", "3").stdout; out != "Limits for shop/ci: 3/min.\n" {
		t.Fatalf("envs limits printed %q", out)
	}
}
