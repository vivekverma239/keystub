package main

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/proxy"
)

const tok = "sk-stub-0123456789abcdef0123456789abcdef0123"

func TestRunOptsCheck(t *testing.T) {
	for name, c := range map[string]struct {
		o  runOpts
		ok bool
	}{
		"admin path":           {runOpts{}, true},
		"token":                {runOpts{token: tok}, true},
		"compact token":        {runOpts{token: core.Compact(tok)}, true},
		"remote with token":    {runOpts{token: tok, remote: "https://e.example"}, true},
		"remote without token": {runOpts{remote: "https://e.example"}, false},
		"token with env":       {runOpts{token: tok, envID: "a/b"}, false},
		"token with name":      {runOpts{token: tok, name: "x"}, false},
		"not a token":          {runOpts{token: "hunter2"}, false},
	} {
		if err := c.o.check(); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBuildFromCatalog(t *testing.T) {
	cat := proxy.CatalogResponse{
		Token: proxy.CatalogToken{Name: "ci", Env: "my-app/dev"},
		Services: []proxy.CatalogService{
			{ID: "openai", Name: "OpenAI", EnvVars: []string{"OPENAI_API_KEY"}, BaseURL: core.BaseURL{Var: "OPENAI_BASE_URL", Path: "/v1"}},
			{ID: "github", Name: "GitHub", EnvVars: []string{"GH_TOKEN"}},
		},
	}
	v, err := build(fromCatalog(tok, cat), where{edgeURL: "https://e.example"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if v["OPENAI_BASE_URL"] != "https://e.example/s/openai/v1" || v["OPENAI_API_KEY"] != tok || v["GH_TOKEN"] != "" || v["KEYSTUB_KEY"] != "ci" || v["KEYSTUB_ENV"] != "my-app/dev" {
		t.Fatalf("direct vars = %v", v)
	}
	v, err = build(fromCatalog(tok, cat), where{proxyAddr: "127.0.0.1:9", caPath: "/ca.pem"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if v["HTTPS_PROXY"] != "http://keystub:"+tok+"@127.0.0.1:9" || v["GH_TOKEN"] != tok || v["OPENAI_BASE_URL"] != "" {
		t.Fatalf("proxy vars = %v", v)
	}
}

func TestExitCodePassesThrough(t *testing.T) {
	err := runChild("/bin/sh", []string{"sh", "-c", "exit 7"}, nil)
	if c, ok := err.(exitCode); !ok || c != 7 {
		t.Fatalf("got %v", err)
	}
}

func writeInfo(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLocalPrefersTheRightThing(t *testing.T) {
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	writeInfo(t, filepath.Join(dir, "agent.json"), agentInfo{ProxyAddr: l.Addr().String(), Remote: "https://e.example", Services: []string{"openai"}, PID: os.Getpid()})

	// Only an agent: fine with a token, a clear error without.
	if w, si, ai, err := local(dir, true); err != nil || si != nil || ai == nil || w.proxyAddr != l.Addr().String() || w.edgeURL != "https://e.example" {
		t.Fatalf("agent with token: %+v %v", w, err)
	}
	if _, _, _, err := local(dir, false); err == nil || !strings.Contains(err.Error(), "--token") {
		t.Fatalf("agent without token: %v", err)
	}

	// A server too: without a token, the server hands one out.
	writeInfo(t, filepath.Join(dir, "serve.json"), serveInfo{ProxyAddr: "127.0.0.1:8787", DashboardAddr: "127.0.0.1:8788", EdgeAddr: "127.0.0.1:8789"})
	if w, si, _, err := local(dir, false); err != nil || si == nil || w.proxyAddr != "127.0.0.1:8787" || w.edgeURL != "http://127.0.0.1:8789" {
		t.Fatalf("server without token: %+v %v", w, err)
	}
	if w, _, _, _ := local(dir, true); w.proxyAddr != l.Addr().String() {
		t.Fatalf("with a token the agent comes first: %+v", w)
	}

	// An agent that crashed and left agent.json behind is skipped, even
	// when something else (a `keystub serve`) took its port.
	writeInfo(t, filepath.Join(dir, "agent.json"), agentInfo{ProxyAddr: l.Addr().String(), Remote: "https://e.example", PID: deadPID(t)})
	if w, si, _, err := local(dir, true); err != nil || si == nil || w.proxyAddr != "127.0.0.1:8787" {
		t.Fatalf("dead agent, port taken: %+v %v", w, err)
	}
	writeInfo(t, filepath.Join(dir, "agent.json"), agentInfo{ProxyAddr: l.Addr().String(), Remote: "https://e.example", PID: os.Getpid()})
	l.Close()
	if w, si, _, err := local(dir, true); err != nil || si == nil || w.proxyAddr != "127.0.0.1:8787" {
		t.Fatalf("stale agent: %+v %v", w, err)
	}
}

func TestOnlyDecryptedServicesGetTheToken(t *testing.T) {
	is := issued{token: tok, services: []svcVars{{ID: "openai", Name: "OpenAI", EnvVars: []string{"OPENAI_API_KEY"}}, {ID: "github", Name: "GitHub", EnvVars: []string{"GH_TOKEN"}}}}
	got := onlyDecrypted(is, &agentInfo{Services: []string{"openai"}})
	if len(got.services) != 1 || got.services[0].ID != "openai" {
		t.Fatalf("kept %+v", got.services)
	}
	if got := onlyDecrypted(is, &agentInfo{}); len(got.services) != 2 {
		t.Fatalf("an agent.json from before services were listed drops %+v", got.services)
	}
	if got := onlyDecrypted(is, nil); len(got.services) != 2 {
		t.Fatal("no agent drops services")
	}
}

func TestParseRemote(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://e.example":         true,
		"https://e.example/":        true,
		"https://e.example/keystub": true,
		"http://127.0.0.1:8789":     true,
		"http://localhost:8789":     true,
		"http://10.0.0.5:8789":      false,
		"http://keystub.example":    false,
		"https://e.example/?x=1":    false,
		"https://e.example/#top":    false,
		"https://me:pw@e.example":   false,
		"ftp://e.example":           false,
		"e.example":                 false,
	} {
		if _, err := parseRemote(in); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
}

// deadPID is the PID of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	c := exec.Command("/bin/sh", "-c", "exit 0")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	return c.Process.Pid
}

func TestTokenStaysOutOfUsage(t *testing.T) {
	t.Setenv("KEYSTUB_TOKEN", tok)
	var out strings.Builder
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(&out)
	var o runOpts
	o.flags(fs)
	fs.PrintDefaults()
	if strings.Contains(out.String(), tok) {
		t.Fatalf("usage shows the token:\n%s", out.String())
	}
	o.parse(fs, nil)
	if o.token != tok {
		t.Fatalf("$KEYSTUB_TOKEN not used: %q", o.token)
	}
}

func TestOnThisBox(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8789":   "127.0.0.1:8789",
		":8789":          "127.0.0.1:8789",
		"[::]:8789":      "[::1]:8789",
		"127.0.0.1:8789": "127.0.0.1:8789",
		"10.0.0.5:8789":  "10.0.0.5:8789",
	} {
		if got := onThisBox(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	// A server on every interface (Docker, a devcontainer) is still this box's.
	dir := t.TempDir()
	writeInfo(t, filepath.Join(dir, "serve.json"), serveInfo{ProxyAddr: "0.0.0.0:8787", EdgeAddr: "0.0.0.0:8789"})
	w, _, _, err := local(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRemote(w.edgeURL); err != nil || w.proxyAddr != "127.0.0.1:8787" {
		t.Fatalf("%+v: %v", w, err)
	}
}
