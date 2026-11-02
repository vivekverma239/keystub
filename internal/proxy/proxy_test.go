package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

var bg = context.Background()

// keys wraps the engine so tests read simply: create a token, revoke it.
type keys struct{ e *core.Engine }

func (k keys) CreateKey(name string, limit int) (string, core.Token, error) {
	return k.e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: name, Limits: core.Limits{DailyRequests: limit}})
}
func (k keys) RevokeKey(id string) error { return k.e.RevokeToken(bg, id) }

type rig struct {
	store    keys
	log      *reqlog.Log
	ca       *ca.CA
	proxyURL *url.URL
	upstream *httptest.Server
}

// newRig starts an upstream TLS server, a store with one service for it,
// and the proxy in front.
func newRig(t *testing.T, serviceHost string, handler http.HandlerFunc) *rig {
	t.Helper()
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)

	s, dir := coretest.Engine(t, "")
	c, err := ca.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := reqlog.Open("", 50)
	if err := s.AddService(bg, core.Service{ID: "echo", Name: "Echo", Hosts: []string{serviceHost}, Header: "Authorization", Format: "Bearer {key}"}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, s, core.DefaultEnv, "echo", "real-secret-xyz"); err != nil {
		t.Fatal(err)
	}

	p := New(s, c, l)
	upPool := x509.NewCertPool()
	upPool.AddCert(up.Certificate())
	p.Upstream = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: upPool}, ForceAttemptHTTP2: true}

	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	pu, _ := url.Parse(ps.URL)
	return &rig{store: keys{s}, log: l, ca: c, proxyURL: pu, upstream: up}
}

// waitLog waits for n log entries; the proxy writes an entry just after it
// finishes sending the response, so it can land after the client returns.
func (r *rig) waitLog(t *testing.T, n int) []reqlog.Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e := r.log.Recent(n + 5)
		if len(e) >= n || time.Now().After(deadline) {
			return e
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// client trusts the given roots and sends everything through the proxy,
// optionally with a proxy token in the proxy URL.
func (r *rig) client(roots *x509.CertPool, token string) *http.Client {
	pu := *r.proxyURL
	if token != "" {
		pu.User = url.UserPassword("keystub", token)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&pu),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
}

func TestInterceptSwapsKey(t *testing.T) {
	var gotAuth string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		_, _ = io.WriteString(w, "hello "+req.URL.Path)
	})
	token, _, err := r.store.CreateKey("wt-test", 0)
	if err != nil {
		t.Fatal(err)
	}

	// The SDK sends the placeholder as its API key; no proxy auth.
	c := r.client(r.ca.Pool(), "")
	req, _ := http.NewRequest("GET", r.upstream.URL+"/v1/models?secret=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello /v1/models" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if gotAuth != "Bearer real-secret-xyz" {
		t.Fatalf("upstream saw Authorization %q", gotAuth)
	}

	// Keep-alive: a second request on the same client works too.
	req2, _ := http.NewRequest("GET", r.upstream.URL+"/again", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := c.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()

	entries := r.waitLog(t, 2)
	if len(entries) != 2 || entries[1].Key != "wt-test" || entries[1].Path != "/v1/models" || entries[1].Status != 200 ||
		entries[1].Env != core.DefaultEnv || entries[1].Project != "default" || entries[1].TokenID == "" {
		t.Fatalf("log = %+v", entries)
	}
	for _, e := range entries {
		if strings.Contains(e.Path, "secret") {
			t.Fatal("query string reached the log")
		}
	}
}

func TestProxyAuthIdentifiesCaller(t *testing.T) {
	var gotAuth string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
	})
	token, _, _ := r.store.CreateKey("proxy-auth", 0)
	resp, err := r.client(r.ca.Pool(), token).Get(r.upstream.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || gotAuth != "Bearer real-secret-xyz" {
		t.Fatalf("status %d, upstream saw %q", resp.StatusCode, gotAuth)
	}
}

func TestUnknownAndRevokedKeysAreRefused(t *testing.T) {
	called := false
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) { called = true })
	c := r.client(r.ca.Pool(), "")

	resp, err := c.Get(r.upstream.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no key: got %d", resp.StatusCode)
	}

	token, k, _ := r.store.CreateKey("soon-revoked", 0)
	_ = r.store.RevokeKey(k.ID)
	req, _ := http.NewRequest("GET", r.upstream.URL+"/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked key: got %d", resp.StatusCode)
	}
	if called {
		t.Fatal("upstream was called without a valid key")
	}
}

func TestDailyLimitRefuses(t *testing.T) {
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {})
	token, _, _ := r.store.CreateKey("limited", 1)
	c := r.client(r.ca.Pool(), token)
	for i, want := range []int{200, http.StatusTooManyRequests} {
		resp, err := c.Get(r.upstream.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("request %d: got %d, want %d", i, resp.StatusCode, want)
		}
	}
}

func TestStreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
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
	token, _, _ := r.store.CreateKey("stream", 0)
	resp, err := r.client(r.ca.Pool(), token).Get(r.upstream.URL + "/stream")
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

func TestOtherHostsAreTunnelled(t *testing.T) {
	var gotAuth string
	// The service is for a different host, so 127.0.0.1 passes through.
	r := newRig(t, "api.example.com", func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
	})
	upPool := x509.NewCertPool()
	upPool.AddCert(r.upstream.Certificate())
	req, _ := http.NewRequest("GET", r.upstream.URL+"/x", nil)
	req.Header.Set("Authorization", "Bearer untouched")
	resp, err := r.client(upPool, "").Do(req) // trusts the real cert, not our CA
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || gotAuth != "Bearer untouched" {
		t.Fatalf("status %d, upstream saw %q", resp.StatusCode, gotAuth)
	}
	if n := len(r.log.Recent(10)); n != 0 {
		t.Fatalf("tunnelled request was logged as intercepted (%d entries)", n)
	}
}

func TestSwapKeepsHeaderShape(t *testing.T) {
	var gotAuth string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
	})
	token, _, _ := r.store.CreateKey("shape", 0)
	basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	for sent, want := range map[string]string{
		"token " + token:                 "token real-secret-xyz",                 // gh CLI
		basic("x-access-token:" + token): basic("x-access-token:real-secret-xyz"), // git over HTTPS
		"Convex prod:my-app|" + token:    "Convex prod:my-app|real-secret-xyz",    // prefixed key
	} {
		req, _ := http.NewRequest("GET", r.upstream.URL+"/x", nil)
		req.Header.Set("Authorization", sent)
		resp, err := r.client(r.ca.Pool(), "").Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || gotAuth != want {
			t.Errorf("sent %q: status %d, upstream saw %q, want %q", sent, resp.StatusCode, gotAuth, want)
		}
	}
}

func TestExpectContinueIsAnswered(t *testing.T) {
	var got int
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got = len(b)
	})
	token, _, _ := r.store.CreateKey("upload", 0)
	c := r.client(r.ca.Pool(), token)
	c.Transport.(*http.Transport).ExpectContinueTimeout = 5 * time.Second
	req, _ := http.NewRequest("POST", r.upstream.URL+"/upload", strings.NewReader(strings.Repeat("x", 1<<20)))
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

func TestWebsocketUpgrade(t *testing.T) {
	var gotAuth string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
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
	token, _, _ := r.store.CreateKey("ws", 0)
	req, _ := http.NewRequest("GET", r.upstream.URL+"/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := r.client(r.ca.Pool(), token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	rwc := resp.Body.(io.ReadWriteCloser)
	defer rwc.Close()
	_, _ = io.WriteString(rwc, "ping\n")
	line, err := bufio.NewReader(rwc).ReadString('\n')
	if err != nil || line != "echo ping\n" {
		t.Fatalf("got %q, %v", line, err)
	}
	if gotAuth != "Bearer real-secret-xyz" {
		t.Fatalf("upstream saw %q", gotAuth)
	}
}

func TestPlainHTTPGetsNoKey(t *testing.T) {
	var gotAuth string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
	}))
	defer plain.Close()
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {})
	token, _, _ := r.store.CreateKey("plain", 0)
	req, _ := http.NewRequest("GET", plain.URL+"/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.client(r.ca.Pool(), "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || gotAuth != "Bearer "+token {
		t.Fatalf("status %d, upstream saw %q (a real key must never go over plain HTTP)", resp.StatusCode, gotAuth)
	}
}

func TestPipeEndsWhenPeerNeverCloses(t *testing.T) {
	stuck, held := net.Pipe() // `held` is never closed or written: a peer that hangs
	defer held.Close()
	finished := make(chan struct{})
	go func() {
		// b ends at once (EOF); a would block forever without closeAll.
		pipe(stuck, io.Discard, strings.NewReader(""), stuck, 50*time.Millisecond, func() { stuck.Close() })
		close(finished)
	}()
	go func() { _, _ = io.Copy(io.Discard, held) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe never returned")
	}
}

func TestCompactTokenForm(t *testing.T) {
	var gotAuth string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
	})
	token, _, _ := r.store.CreateKey("vercel-style", 0)
	compact := core.Compact(token)
	if strings.Contains(compact, "-") {
		t.Fatalf("compact form has a dash: %q", compact)
	}
	req, _ := http.NewRequest("GET", r.upstream.URL+"/v2/user", nil)
	req.Header.Set("Authorization", "Bearer "+compact)
	resp, err := r.client(r.ca.Pool(), "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || gotAuth != "Bearer real-secret-xyz" {
		t.Fatalf("status %d, upstream saw %q", resp.StatusCode, gotAuth)
	}
}

func TestScopedTokens(t *testing.T) {
	var gotAuth string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
	})
	e := r.store.e
	if err := e.AddService(bg, core.Service{ID: "other", Name: "Other", Hosts: []string{"other.example"}, Header: "Authorization"}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, e, core.DefaultEnv, "other", "real-other"); err != nil {
		t.Fatal(err)
	}
	scoped, _, err := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "agent", Service: "other"})
	if err != nil {
		t.Fatal(err)
	}
	call := func(token string) int {
		t.Helper()
		resp, err := r.client(r.ca.Pool(), token).Get(r.upstream.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := call(scoped); got != http.StatusForbidden {
		t.Fatalf("token scoped to another service: %d", got)
	}

	run, _, err := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "run-1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if got := call(run); got != 200 || gotAuth != "Bearer real-secret-xyz" {
		t.Fatalf("expiring token: %d, upstream saw %q", got, gotAuth)
	}
	entries := r.waitLog(t, 2)
	if entries[0].Key != "run-1" {
		t.Fatalf("log = %+v", entries[0])
	}
}

func TestTokenOutsideAuthHeadersIsRefused(t *testing.T) {
	reached := false
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) { reached = true })
	token, k, _ := r.store.CreateKey("stray", 0)
	req, _ := http.NewRequest("POST", r.upstream.URL+"/v1/customers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", token) // a header the service may keep and echo
	resp, err := r.client(r.ca.Pool(), "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || reached {
		t.Fatalf("status %d, reached upstream %v", resp.StatusCode, reached)
	}
	if n := r.store.e.UsedToday(bg, "token:"+k.ID); n != 0 {
		t.Fatalf("refused request counted: %d", n)
	}
	// A generic API-key header the service doesn't use is refused too.
	req, _ = http.NewRequest("GET", r.upstream.URL+"/x", nil)
	req.Header.Set("X-Api-Key", token)
	resp, err = r.client(r.ca.Pool(), "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || reached {
		t.Fatalf("X-Api-Key: status %d, reached upstream %v", resp.StatusCode, reached)
	}
}

func TestRequireTokenGuardsTunnelsToo(t *testing.T) {
	r := newRig(t, "intercepted.example", func(http.ResponseWriter, *http.Request) {})
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "tunnelled") }))
	t.Cleanup(other.Close)
	pool := x509.NewCertPool()
	pool.AddCert(other.Certificate())

	p := New(r.store.e, r.ca, r.log)
	p.RequireToken = true
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	via := func(token string) (int, error) {
		pu, _ := url.Parse(ps.URL)
		if token != "" {
			pu.User = url.UserPassword("keystub", token)
		}
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}
		resp, err := c.Get(other.URL)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if _, err := via(""); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("tunnel without a token: %v", err)
	}
	if _, err := via(core.TokenPrefix + "0123abcd"); err == nil {
		t.Fatal("tunnel with an unknown token was allowed")
	}
	token, k, _ := r.store.CreateKey("ci", 0)
	if code, err := via(token); err != nil || code != 200 {
		t.Fatalf("tunnel with a valid token: %d, %v", code, err)
	}
	_ = r.store.RevokeKey(k.ID)
	if _, err := via(token); err == nil {
		t.Fatal("tunnel with a revoked token was allowed")
	}
}

func TestBlockPrivateKeepsTokenHoldersOffTheHostNetwork(t *testing.T) {
	var reached bool
	r := newRig(t, "svc.example", func(http.ResponseWriter, *http.Request) {}) // 127.0.0.1 is not a service here
	private := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	t.Cleanup(private.Close)
	privateTLS := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	t.Cleanup(privateTLS.Close)
	token, _, _ := r.store.CreateKey("ci", 0)

	p := New(r.store.e, r.ca, r.log)
	p.RequireToken, p.BlockPrivate = true, true
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	pu, _ := url.Parse(ps.URL)
	pu.User = url.UserPassword("keystub", token)
	pool := x509.NewCertPool()
	pool.AddCert(privateTLS.Certificate())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}

	// Plain HTTP to a loopback address: refused with 403.
	resp, err := c.Get(private.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("plain HTTP to loopback: %d", resp.StatusCode)
	}
	// A tunnel to a loopback port that isn't a service: refused.
	if _, err := c.Get(privateTLS.URL); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("tunnel to loopback: %v", err)
	}
	if reached {
		t.Fatal("a private server was reached")
	}
}

func TestHostHeaderIsTheServiceNotTheClients(t *testing.T) {
	var gotHost string
	r := newRig(t, "127.0.0.1", func(w http.ResponseWriter, req *http.Request) { gotHost = req.Host })
	token, _, _ := r.store.CreateKey("fronting", 0)
	req, _ := http.NewRequest("GET", r.upstream.URL+"/x", nil)
	req.Host = "attackers-app.example"
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.client(r.ca.Pool(), "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := strings.TrimPrefix(r.upstream.URL, "https://"); gotHost != want {
		t.Fatalf("upstream saw Host %q, want %q", gotHost, want)
	}
}

func TestPublicOnly(t *testing.T) {
	for addr, ok := range map[string]bool{
		"93.184.216.34:443": true, "[2606:2800:220:1::]:443": true,
		"127.0.0.1:80": false, "10.0.0.1:80": false, "169.254.169.254:80": false, "0.0.0.0:80": false,
		"100.100.100.200:80": false, "100.64.0.1:80": false, "[64:ff9b::a9fe:a9fe]:80": false,
		"[::ffff:127.0.0.1]:80": false, "[fd00:ec2::254]:80": false, "[::1]:80": false,
	} {
		if err := publicOnly("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("%s: allowed=%v, want %v", addr, err == nil, ok)
		}
	}
}

// hostSet is a Catalog with fixed services, as an agent's would be.
type hostSet []core.Service

func (h hostSet) ServiceForHost(host string) (core.Service, bool) {
	for _, s := range h {
		if s.Matches(host) {
			return s, true
		}
	}
	return core.Service{}, false
}

func TestAgentRefusesWhatTheEdgeCantReach(t *testing.T) {
	edge := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("request reached the edge") }))
	defer edge.Close()
	eu, _ := url.Parse(edge.URL)
	dir := t.TempDir()
	c, err := ca.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := NewAgent(hostSet{{ID: "echo", Name: "Echo", Hosts: []string{"127.0.0.1"}, Header: "Authorization"}}, eu, c, nil)
	ps := httptest.NewServer(p)
	defer ps.Close()
	pu, _ := url.Parse(ps.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: c.Pool()}}}

	// /h/<host> always means port 443, so another port can't be forwarded.
	resp, err := client.Get("https://127.0.0.1:8443/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("non-443 port: %d", resp.StatusCode)
	}

	// An agent can't check tokens, so RequireToken refuses everything.
	p.RequireToken = true
	pu.User = url.UserPassword("keystub", "sk-stub-00ff")
	_, err = client.Get("https://127.0.0.1:8443/v1/models")
	if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("RequireToken on an agent: %v", err)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8787": true, "[::1]:8787": true, "localhost:8787": true,
		"0.0.0.0:8787": false, "10.0.0.2:8787": false, "example.com:443": false, "127.0.0.1": false,
	} {
		if IsLoopback(addr) != want {
			t.Errorf("%s: want %v", addr, want)
		}
	}
}

func TestAgentPlainHTTPDoesntUseTheEdgeTransport(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "plain") }))
	defer plain.Close()
	eu, _ := url.Parse("https://edge.invalid")
	p := NewAgent(hostSet{}, eu, nil, nil)
	p.Upstream = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("plain HTTP went through the edge transport")
		return nil, io.EOF
	})
	ps := httptest.NewServer(p)
	defer ps.Close()
	pu, _ := url.Parse(ps.URL)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}).Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "plain" {
		t.Fatalf("got %q", b)
	}
	if tr, ok := p.plainPublic.(*http.Transport); !ok || tr.IdleConnTimeout == 0 {
		t.Fatalf("plain transport keeps idle connections forever: %+v", p.plainPublic)
	}
}

func TestOwnCredential(t *testing.T) {
	const tk = "sk-stub-0123456789abcdef0123456789abcdef0123"
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for v, own := range map[string]bool{
		"Bearer " + tk:                       false,
		tk:                                   false,
		"Bearer " + core.Compact(tk):         false,
		"prod:my-app|" + tk:                  false,
		"Bearer":                             false,
		"":                                   false,
		"Basic " + b64("x-access-token:"+tk): false,
		"Basic " + b64(tk+":"):               false,
		"Basic " + b64(tk+":x-oauth-basic"):  false,
		"Convex prod:my-app|" + tk:           false,
		"Key " + tk:                          false,
		"DeepL-Auth-Key " + tk:               false,
		"Basic " + b64(tk+":X"):              false,
		"Basic " + b64(tk+":api_token"):      false,
		"sk-proj-real":                       true,
		"Bearer sk-real-key":                 true,
		"Bearer undefined":                   true,
		"Bearer " + tk + " sk-real-key":      true,
		"Basic " + b64(tk+":realpassword"):   true,
		"Basic " + b64("me:ghp_real"):        true,
		"Basic not-base64!":                  true,
	} {
		if got := ownCredential(v); got != own {
			t.Errorf("%q: %v, want %v", v, got, own)
		}
	}
	h := http.Header{}
	h.Add("X-Api-Key", tk)
	h.Add("X-Api-Key", "sk-ant-real")
	if got := realCredential(h, "x-api-key"); got != "X-Api-Key" {
		t.Fatalf("a real key as a second value of the service's header: %q", got)
	}
	if got := realCredential(http.Header{"X-Api-Key": {tk}}, "x-api-key"); got != "" {
		t.Fatalf("the token in the service's header: %q", got)
	}
}
