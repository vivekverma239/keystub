package gateway

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/proxy"
)

const gatewayKey = "gw-test-credential-0123456789abcdef"

// testCA is an account's CA as the edge hands it out.
type testCA struct {
	certPEM string
	keyB64  string // PKCS #8
	cert    *x509.Certificate
	pool    *x509.CertPool
}

func newTestCA(t *testing.T, account string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Keystub account CA", OrganizationalUnit: []string{account}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	k8, _ := x509.MarshalPKCS8PrivateKey(key)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyB64: base64.StdEncoding.EncodeToString(k8), cert: cert, pool: pool}
}

func expiredCA(t *testing.T) testCA {
	c := newTestCA(t, "old")
	key, _ := x509.ParsePKCS8PrivateKey(pemBytes(c.keyB64))
	tmpl := *c.cert
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.(*ecdsa.PrivateKey).Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c.certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return c
}

func pemBytes(b64 string) []byte {
	b, _ := base64.StdEncoding.DecodeString(b64)
	return b
}

// fakeEdge serves /gateway/check, /gateway/ca and /h as the hosted edge
// does, with tokens and CAs held in memory.
type fakeEdge struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	accounts map[string]string // token → account
	revoked  map[string]bool
	cas      map[string]testCA
	hosts    map[string][]string // service ID → hosts it lists (default: openai's)
	caFor    func(account string) string
	fail     bool // /gateway/check answers 500
	status   int  // if set, /gateway/check answers it as a refusal (token_refused)
	bare     int  // if set, /gateway/check answers it as something in front of the edge would
	delay    time.Duration
	caHook   func(tok string) // runs before /gateway/ca answers, unlocked
	expired  bool             // /gateway/ca hands out an expired CA
	seen     []http.Header
	paths    []string
	checks   atomic.Int32
	caCalls  atomic.Int32
}

func newFakeEdge(t *testing.T) *fakeEdge {
	e := &fakeEdge{t: t, accounts: map[string]string{}, revoked: map[string]bool{}, cas: map[string]testCA{},
		hosts: map[string][]string{"openai": {"api.openai.com"}}}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *fakeEdge) addToken(account string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	tok := "sk-stub-" + fmt.Sprintf("%x", b)
	e.accounts[tok] = account
	if _, ok := e.cas[account]; !ok {
		e.cas[account] = newTestCA(e.t, account)
	}
	return tok
}

func (e *fakeEdge) revoke(tok string) {
	e.mu.Lock()
	e.revoked[tok] = true
	e.mu.Unlock()
}

func refuse(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{"type": "keystub", "message": "keystub: " + msg}
	if code != "" {
		body["code"] = code
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": body})
}

func (e *fakeEdge) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	delay, hook := e.delay, e.caHook
	e.mu.Unlock()
	if r.URL.Path == "/gateway/check" && delay > 0 {
		time.Sleep(delay)
	}
	if r.URL.Path == "/gateway/ca" && hook != nil {
		hook(r.Header.Get(proxy.TokenHeader))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/h/") {
		e.seen = append(e.seen, r.Header.Clone())
		e.paths = append(e.paths, r.URL.Path)
		tok := r.Header.Get(proxy.TokenHeader)
		_, _ = fmt.Fprintf(w, "edge served %s for %s", r.URL.Path, e.accounts[tok])
		return
	}
	if r.Method != http.MethodPost || r.Header.Get(KeyHeader) != gatewayKey {
		refuse(w, http.StatusUnauthorized, "gateway_credential", "the gateway credential is missing or wrong")
		return
	}
	tok := r.Header.Get(proxy.TokenHeader)
	account, ok := e.accounts[tok]
	switch r.URL.Path {
	case "/gateway/check":
		e.checks.Add(1)
		if e.fail {
			refuse(w, http.StatusInternalServerError, "", "internal error")
			return
		}
		if e.status != 0 {
			refuse(w, e.status, "token_refused", "this proxy token can't be used here")
			return
		}
		if e.bare != 0 {
			// A WAF or access page: not the edge's JSON, no code.
			w.WriteHeader(e.bare)
			_, _ = io.WriteString(w, "<html>Access denied</html>")
			return
		}
		if !ok || e.revoked[tok] {
			refuse(w, http.StatusUnauthorized, "token_refused", "this request has no valid proxy token")
			return
		}
		var svcs []proxy.CatalogService
		for id, hosts := range e.hosts {
			svcs = append(svcs, proxy.CatalogService{ID: id, Name: id, Hosts: hosts})
		}
		_ = json.NewEncoder(w).Encode(checkResponse{AccountID: account, CatalogResponse: proxy.CatalogResponse{
			Token: proxy.CatalogToken{ID: "tk_" + tok[8:14], Name: "ci", Env: "app/dev"}, Services: svcs}})
	case "/gateway/ca":
		e.caCalls.Add(1)
		if !ok || e.revoked[tok] {
			refuse(w, http.StatusUnauthorized, "token_refused", "this request has no valid proxy token")
			return
		}
		named := account
		if e.caFor != nil {
			named = e.caFor(account)
		}
		c := e.cas[named]
		if e.expired {
			c = expiredCA(e.t)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"accountId": named, "certificate": c.certPEM, "key": c.keyB64})
	default:
		refuse(w, http.StatusNotFound, "", "no such route")
	}
}

func (e *fakeEdge) ca(account string) testCA {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cas[account]
}

// startGateway runs a gateway against e on a loopback port.
func startGateway(t *testing.T, e *fakeEdge, mod func(*Gateway)) (*Gateway, string) {
	t.Helper()
	u, _ := url.Parse(e.srv.URL)
	g, err := New(Config{Edge: u, Key: gatewayKey, Transport: e.srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(g)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(l, nil) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = g.Shutdown(ctx)
	})
	return g, l.Addr().String()
}

// client goes through the gateway as a box does, trusting only roots.
func client(addr, token string, roots *x509.CertPool) *http.Client {
	pu := &url.URL{Scheme: "http", Host: addr}
	if token != "" {
		pu.User = url.UserPassword("keystub", token)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true,
	}}
}

func get(t *testing.T, c *http.Client, u string) (string, error) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(b), nil
}

// connectRaw sends a CONNECT and returns the answer, and the connection
// to read the tunnel from.
func connectRaw(t *testing.T, addr, target, auth string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp, c, br
}

func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("keystub:"+tok))
}

func TestEndToEnd(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)

	c := client(addr, tok, e.ca("acct_a").pool)
	for i := 0; i < 2; i++ {
		body, err := get(t, c, "https://api.openai.com/v1/models?limit=2")
		if err != nil {
			t.Fatal(err, body)
		}
		if body != "edge served /h/api.openai.com/v1/models for acct_a" {
			t.Fatalf("body = %q", body)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.seen) != 2 {
		t.Fatalf("edge saw %d requests", len(e.seen))
	}
	h := e.seen[0]
	if h.Get(proxy.TokenHeader) != tok {
		t.Fatalf("Keystub-Token = %q", h.Get(proxy.TokenHeader))
	}
	if h.Get(KeyHeader) != "" || h.Get("Proxy-Authorization") != "" {
		t.Fatal("the gateway's credential or Proxy-Authorization reached /h")
	}
	// One check and one CA fetch for both connections.
	if n := e.checks.Load(); n != 1 {
		t.Fatalf("checks = %d", n)
	}
	if n := e.caCalls.Load(); n != 1 {
		t.Fatalf("CA fetches = %d", n)
	}
}

// leafIssuer CONNECTs with tok and returns the certificate the gateway
// presents for host.
func leafIssuer(t *testing.T, addr, tok, host string) *x509.Certificate {
	t.Helper()
	resp, c, br := connectRaw(t, addr, host+":443", basic(tok))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %s", resp.Status)
	}
	tc := tls.Client(&readerConn{Conn: c, r: br}, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc.ConnectionState().PeerCertificates[0]
}

type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func TestAccountIsolation(t *testing.T) {
	e := newFakeEdge(t)
	ta, tb := e.addToken("acct_a"), e.addToken("acct_b")
	ta2 := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	caA, caB := e.ca("acct_a"), e.ca("acct_b")

	// Interleaved, in parallel: each token's connections are signed by its
	// own account's CA, never the other's.
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 10; i++ {
		for _, c := range []struct {
			tok      string
			own, not testCA
		}{{ta, caA, caB}, {tb, caB, caA}, {ta2, caA, caB}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := get(t, client(addr, c.tok, c.own.pool), "https://api.openai.com/v1/models"); err != nil {
					errs <- fmt.Errorf("own CA: %w", err)
				}
				if _, err := get(t, client(addr, c.tok, c.not.pool), "https://api.openai.com/v1/models"); err == nil {
					errs <- errors.New("a connection verified with another account's CA")
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tok string
		ca  testCA
	}{{ta, caA}, {tb, caB}} {
		leaf := leafIssuer(t, addr, c.tok, "api.openai.com")
		if err := leaf.CheckSignatureFrom(c.ca.cert); err != nil {
			t.Fatalf("leaf not signed by the token's own account CA: %v", err)
		}
	}
	// Each account's CA was fetched once, with a token of that account.
	if n := e.caCalls.Load(); n != 2 {
		t.Fatalf("CA fetches = %d", n)
	}
}

func TestCAForAnotherAccountIsRefused(t *testing.T) {
	e := newFakeEdge(t)
	ta := e.addToken("acct_a")
	e.addToken("acct_b")
	// A broken or compromised edge answers token A with account B's CA.
	e.caFor = func(string) string { return "acct_b" }
	_, addr := startGateway(t, e, nil)
	for _, pool := range []*x509.CertPool{e.ca("acct_a").pool, e.ca("acct_b").pool} {
		if body, err := get(t, client(addr, ta, pool), "https://api.openai.com/v1/models"); err == nil {
			t.Fatalf("decrypted with another account's CA: %s", body)
		}
	}
	resp, _, _ := connectRaw(t, addr, "api.openai.com:443", basic(ta))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("CONNECT = %s, want 502", resp.Status)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.seen) != 0 {
		t.Fatal("a request reached the edge")
	}
}

func TestTokenRequiredOnTunnels(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	for name, auth := range map[string]string{
		"none":         "",
		"unknown":      basic("sk-stub-" + strings.Repeat("0", 36)),
		"not a token":  basic("hunter2"),
		"wrong scheme": "Digest " + tok,
	} {
		for _, target := range []string{"example.com:443", "api.openai.com:443"} {
			resp, _, _ := connectRaw(t, addr, target, auth)
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("%s, %s: %s, want 407", name, target, resp.Status)
			}
			if resp.Header.Get("Proxy-Authenticate") == "" {
				t.Fatalf("%s: no Proxy-Authenticate", name)
			}
		}
	}
	// Revoked before its first connection.
	e.revoke(tok)
	resp, _, _ := connectRaw(t, addr, "example.com:443", basic(tok))
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("revoked: %s", resp.Status)
	}
	// Bearer works as well as Basic.
	tok2 := e.addToken("acct_a")
	resp, _, _ = connectRaw(t, addr, "10.0.0.1:443", "Bearer "+tok2)
	if resp.StatusCode != http.StatusForbidden { // past the token check, stopped by the address
		t.Fatalf("Bearer: %s", resp.Status)
	}
}

func TestRefusalIsRemembered(t *testing.T) {
	e := newFakeEdge(t)
	_, addr := startGateway(t, e, nil)
	bad := basic("sk-stub-" + strings.Repeat("1", 36))
	for i := 0; i < 5; i++ {
		resp, _, _ := connectRaw(t, addr, "example.com:443", bad)
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatal(resp.Status)
		}
	}
	if n := e.checks.Load(); n != 1 {
		t.Fatalf("checks = %d, want 1", n)
	}
}

func TestBlocksPrivateAddresses(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	for _, target := range []string{
		"127.0.0.1:443", "localhost:443", "[::1]:443", "10.1.2.3:443", "192.168.0.1:443",
		"169.254.169.254:443", "100.100.100.200:443", "[fdaa::3]:443", "[64:ff9b::a00:1]:443", "0.0.0.0:443",
		addr[:strings.LastIndex(addr, ":")] + ":443", // the gateway's own host
	} {
		resp, _, _ := connectRaw(t, addr, target, basic(tok))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %s, want 403", target, resp.Status)
		}
	}
}

func TestOnlyPort443(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	for _, target := range []string{"example.com:25", "example.com:22", "example.com:80", "api.openai.com:8443"} {
		resp, _, _ := connectRaw(t, addr, target, basic(tok))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %s, want 403", target, resp.Status)
		}
		// Without a token the answer is 407 whatever the port: nothing to
		// probe without one.
		resp, _, _ = connectRaw(t, addr, target, "")
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("%s without a token: %s", target, resp.Status)
		}
	}
}

func TestPlainHTTPRefused(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	body, err := get(t, client(addr, tok, nil), "http://example.com/")
	if err == nil || !strings.Contains(err.Error(), "405") {
		t.Fatalf("plain HTTP: %v %q", err, body)
	}
}

// tunnelTarget is a TCP echo server, and a dial hook that sends every
// tunnel there and records what the gateway meant to dial.
func tunnelTarget(t *testing.T) (dial func(string, string) (net.Conn, error), dialled func() []string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	var mu sync.Mutex
	var targets []string
	return func(network, a string) (net.Conn, error) {
			mu.Lock()
			targets = append(targets, a)
			mu.Unlock()
			return net.Dial(network, l.Addr().String())
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), targets...)
		}
}

func TestOtherHostsAreTunnelledUntouched(t *testing.T) {
	e := newFakeEdge(t)
	// The edge lists a host the built-in catalog doesn't give openai:
	// tunnelled, never decrypted.
	e.hosts["openai"] = []string{"api.openai.com", "evil.example.com"}
	tok := e.addToken("acct_a")
	dial, dialled := tunnelTarget(t)
	_, addr := startGateway(t, e, func(g *Gateway) { g.blockPrivate, g.dial = false, dial })
	for _, host := range []string{"example.com", "evil.example.com"} {
		resp, c, br := connectRaw(t, addr, host+":443", basic(tok))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %s", host, resp.Status)
		}
		if _, err := io.WriteString(c, "ping\n"); err != nil {
			t.Fatal(err)
		}
		line, err := br.ReadString('\n')
		if err != nil || line != "ping\n" {
			t.Fatalf("%s: echo = %q, %v", host, line, err)
		}
	}
	if got := dialled(); len(got) != 2 || got[0] != "example.com:443" || got[1] != "evil.example.com:443" {
		t.Fatalf("dialled %v", got)
	}
}

func TestRevokedTokenTunnelsClose(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	other := e.addToken("acct_a")
	dial, _ := tunnelTarget(t)
	u, _ := url.Parse(e.srv.URL)
	g, err := New(Config{Edge: u, Key: gatewayKey, Transport: e.srv.Client().Transport, CheckTTL: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	g.blockPrivate, g.dial = false, dial
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = g.Serve(l, nil) }()
	defer g.Shutdown(context.Background())
	addr := l.Addr().String()

	open := func(tk string) (net.Conn, *bufio.Reader) {
		resp, c, br := connectRaw(t, addr, "example.com:443", basic(tk))
		if resp.StatusCode != http.StatusOK {
			t.Fatal(resp.Status)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		return c, br
	}
	c1, br1 := open(tok)
	c2, br2 := open(other)
	e.revoke(tok)
	// The revoked token's tunnel is closed by the gateway...
	if _, err := br1.ReadString('\n'); err == nil {
		t.Fatal("the revoked token's tunnel is still open")
	}
	// ...the other token's still works.
	_, _ = io.WriteString(c2, "still\n")
	if line, err := br2.ReadString('\n'); err != nil || line != "still\n" {
		t.Fatalf("other tunnel: %q %v", line, err)
	}
	_ = c1
}

func TestEdgeDownIsNotRemembered(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	e.mu.Lock()
	e.fail = true
	e.mu.Unlock()
	resp, _, _ := connectRaw(t, addr, "api.openai.com:443", basic(tok))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("edge down: %s", resp.Status)
	}
	e.mu.Lock()
	e.fail = false
	e.mu.Unlock()
	if _, err := get(t, client(addr, tok, e.ca("acct_a").pool), "https://api.openai.com/v1/models"); err != nil {
		t.Fatalf("after the edge is back: %v", err)
	}
}

func TestWrongGatewayCredentialIsNotTheBoxsFault(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	u, _ := url.Parse(e.srv.URL)
	g, err := New(Config{Edge: u, Key: strings.Repeat("x", 40), Transport: e.srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	req.Header.Set("Proxy-Authorization", basic(tok))
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", rec.Code)
	}
}

func TestHTTPSProxy(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	u, _ := url.Parse(e.srv.URL)
	g, err := New(Config{Edge: u, Key: gatewayKey, Transport: e.srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	// The gateway's own certificate, as a load balancer or --tls-cert would give it.
	front := newTestCA(t, "front")
	frontCA, err := ca.Parse([]byte(front.certPEM), pemKey(t, front.keyB64))
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		_ = g.Serve(l, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return frontCA.Leaf("127.0.0.1") }})
	}()
	defer g.Shutdown(context.Background())

	roots := e.ca("acct_a").pool.Clone()
	roots.AddCert(front.cert)
	pu := &url.URL{Scheme: "https", Host: l.Addr().String(), User: url.UserPassword("keystub", tok)}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	if body, err := get(t, c, "https://api.openai.com/v1/models"); err != nil {
		t.Fatal(err, body)
	}
}

func pemKey(t *testing.T, b64 string) []byte {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestWorkerCA checks that an account CA as the hosted edge makes it (its
// own DER writer on WebCrypto, written to testdata; trusted by nothing)
// signs leaves Go clients accept.
func TestWorkerCA(t *testing.T) {
	certPEM, err := os.ReadFile("testdata/worker-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("testdata/worker-ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Parse(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := c.Leaf("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.openai.com", Roots: c.Pool()}); err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.AuthorityKeyId) == 0 {
		t.Fatal("no authority key identifier on the leaf (Python 3.13 refuses it)")
	}
}

func TestNewChecksConfig(t *testing.T) {
	good, _ := url.Parse("https://edge.example.com")
	if _, err := New(Config{Edge: good, Key: "short"}); err == nil {
		t.Fatal("a short credential was accepted")
	}
	for _, s := range []string{"http://edge.example.com", "https://user@edge.example.com", "ftp://x"} {
		u, _ := url.Parse(s)
		if _, err := New(Config{Edge: u, Key: gatewayKey}); err == nil {
			t.Fatalf("edge %s was accepted", s)
		}
	}
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	Health().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != 200 || rec.Body.String() != "ok\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestRefusalsCloseTheConnection(t *testing.T) {
	e := newFakeEdge(t)
	_, addr := startGateway(t, e, nil)
	for _, auth := range []string{"", basic("sk-stub-" + strings.Repeat("2", 36))} {
		resp, c, br := connectRaw(t, addr, "example.com:443", auth)
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatal(resp.Status)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := br.ReadByte(); err != io.EOF {
			t.Fatalf("the connection stayed open after a refusal: %v", err)
		}
	}
}

func TestPlainRequestsDontKeepTheConnection(t *testing.T) {
	e := newFakeEdge(t)
	_, addr := startGateway(t, e, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("%v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("the connection stayed open after a refusal: %v", err)
	}
}

func TestBadConnectHostsAreRefused(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	_, addr := startGateway(t, e, nil)
	for _, target := range []string{"api.openai.com%2f:443", "x_y.example.com:443", "-a.example.com:443", strings.Repeat("a", 64) + ".com:443", "[fe80::1%25en0]:443"} {
		resp, _, _ := connectRaw(t, addr, target, basic(tok))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %s, want 400", target, resp.Status)
		}
	}
	// Without a token, the target isn't looked at: 407 whatever it is. (A
	// Host that isn't valid HTTP, such as one with %, net/http itself answers
	// 400 before the gateway sees the request.)
	for _, target := range []string{"x_y.example.com:443", "-a.example.com:443", "example.com:25", "nonsense"} {
		if resp, _, _ := connectRaw(t, addr, target, ""); resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("%s with no token: %s, want 407", target, resp.Status)
		}
	}
	for _, h := range []string{"api.openai.com", "API.OpenAI.com.", "10.0.0.1", "::1", "xn--bcher-kva.example"} {
		if !validHost(h) {
			t.Fatalf("%s refused", h)
		}
	}
}

func TestOnlyTheEdgesRefusalIsARefusal(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		e := newFakeEdge(t)
		tok := e.addToken("acct_a")
		e.bare = status
		g, addr := startGateway(t, e, nil)
		if resp, _, _ := connectRaw(t, addr, "example.com:443", basic(tok)); resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("a %d without the edge's code: %s, want 502", status, resp.Status)
		}
		// An open tunnel of the token stays open through a recheck.
		a, b := net.Pipe()
		defer b.Close()
		tc := &trackedConn{Conn: a, g: g}
		g.mu.Lock()
		g.open[tokenKey(tok)] = map[*trackedConn]string{tc: tok}
		g.mu.Unlock()
		g.recheckOnce()
		g.mu.Lock()
		closed := tc.closed
		_, remembered := g.refusals.peek(tokenKey(tok))
		g.mu.Unlock()
		if closed || remembered {
			t.Fatalf("a %d without the edge's code: closed %v, remembered %v", status, closed, remembered)
		}
	}
	// With the code, it is one.
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	e.status = http.StatusUnauthorized
	_, addr := startGateway(t, e, nil)
	if resp, _, _ := connectRaw(t, addr, "example.com:443", basic(tok)); resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("token_refused: %s, want 407", resp.Status)
	}
}

func TestRefusalsDontPushOutLiveSessions(t *testing.T) {
	e := newFakeEdge(t)
	live := e.addToken("acct_a")
	g, addr := startGateway(t, e, nil)
	g.sessions, g.refusals = newLRU[*session](4), newLRU[*session](4)
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(live)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("live token: %s", resp.Status)
	}
	for i := 0; i < 20; i++ {
		madeUp := fmt.Sprintf("sk-stub-%036x", i)
		if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(madeUp)); resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("made-up token: %s", resp.Status)
		}
	}
	g.mu.Lock()
	_, ok := g.sessions.peek(tokenKey(live))
	g.mu.Unlock()
	if !ok {
		t.Fatal("a flood of refused tokens pushed out a live session")
	}
}

func TestChecksInFlightDontPushOutLiveSessions(t *testing.T) {
	e := newFakeEdge(t)
	a, b := e.addToken("acct_a"), e.addToken("acct_b")
	g, addr := startGateway(t, e, nil)
	g.sessions = newLRU[*session](2) // full with the two live tokens
	for _, tok := range []string{a, b} {
		if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(tok)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("live token: %s", resp.Status)
		}
	}
	for i := 0; i < 5; i++ {
		if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(fmt.Sprintf("sk-stub-%036x", i))); resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("made-up token: %s", resp.Status)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, tok := range []string{a, b} {
		if _, ok := g.sessions.peek(tokenKey(tok)); !ok {
			t.Fatal("a made-up token's check pushed out a live session")
		}
	}
}

func TestEdgeErrorKeepsAStaleSession(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	g, addr := startGateway(t, e, nil)
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(tok)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("live token: %s", resp.Status)
	}
	g.mu.Lock()
	s, _ := g.sessions.peek(tokenKey(tok))
	s.until = time.Time{}
	g.mu.Unlock()
	e.mu.Lock()
	e.fail = true
	e.mu.Unlock()
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(tok)); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("edge down: %s, want 502", resp.Status)
	}
	g.mu.Lock()
	_, ok := g.sessions.peek(tokenKey(tok))
	g.mu.Unlock()
	if !ok {
		t.Fatal("an edge error dropped the token's stale session, so it would check again as a new token")
	}
}

func TestOpenConnectionsMakeATokenKnown(t *testing.T) {
	e := newFakeEdge(t)
	e.delay = 300 * time.Millisecond
	tok := e.addToken("acct_a")
	g, _ := startGateway(t, e, func(g *Gateway) { g.cfg.MaxChecks = 1 })
	// The token's session is gone (evicted), but it has a tunnel open; the
	// only slot for new tokens is taken.
	a, b := net.Pipe()
	defer b.Close()
	g.mu.Lock()
	g.open[tokenKey(tok)] = map[*trackedConn]string{{Conn: a, g: g}: tok}
	g.checking = 1
	g.mu.Unlock()
	if _, err := g.session(context.Background(), tok); err != nil {
		t.Fatalf("a token with open connections: %v, want checked in its own slots", err)
	}
}

func TestLiveTokensCheckAgainDuringAFlood(t *testing.T) {
	e := newFakeEdge(t)
	live := e.addToken("acct_a")
	g, addr := startGateway(t, e, func(g *Gateway) { g.cfg.MaxChecks = 1 })
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(live)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("live token: %s", resp.Status)
	}
	// The live session goes stale, and a made-up token's check holds the
	// only slot for new tokens.
	g.mu.Lock()
	s, _ := g.sessions.peek(tokenKey(live))
	s.until = time.Time{}
	g.mu.Unlock()
	e.mu.Lock()
	e.delay = 500 * time.Millisecond
	e.mu.Unlock()
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\nProxy-Authorization: "+basic("sk-stub-"+strings.Repeat("0", 36))+"\r\n\r\n")
		_, _ = http.ReadResponse(bufio.NewReader(c), nil)
	}()
	time.Sleep(100 * time.Millisecond)
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic("sk-stub-"+strings.Repeat("1", 36))); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second new token: %s, want 503", resp.Status)
	}
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(live)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the live token, checked again: %s, want 403 (past the check)", resp.Status)
	}
}

func TestSweepDropsOldCAsAndSessions(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	g, addr := startGateway(t, e, nil)
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(tok)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("live token: %s", resp.Status)
	}
	if resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic("sk-stub-"+strings.Repeat("2", 36))); resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("made-up token: %s", resp.Status)
	}
	count := func() (int, int, int) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.cas.order.Len(), g.sessions.order.Len(), g.refusals.order.Len()
	}
	g.sweep()
	if c, s, r := count(); c != 1 || s != 1 || r != 1 {
		t.Fatalf("swept too early: %d CAs, %d sessions, %d refusals", c, s, r)
	}
	later := time.Now().Add(caTTL + time.Minute)
	g.now = func() time.Time { return later }
	g.recheckOnce() // the recheck ticker sweeps
	if c, s, r := count(); c != 0 || s != 0 || r != 0 {
		t.Fatalf("left after an hour: %d CAs, %d sessions, %d refusals", c, s, r)
	}
}

func TestTooManyChecksInFlight(t *testing.T) {
	e := newFakeEdge(t)
	e.delay = 500 * time.Millisecond
	t1, t2 := e.addToken("acct_a"), e.addToken("acct_a")
	_, addr := startGateway(t, e, func(g *Gateway) { g.cfg.MaxChecks = 1 })
	done := make(chan int, 1)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			done <- 0
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\nProxy-Authorization: "+basic(t1)+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			done <- 0
			return
		}
		done <- resp.StatusCode
	}()
	time.Sleep(100 * time.Millisecond) // t1's check is waiting on the edge
	resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(t2))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second check: %s, want 503", resp.Status)
	}
	if got := <-done; got != http.StatusForbidden {
		t.Fatalf("first: %d, want 403 (checked, then a private address)", got)
	}
}

func TestCARefusedForAnotherTokenIsNotShared(t *testing.T) {
	e := newFakeEdge(t)
	x, y := e.addToken("acct_a"), e.addToken("acct_a")
	release := make(chan struct{})
	var once sync.Once
	e.caHook = func(tok string) {
		if tok == x {
			once.Do(func() {
				<-release
				e.revoke(x) // revoked between its check and its CA fetch
			})
		}
	}
	_, addr := startGateway(t, e, nil)
	xDone := make(chan int, 1)
	go func() {
		c, _ := net.Dial("tcp", addr)
		defer c.Close()
		_, _ = io.WriteString(c, "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\nProxy-Authorization: "+basic(x)+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			xDone <- 0
			return
		}
		xDone <- resp.StatusCode
	}()
	time.Sleep(100 * time.Millisecond) // x's CA fetch is in flight
	yDone := make(chan *http.Response, 1)
	go func() {
		resp, _, _ := connectRaw(t, addr, "10.0.0.1:443", basic(y))
		yDone <- resp
	}()
	time.Sleep(100 * time.Millisecond) // y waits on x's fetch
	close(release)
	if got := <-xDone; got != http.StatusProxyAuthRequired {
		t.Fatalf("x: %d, want 407", got)
	}
	if resp := <-yDone; resp.StatusCode != http.StatusForbidden {
		t.Fatalf("y: %s, want 403 (its own token is live)", resp.Status)
	}
}

func TestCAIsFetchedAgainAfterAnHour(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	var mu sync.Mutex
	now := time.Now()
	g, addr := startGateway(t, e, func(g *Gateway) {
		g.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	_ = g
	c := client(addr, tok, e.ca("acct_a").pool)
	if _, err := get(t, c, "https://api.openai.com/v1/models"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(caTTL + time.Minute)
	mu.Unlock()
	if _, err := get(t, c, "https://api.openai.com/v1/models"); err != nil {
		t.Fatal(err)
	}
	if n := e.caCalls.Load(); n != 2 {
		t.Fatalf("CA fetches = %d, want 2", n)
	}
}

func TestExpiredCAIsRefused(t *testing.T) {
	e := newFakeEdge(t)
	tok := e.addToken("acct_a")
	e.expired = true
	_, addr := startGateway(t, e, nil)
	resp, _, _ := connectRaw(t, addr, "api.openai.com:443", basic(tok))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expired CA: %s, want 502", resp.Status)
	}
}

func TestRecheckRunsInParallel(t *testing.T) {
	e := newFakeEdge(t)
	e.delay = 100 * time.Millisecond
	g, _ := startGateway(t, e, nil)
	g.mu.Lock()
	for i := 0; i < 32; i++ {
		tok := e.addToken("acct_a")
		a, _ := net.Pipe()
		g.open[tokenKey(tok)] = map[*trackedConn]string{{Conn: a, g: g}: tok}
	}
	g.mu.Unlock()
	start := time.Now()
	g.recheckOnce()
	// 32 checks of 100ms one at a time would take 3.2s.
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("recheck took %v", d)
	}
}

func TestRecheckPassIsShortForManyTokens(t *testing.T) {
	e := newFakeEdge(t)
	e.delay = 100 * time.Millisecond
	g, _ := startGateway(t, e, nil)
	g.mu.Lock()
	for i := 0; i < 512; i++ {
		tok := e.addToken("acct_a")
		a, _ := net.Pipe()
		g.open[tokenKey(tok)] = map[*trackedConn]string{{Conn: a, g: g}: tok}
	}
	g.mu.Unlock()
	start := time.Now()
	g.recheckOnce()
	// 512 checks of 100ms, 16 at a time, take 3.2s; at 64, 0.8s.
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a recheck pass over 512 tokens took %v", d)
	}
}
