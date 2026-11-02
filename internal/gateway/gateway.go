// Package gateway is Keystub's hosted remote proxy: the agent's forwarding
// mode run as one server for many accounts, for CI and sandboxes where
// nothing can be installed. A box sets only
//
//	HTTPS_PROXY=https://keystub:<token>@proxy.keystub.app
//
// and trusts one CA file, its account's. For every connection the gateway
//
//   - requires a live proxy token in Proxy-Authorization, tunnels included,
//     checked with the edge (POST /gateway/check, counted nowhere);
//   - tunnels only to port 443 (by default) and never to private,
//     loopback, link-local, carrier-grade NAT or NAT64 addresses;
//   - decrypts only the catalog hosts of the services the token may use,
//     with leaf certificates from the token's own account's CA (POST
//     /gateway/ca, kept in memory only);
//   - sends each decrypted request to the edge's /h route with the token in
//     Keystub-Token, so the edge checks it, counts limits and swaps the key.
//
// It holds no real keys and no counters: limits stay in the edge's Durable
// Objects, shared with every other route. Every other host is tunnelled
// untouched.
//
// Account isolation: the edge answers both routes for the presented token's
// account only, and the gateway files a CA under the account the token
// check named, refusing a CA answer for any other. A token's connection is
// decrypted only with its own account's CA, so one account's CA never
// signs for another account's traffic.
package gateway

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/agent"
	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/proxy"
)

// KeyHeader carries the gateway's own credential to the edge's /gateway
// routes. It is never sent anywhere else.
const KeyHeader = "Keystub-Gateway-Key"

// Config is what a gateway runs with.
type Config struct {
	// Edge is the hosted edge: https, with /gateway/… and /h/… on it.
	Edge *url.URL
	// Key is the gateway's credential for the edge's /gateway routes (the
	// edge's GATEWAY_KEY secret).
	Key string
	// Transport reaches the edge; proxy.EdgeTransport() if nil. Checks, CA
	// fetches and every forwarded request share it.
	Transport http.RoundTripper
	// CheckTTL is how long a token check is trusted before the edge is
	// asked again, and how often open connections' tokens are checked
	// again; default 30 seconds. A revoked token's open tunnels close
	// within two of these plus one recheck pass (a check trusted just
	// before a pass is trusted through it): about a minute.
	CheckTTL time.Duration
	// TunnelPorts are the ports a CONNECT may name; default 443 only, so
	// the gateway isn't a relay for mail or anything else.
	TunnelPorts []string
	// MaxTokens and MaxAccounts bound what is kept in memory: live token
	// checks, refused tokens (kept apart, so a flood of made-up tokens
	// can't push out live ones) and account CAs, least recently used
	// dropped first. Default 10,000.
	MaxTokens, MaxAccounts int
	// MaxChecks bounds checks of new tokens waiting on the edge at once, so
	// a flood of made-up tokens can't pile up; past it a connection gets
	// 503. Checking again a token that was live has as many slots of its
	// own, which no flood of new ones can take. Default 256.
	MaxChecks int
	// ErrorLog gets the gateway's own errors, never a token or header.
	ErrorLog *log.Logger
}

// refusedTTL is how long a refused token is remembered, so a client
// retrying with a bad token doesn't reach the edge every time.
const refusedTTL = 5 * time.Second

// caTTL is how long an account's CA is kept before it is fetched again,
// so a CA the edge replaces stops being used within the hour.
const caTTL = time.Hour

// recheckers is how many tokens are checked again at once. A machine holds
// at most a few thousand connections (its load balancer's limit), so a pass over all
// their tokens takes a few seconds at the edge's usual latency, well inside
// CheckTTL.
const recheckers = 64

// errBusy is too many token checks waiting on the edge.
var errBusy = errors.New("too many token checks in flight")

// Gateway is an http.Handler for the proxy listener.
type Gateway struct {
	cfg       Config
	transport http.RoundTripper

	// blockPrivate is always true outside tests, which tunnel to loopback.
	blockPrivate bool
	dial         func(network, addr string) (net.Conn, error)
	now          func() time.Time

	mu         sync.Mutex
	checking   int                                // checks of new tokens in flight
	refreshing int                                // checks of tokens that were live, in flight
	sessions   *lru[*session]                     // by token hash: live (checked, maybe stale)
	refusals   *lru[*session]                     // by token hash: refused, for refusedTTL
	pending    map[string]*session                // by token hash: checks in flight
	cas        *lru[*caEntry]                     // by account ID
	open       map[string]map[*trackedConn]string // token hash → open connections → token
	srv        *http.Server
	stop       chan struct{}
	stopOnce   sync.Once
}

// New checks cfg and returns a gateway.
func New(cfg Config) (*Gateway, error) {
	if err := agent.CheckRemote(cfg.Edge); err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(cfg.Key)) < 32 {
		return nil, errors.New("the gateway's credential for the edge must be at least 32 characters (the edge's GATEWAY_KEY)")
	}
	if cfg.Transport == nil {
		cfg.Transport = proxy.EdgeTransport()
	}
	if cfg.CheckTTL <= 0 {
		cfg.CheckTTL = 30 * time.Second
	}
	if len(cfg.TunnelPorts) == 0 {
		cfg.TunnelPorts = []string{"443"}
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 10_000
	}
	if cfg.MaxAccounts <= 0 {
		cfg.MaxAccounts = 10_000
	}
	if cfg.MaxChecks <= 0 {
		cfg.MaxChecks = 256
	}
	if cfg.ErrorLog == nil {
		cfg.ErrorLog = log.New(io.Discard, "", 0)
	}
	return &Gateway{
		cfg: cfg, transport: cfg.Transport, blockPrivate: true, now: time.Now,
		dial:     (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).Dial,
		sessions: newLRU[*session](cfg.MaxTokens), refusals: newLRU[*session](cfg.MaxTokens),
		cas:     newLRU[*caEntry](cfg.MaxAccounts),
		pending: map[string]*session{}, open: map[string]map[*trackedConn]string{}, stop: make(chan struct{}),
	}, nil
}

// session is one token's check and the proxy that serves its connections.
type session struct {
	ready   chan struct{} // closed once the fields below are set
	err     error
	account string
	proxy   *proxy.Proxy
	until   time.Time // trusted until then
}

type caEntry struct {
	ready   chan struct{}
	err     error
	ca      *ca.CA
	fetched time.Time
}

// refused is the edge turning the token down: the client gets 407.
type refused struct{ msg string }

func (e *refused) Error() string { return e.msg }

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// Plain-HTTP proxying would carry tokens and requests in the clear
		// past this hop, and nothing is decrypted for it anyway.
		fail(w, http.StatusMethodNotAllowed, "keystub: this gateway only tunnels https; set HTTPS_PROXY to it, not HTTP_PROXY")
		return
	}
	// The token first, whatever the target, so nothing about targets can be
	// probed without one.
	token := proxy.ProxyAuthToken(r.Header.Get("Proxy-Authorization"))
	if token == "" {
		g.authRequired(w, "keystub: this proxy needs a proxy token: HTTPS_PROXY=https://keystub:<token>@<host>")
		return
	}
	s, err := g.session(r.Context(), token)
	var no *refused
	switch {
	case errors.As(err, &no):
		g.authRequired(w, "keystub: "+no.msg)
		return
	case errors.Is(err, errBusy):
		fail(w, http.StatusServiceUnavailable, "keystub: the gateway is busy; try again")
		return
	case err != nil:
		g.cfg.ErrorLog.Printf("keystub gateway: %v", err)
		fail(w, http.StatusBadGateway, "keystub: couldn't check the proxy token with the edge; try again")
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || !validHost(host) {
		// Only a host name or an IP address is matched against the catalog,
		// signed into a certificate or put in an edge path.
		fail(w, http.StatusBadRequest, "keystub: bad CONNECT target")
		return
	}
	if !slices.Contains(g.cfg.TunnelPorts, port) {
		fail(w, http.StatusForbidden, "keystub: this gateway only connects to port "+strings.Join(g.cfg.TunnelPorts, ", "))
		return
	}
	g.track(r.Context(), tokenKey(token), token)
	s.proxy.ServeHTTP(w, r)
}

func (g *Gateway) authRequired(w http.ResponseWriter, msg string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="keystub"`)
	fail(w, http.StatusProxyAuthRequired, msg)
}

// fail answers a refused connection and closes it, so a client can't hold
// it open with nothing more to say.
func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Connection", "close")
	http.Error(w, msg, status)
}

// validHost is an IP address or a DNS name: letters, digits and dashes in
// labels of at most 63, at most 253 in all.
func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// session returns token's checked session, asking the edge when there is
// none or it is stale. Concurrent callers for one token share one check.
//
// Only live sessions are in g.sessions: a check in flight is in g.pending
// (as many as there are slots), and a refusal in g.refusals. So made-up
// tokens can't push live sessions out, and a token that was live (its
// session is still there, stale, or it has connections open) checks again
// in slots of its own.
func (g *Gateway) session(ctx context.Context, token string) (*session, error) {
	key := tokenKey(token)
	g.mu.Lock()
	s, ok := g.pending[key]
	if !ok {
		if live, found := g.sessions.get(key); found && g.now().Before(live.until) {
			g.mu.Unlock()
			return live, nil
		}
		if r, found := g.refusals.get(key); found {
			if g.now().Before(r.until) {
				g.mu.Unlock()
				return r, r.err
			}
			g.refusals.remove(key)
		}
		_, stale := g.sessions.peek(key)
		count := &g.checking
		if stale || len(g.open[key]) > 0 {
			count = &g.refreshing
		}
		if *count >= g.cfg.MaxChecks {
			g.mu.Unlock()
			return nil, errBusy
		}
		*count++
		s = &session{ready: make(chan struct{})}
		g.pending[key] = s
		// The check outlives this request: other callers wait on it.
		go g.check(s, key, token, count)
	}
	g.mu.Unlock()
	select {
	case <-s.ready:
		return s, s.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// check asks the edge about token, fills s, and files it: a live session in
// g.sessions, a refusal in g.refusals. An edge error is filed nowhere, so
// the next connection asks again, and a stale session it would have
// replaced stays, so the token still checks again in its own slots.
func (g *Gateway) check(s *session, key, token string, count *int) {
	defer close(s.ready)
	defer func() {
		g.mu.Lock()
		*count--
		if g.pending[key] == s {
			delete(g.pending, key)
		}
		switch {
		case s.proxy != nil:
			g.sessions.put(key, s)
		case s.until != (time.Time{}): // refused
			g.sessions.remove(key)
			g.refusals.put(key, s)
		}
		g.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	account, cat, expires, err := g.checkToken(ctx, token)
	var authority *ca.CA
	if err == nil {
		authority, err = g.accountCA(ctx, account, token)
	}
	var no *refused
	if errors.As(err, &no) {
		s.err, s.until = err, g.now().Add(refusedTTL)
		return
	}
	if err != nil {
		s.err = err
		return
	}
	hosts := agent.NewHosts()
	hosts.Set(cat)
	p := proxy.NewAgent(hosts, g.cfg.Edge, authority, nil)
	p.Upstream = g.transport
	p.BlockPrivate = g.blockPrivate
	p.Dial = g.dial
	s.account, s.proxy = account, p
	s.until = g.now().Add(g.cfg.CheckTTL)
	if expires != nil && expires.Before(s.until) {
		s.until = *expires
	}
}

// checkResponse is POST /gateway/check: the catalog an agent reads from
// GET /catalog, plus the token's account.
type checkResponse struct {
	AccountID string `json:"accountId"`
	proxy.CatalogResponse
}

type caResponse struct {
	AccountID   string `json:"accountId"`
	Certificate string `json:"certificate"`
	Key         []byte `json:"key"` // PKCS #8, base64 in JSON; wiped after use
}

func (g *Gateway) checkToken(ctx context.Context, token string) (string, proxy.CatalogResponse, *time.Time, error) {
	var out checkResponse
	if err := g.call(ctx, "/gateway/check", token, &out); err != nil {
		return "", proxy.CatalogResponse{}, nil, err
	}
	if !validAccount(out.AccountID) {
		return "", proxy.CatalogResponse{}, nil, errors.New("the edge's token check named no account")
	}
	return out.AccountID, out.CatalogResponse, out.Token.ExpiresAt, nil
}

// accountCA returns the account's CA, fetching it with token (a live token
// of that account) if it isn't in memory. The edge picks the CA by the
// token's account; an answer for any other account is refused, so a CA is
// only ever filed under its own account.
func (g *Gateway) accountCA(ctx context.Context, account, token string) (*ca.CA, error) {
	// A fetch another token of the account started, and the edge refused
	// that token (revoked in between), says nothing about this one: ask
	// again with this token. A few times at most.
	for range 3 {
		c, err, theirs := g.accountCAOnce(ctx, account, token)
		var no *refused
		if theirs && errors.As(err, &no) {
			continue
		}
		return c, err
	}
	return nil, errors.New("couldn't fetch the account's CA")
}

// accountCAOnce returns the account's CA, fetched with token if no fetch is
// cached or in flight; theirs is whether the answer came from another
// token's fetch.
func (g *Gateway) accountCAOnce(ctx context.Context, account, token string) (*ca.CA, error, bool) {
	g.mu.Lock()
	e, ok := g.cas.get(account)
	if ok {
		select {
		case <-e.ready:
			if e.err == nil && g.now().Sub(e.fetched) >= caTTL {
				ok = false // fetch it again
			}
		default:
		}
	}
	if !ok {
		e = &caEntry{ready: make(chan struct{})}
		g.cas.put(account, e)
	}
	g.mu.Unlock()
	if ok {
		<-e.ready
		return e.ca, e.err, true // a failed fetch is dropped, so the next asks again
	}
	defer close(e.ready)
	e.ca, e.err = g.fetchCA(ctx, account, token)
	e.fetched = g.now()
	if e.err != nil {
		g.mu.Lock()
		if cur, ok := g.cas.peek(account); ok && cur == e {
			g.cas.remove(account)
		}
		g.mu.Unlock()
	}
	return e.ca, e.err, false
}

func (g *Gateway) fetchCA(ctx context.Context, account, token string) (*ca.CA, error) {
	var out caResponse
	if err := g.call(ctx, "/gateway/ca", token, &out); err != nil {
		return nil, err
	}
	if out.AccountID != account {
		return nil, fmt.Errorf("the edge sent a CA for another account than the token's")
	}
	der := out.Key
	defer clear(der)
	if len(der) == 0 {
		return nil, errors.New("the edge sent no CA key")
	}
	if cb, _ := pem.Decode([]byte(out.Certificate)); cb != nil {
		if cert, err := x509.ParseCertificate(cb.Bytes); err == nil {
			if now := g.now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return nil, errors.New("the edge's CA for an account isn't valid now")
			}
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	c, err := ca.Parse([]byte(out.Certificate), keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the edge's CA for an account isn't usable: %w", err)
	}
	return c, nil
}

// call POSTs to one of the edge's /gateway routes with the gateway's
// credential and the token, and reads the JSON answer into out. Only a 401
// with the edge's code token_refused is a refusal of the token: any other
// 401 or 403 (its credential refused, or something in front of the edge
// answering) is an edge problem, so it closes no tunnels and isn't
// remembered. The answer, which may hold a CA key, is wiped once read.
func (g *Gateway) call(ctx context.Context, route, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(g.cfg.Edge.String(), "/")+route, nil)
	if err != nil {
		return err
	}
	req.Header.Set(KeyHeader, g.cfg.Key)
	req.Header.Set(proxy.TokenHeader, token)
	resp, err := g.transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("POST %s: can't reach the edge", route)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	defer clear(body)
	if err != nil {
		return fmt.Errorf("POST %s: %w", route, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		var e struct {
			Error struct {
				Type    string `json:"type"`
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		switch {
		case e.Error.Type == "keystub" && e.Error.Code == "token_refused":
			msg := strings.TrimPrefix(e.Error.Message, "keystub: ")
			if msg == "" {
				msg = "this request has no valid proxy token"
			}
			return &refused{msg: printable(msg)}
		case e.Error.Type == "keystub" && e.Error.Code == "gateway_credential":
			// The gateway's own credential is wrong: not the box's fault.
			return fmt.Errorf("POST %s: the edge refused the gateway's credential", route)
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: %s", route, printable(resp.Status))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("POST %s: the edge's answer isn't valid", route)
	}
	return nil
}

// validAccount is an account ID as the control plane makes them.
func validAccount(id string) bool {
	if id == "" || len(id) > 80 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// --- serving, and closing a revoked token's connections ---

// Serve accepts connections on l (TLS with tlsConfig, if not nil) until
// Shutdown. Every so often (CheckTTL) it checks again the tokens of open
// connections, and closes those of a token the edge now refuses, so a
// revoked token's tunnels don't outlive it.
func (g *Gateway) Serve(l net.Listener, tlsConfig *tls.Config) error {
	var ln net.Listener = &trackingListener{Listener: l, g: g}
	if tlsConfig != nil {
		ln = tls.NewListener(ln, tlsConfig)
	}
	g.mu.Lock()
	g.srv = &http.Server{
		Handler:           g,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       30 * time.Second,
		ConnContext:       connContext,
		ErrorLog:          g.cfg.ErrorLog,
	}
	srv := g.srv
	g.mu.Unlock()
	go g.recheck()
	return srv.Serve(ln)
}

// Shutdown stops accepting connections and closes the open ones.
func (g *Gateway) Shutdown(ctx context.Context) error {
	g.stopOnce.Do(func() { close(g.stop) })
	g.mu.Lock()
	srv := g.srv
	var conns []*trackedConn
	for _, m := range g.open {
		for c := range m {
			conns = append(conns, c)
		}
	}
	g.mu.Unlock()
	var err error
	if srv != nil {
		err = srv.Shutdown(ctx)
	}
	for _, c := range conns {
		c.Close() // hijacked tunnels aren't closed by Shutdown
	}
	return err
}

func (g *Gateway) recheck() {
	t := time.NewTicker(g.cfg.CheckTTL)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			g.recheckOnce()
		}
	}
}

// recheckOnce checks each open connection's token and closes the
// connections of one the edge now refuses. An edge that can't be reached
// closes nothing: decrypted requests still go through it, and it refuses
// them itself.
func (g *Gateway) recheckOnce() {
	g.sweep()
	g.mu.Lock()
	tokens := map[string]string{}
	for key, m := range g.open {
		for _, tok := range m {
			tokens[key] = tok
			break
		}
	}
	g.mu.Unlock()
	sem := make(chan struct{}, recheckers)
	var wg sync.WaitGroup
	for key, tok := range tokens {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			g.recheckToken(key, tok)
		}()
	}
	wg.Wait()
}

// sweep drops what is past use, so account CA keys don't stay in memory
// for accounts no box uses any more: CAs fetched over caTTL ago, sessions
// (each holding its account's CA) stale for caTTL, and expired refusals.
// Open connections' sessions are checked again before they get that stale.
func (g *Gateway) sweep() {
	now := g.now()
	done := func(ready chan struct{}) bool {
		select {
		case <-ready:
			return true
		default:
			return false
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cas.removeIf(func(e *caEntry) bool { return done(e.ready) && now.Sub(e.fetched) >= caTTL })
	g.sessions.removeIf(func(s *session) bool { return done(s.ready) && now.Sub(s.until) >= caTTL })
	g.refusals.removeIf(func(s *session) bool { return !now.Before(s.until) })
}

func (g *Gateway) recheckToken(key, tok string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	for {
		if _, err = g.session(ctx, tok); !errors.Is(err, errBusy) || ctx.Err() != nil {
			break
		}
		time.Sleep(50 * time.Millisecond) // new connections' checks first
	}
	var no *refused
	if !errors.As(err, &no) {
		return
	}
	g.mu.Lock()
	var conns []*trackedConn
	for c := range g.open[key] {
		conns = append(conns, c)
	}
	g.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

type connKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if tc, ok := c.(*trackedConn); ok {
		return context.WithValue(ctx, connKey{}, tc)
	}
	return ctx
}

// track files the request's connection under its token, so recheck can
// close it. A connection carries one CONNECT, so one token.
func (g *Gateway) track(ctx context.Context, key, token string) {
	c, ok := ctx.Value(connKey{}).(*trackedConn)
	if !ok {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if c.closed {
		return
	}
	if c.key != "" && c.key != key {
		delete(g.open[c.key], c)
		if len(g.open[c.key]) == 0 {
			delete(g.open, c.key)
		}
	}
	c.key = key
	if g.open[key] == nil {
		g.open[key] = map[*trackedConn]string{}
	}
	g.open[key][c] = token
}

type trackingListener struct {
	net.Listener
	g *Gateway
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedConn{Conn: c, g: l.g}, nil
}

// trackedConn is a client connection that leaves the gateway's list of
// open connections when it closes, hijacked (a tunnel) or not.
type trackedConn struct {
	net.Conn
	g      *Gateway
	key    string // guarded by g.mu
	closed bool   // guarded by g.mu
	once   sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.g.mu.Lock()
		c.closed = true
		if m := c.g.open[c.key]; m != nil {
			delete(m, c)
			if len(m) == 0 {
				delete(c.g.open, c.key)
			}
		}
		c.g.mu.Unlock()
	})
	return c.Conn.Close()
}

// CloseWrite lets a tunnel half-close, as the proxy does with a bare TCP
// connection.
func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// --- a small LRU, guarded by Gateway.mu ---

type lru[V any] struct {
	max   int
	order *list.List // front: most recently used
	items map[string]*list.Element
}

type lruItem[V any] struct {
	key string
	v   V
}

func newLRU[V any](max int) *lru[V] {
	return &lru[V]{max: max, order: list.New(), items: map[string]*list.Element{}}
}

func (l *lru[V]) get(k string) (V, bool) {
	e, ok := l.items[k]
	if !ok {
		var zero V
		return zero, false
	}
	l.order.MoveToFront(e)
	return e.Value.(*lruItem[V]).v, true
}

func (l *lru[V]) peek(k string) (V, bool) {
	e, ok := l.items[k]
	if !ok {
		var zero V
		return zero, false
	}
	return e.Value.(*lruItem[V]).v, true
}

func (l *lru[V]) put(k string, v V) {
	if e, ok := l.items[k]; ok {
		e.Value.(*lruItem[V]).v = v
		l.order.MoveToFront(e)
		return
	}
	l.items[k] = l.order.PushFront(&lruItem[V]{key: k, v: v})
	for l.order.Len() > l.max {
		last := l.order.Back()
		l.order.Remove(last)
		delete(l.items, last.Value.(*lruItem[V]).key)
	}
}

func (l *lru[V]) removeIf(drop func(V) bool) {
	for e := l.order.Front(); e != nil; {
		next := e.Next()
		if it := e.Value.(*lruItem[V]); drop(it.v) {
			l.order.Remove(e)
			delete(l.items, it.key)
		}
		e = next
	}
}

func (l *lru[V]) remove(k string) {
	if e, ok := l.items[k]; ok {
		l.order.Remove(e)
		delete(l.items, k)
	}
}

// Health answers 200 to anyone: for the platform's health checks, on a
// listener of its own.
func Health() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
}
