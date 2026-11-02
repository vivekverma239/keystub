// Package proxy is Keystub's HTTPS proxy. Callers point HTTPS_PROXY at it.
// For hosts that belong to a configured service it ends TLS with a
// certificate from the local CA, checks the caller's proxy token, swaps it
// for the real key in the auth headers, and forwards the
// request over a separate, verified TLS connection. Every other host is
// tunnelled untouched.
//
// As an agent (NewAgent) it holds no keys: each decrypted request goes, as
// it is, to an edge's /h/<host>/<path> route, and the edge checks the token
// and swaps the key.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/swap"
	"github.com/vivekverma239/keystub/internal/usage"
)

// Catalog says which hosts belong to a service, so the proxy knows what to
// decrypt. *core.Engine provides it; an agent's comes from an edge.
type Catalog interface {
	ServiceForHost(host string) (core.Service, bool)
}

// DataPlane is what the proxy and the edge need from the core to check
// tokens and swap keys themselves. *core.Engine provides it.
type DataPlane interface {
	Catalog
	Service(id string) (core.Service, bool)
	CheckToken(token string) error
	Authorize(ctx context.Context, token, serviceID string) (core.Grant, error)
	TokenServices(token string) (core.Token, []core.Service, error)
}

// Proxy is an http.Handler for the proxy listener. It is one ingress; a
// transparent (iptables or DNS) front end would drive the same intercept.
type Proxy struct {
	// Core checks tokens and swaps keys. It is nil for an agent with an Edge.
	Core DataPlane
	// Hosts says which hosts to decrypt; New sets it to Core.
	Hosts Catalog
	// Edge, when set, makes the proxy an agent that holds no keys: each
	// decrypted request goes to Edge's /h/<host>/<path> route unchanged,
	// with the proxy token in Keystub-Token if the request carries none.
	Edge *url.URL
	CA   *ca.CA
	Log  core.Sink // may be nil

	// Upstream sends intercepted requests on: to the service, or to Edge.
	// It must not use a proxy itself.
	Upstream http.RoundTripper
	// Dial opens tunnels for hosts that aren't intercepted.
	Dial func(network, addr string) (net.Conn, error)
	// RequireToken refuses any connection, tunnels and plain HTTP included,
	// whose Proxy-Authorization carries no live proxy token. Turn it on
	// whenever other machines can reach the proxy. It needs Core: an agent
	// with it set refuses everything.
	RequireToken bool
	// BlockPrivate refuses tunnels and plain HTTP to loopback, private and
	// link-local addresses, so a token holder can't reach the proxy host's
	// own network (its dashboard, a cloud metadata service). Catalog
	// services are not affected. Turn it on with RequireToken.
	BlockPrivate bool

	plainOnce   sync.Once
	plainPublic http.RoundTripper
}

// errPrivate is a refused dial to a non-public address.
var errPrivate = errors.New("keystub: this proxy doesn't connect to private addresses")

// publicOnly is a net.Dialer Control func: it runs on the address actually
// dialled, after DNS, so a name that resolves to a private address is
// caught too.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return errPrivate
	}
	if a, ok := netip.AddrFromSlice(ip); ok {
		a = a.Unmap()
		for _, p := range notPublic {
			if p.Contains(a) {
				return errPrivate
			}
		}
	}
	return nil
}

// notPublic are ranges the net.IP helpers don't count as private but that
// reach networks a token holder has no business on.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT: Tailscale nodes, Alibaba Cloud metadata
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking, often internal
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 to any IPv4, private ones included
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
}

func publicDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: publicOnly}
}

// New returns a proxy that swaps keys itself, with production transports.
func New(dp DataPlane, c *ca.CA, l core.Sink) *Proxy {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &Proxy{
		Core: dp, Hosts: dp, CA: c, Log: l,
		Upstream: &http.Transport{
			Proxy:               nil, // never loop back through HTTPS_PROXY
			DialContext:         dialer.DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableCompression:  true, // pass encoded bodies through as they are
		},
		Dial: dialer.Dial,
	}
}

// NewAgent returns a proxy that holds no keys: it decrypts hosts in hosts
// and forwards each request to edge's /h route.
func NewAgent(hosts Catalog, edge *url.URL, c *ca.CA, l core.Sink) *Proxy {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &Proxy{
		Hosts: hosts, Edge: edge, CA: c, Log: l,
		Upstream: EdgeTransport(),
		Dial:     dialer.Dial,
	}
}

// EdgeTransport keeps one long-lived HTTP/2 connection to an https edge,
// with pings so a dead one is noticed. Websocket requests get an HTTP/1.1
// connection of their own (the transport does that for "Upgrade:
// websocket"), and an http:// edge gets HTTP/1.1 keep-alive.
func EdgeTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:               nil, // never loop back through HTTPS_PROXY
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     0, // keep the connection for as long as the edge does
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.connect(w, r)
	case r.URL.IsAbs():
		p.plain(w, r)
	default:
		http.Error(w, "keystub: this is a proxy; point HTTPS_PROXY at it", http.StatusBadRequest)
	}
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "keystub: bad CONNECT target", http.StatusBadRequest)
		return
	}
	proxyToken := proxyAuthToken(r.Header.Get("Proxy-Authorization"))
	if !p.allowed(w, proxyToken) {
		return
	}
	svc, intercept := p.Hosts.ServiceForHost(host)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "keystub: can't take over the connection", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	client := &bufConn{Conn: conn, r: brw.Reader}

	if !intercept {
		p.tunnel(client, target)
		return
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.intercept(client, host, target, svc, proxyToken)
}

// allowed refuses the connection with 407 when a token is required and
// missing or not live.
func (p *Proxy) allowed(w http.ResponseWriter, proxyToken string) bool {
	if !p.RequireToken {
		return true
	}
	if p.Core == nil || p.Core.CheckToken(proxyToken) != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="keystub"`)
		http.Error(w, "keystub: this proxy needs a valid proxy token, e.g. HTTPS_PROXY=http://keystub:<token>@host:port", http.StatusProxyAuthRequired)
		return false
	}
	return true
}

// tunnel copies bytes both ways without looking at them.
func (p *Proxy) tunnel(client net.Conn, target string) {
	dial := p.Dial
	if p.BlockPrivate {
		dial = publicDialer().Dial
	}
	up, err := dial("tcp", target)
	if err != nil {
		status := "502 Bad Gateway"
		if errors.Is(err, errPrivate) {
			status = "403 Forbidden"
		}
		_, _ = io.WriteString(client, "HTTP/1.1 "+status+"\r\n\r\n")
		client.Close()
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		up.Close()
		return
	}
	pipe(client, client, up, up, halfCloseWait, func() { client.Close(); up.Close() })
	client.Close()
	up.Close()
}

func (p *Proxy) intercept(client net.Conn, host, target string, svc core.Service, proxyToken string) {
	tlsConn := tls.Server(client, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		// Always sign for the CONNECT host, whatever SNI says, so a client
		// can't get a certificate for a host it didn't ask the proxy for.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return p.CA.Leaf(host) },
	})
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	br := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Minute)) // idle keep-alive limit
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = tlsConn.SetDeadline(time.Time{})
		if !p.forward(tlsConn, br, req, host, target, svc, proxyToken) {
			return
		}
	}
}

var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer", "Upgrade"}

// forward sends one intercepted request upstream and writes the response.
// It reports whether the client connection can carry another request.
func (p *Proxy) forward(conn net.Conn, br *bufio.Reader, req *http.Request, host, target string, svc core.Service, proxyToken string) bool {
	ctx := context.Background()
	start := time.Now()
	entry := core.Entry{Time: start.UTC(), Service: svc.ID, Method: req.Method, Host: host, Path: req.URL.Path}
	var meter *usage.Meter // reads usage from the response, when the proxy swaps keys itself
	done := func(status int, note string) {
		entry.Status, entry.Note, entry.DurationMs = status, note, time.Since(start).Milliseconds()
		meter.Finish(&entry)
		if entry.Outcome == "" {
			entry.Outcome = usage.Outcome(svc.ID, status, note)
		}
		if p.Log != nil {
			p.Log.Add(entry)
		}
	}

	upgrade := isUpgrade(req.Header)
	for _, h := range hopHeaders {
		if upgrade && (h == "Connection" || h == "Upgrade") {
			continue
		}
		req.Header.Del(h)
	}
	if stray := swap.Stray(req.Header, svc.Header); len(stray) > 0 {
		msg := strayMessage(stray)
		writeError(conn, http.StatusBadRequest, "keystub: "+msg)
		done(http.StatusBadRequest, msg)
		return false
	}
	if p.Edge != nil {
		if status, msg := p.toEdge(req, host, target, svc, proxyToken); status != 0 {
			writeError(conn, status, "keystub: "+msg)
			done(status, msg)
			return false
		}
	} else {
		token := proxyToken
		if token == "" {
			token = swap.Find(req.Header, svc.Header)
		}
		g, err := p.Core.Authorize(ctx, token, svc.ID)
		if g.Token.ID != "" {
			entry.Project, entry.Env, entry.TokenID, entry.Key = g.Project.ID, g.Env.ID, g.Token.ID, g.Token.Name
			entry.Principal, entry.SavedKey = g.Token.Principal, g.SavedKey.ID
		}
		if err != nil {
			status, msg := refusal(err, svc, g.Env.ID)
			writeError(conn, status, "keystub: "+msg)
			done(status, msg)
			return false
		}
		req.URL.Scheme = "https"
		req.URL.Host = target
		// The Host header names the CONNECT host, never what the client
		// wrote: a shared CDN routes by Host, and the real key must only
		// reach the service.
		req.Host = host
		if !strings.HasSuffix(target, ":443") {
			req.Host = target
		}
		swap.Apply(req.Header, g.Key, svc.Header, svc.Format)
		meter = usage.Start(svc.ID, req.Method, req.URL.Path, start)
		usage.Narrow(svc.ID, req.Header)
	}
	body := &trackedBody{ReadCloser: req.Body}
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = meter.Request(body, req.Header)
	} else {
		body.eof = true
	}
	req.RequestURI = ""
	// Whether the client's connection ends after this request is the
	// client's business; passed on, it would make the transport give the
	// request a connection of its own and close it, losing the shared one.
	clientClose := req.Close
	req.Close = false

	// The client is waiting for permission to send its body; give it now
	// rather than making it sit out its own timeout.
	if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
		req.Header.Del("Expect")
		if _, err := io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			entry.Outcome = core.OutcomeCanceled
			done(0, "client went away")
			return false
		}
	}

	entry.OverheadMs = time.Since(start).Milliseconds()
	resp, err := p.Upstream.RoundTrip(req)
	if err != nil {
		if body.failed.Load() {
			// The client stopped sending its body; nobody is left to answer.
			entry.Outcome = core.OutcomeCanceled
			done(0, "client went away")
			return false
		}
		if p.Edge != nil {
			writeError(conn, http.StatusBadGateway, "keystub: couldn't reach the edge at "+p.Edge.Host)
			entry.Outcome = core.OutcomeUnreachable
			done(http.StatusBadGateway, "edge unreachable")
			return false
		}
		writeError(conn, http.StatusBadGateway, "keystub: couldn't reach "+host)
		entry.Outcome = core.OutcomeUnreachable
		done(http.StatusBadGateway, "upstream unreachable")
		return false
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		p.switchProtocols(conn, br, resp)
		done(resp.StatusCode, "")
		return false
	}
	defer resp.Body.Close()
	meter.Response(resp) // scans the body as resp.Write streams it
	note := ""
	if p.Edge != nil {
		// The edge answered itself: its outcome, not the status, says why.
		switch o := resp.Header.Get(OutcomeHeader); o {
		case core.OutcomeRefused, core.OutcomeUnreachable:
			entry.Outcome, note = o, "the edge answered: "+o
		}
	}

	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/1.1", 1, 1
	if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 && req.Method != http.MethodHead && bodyAllowed(resp.StatusCode) {
		resp.TransferEncoding = []string{"chunked"} // stream bodies of unknown length
	}
	resp.Close = clientClose
	err = resp.Write(conn) // writes as data arrives, so streams aren't buffered
	done(resp.StatusCode, note)
	return err == nil && !clientClose && body.eof
}

// toEdge points an intercepted request at the edge's /h route, unchanged
// otherwise. The edge then checks the token and swaps the key, so the agent
// needs none. It returns a status and message if the request can't go.
func (p *Proxy) toEdge(req *http.Request, host, target string, svc core.Service, proxyToken string) (int, string) {
	if !strings.HasSuffix(target, ":443") {
		// /h/<host> always means port 443.
		return http.StatusBadGateway, "the edge only reaches " + host + " on port 443"
	}
	if !strings.HasPrefix(req.URL.Path, "/") {
		return http.StatusBadRequest, "the edge needs a request path starting with /"
	}
	// With no proxy token anywhere the edge can only refuse, and the
	// request may carry the box's own credentials for the host: they stay
	// on the box.
	if proxyToken == "" && swap.Find(req.Header, svc.Header) == "" {
		return http.StatusUnauthorized, "this request has no valid proxy token"
	}
	// The edge writes the real key. A credential the app set itself would
	// go to the edge with the request, so it stays on the box.
	if name := realCredential(req.Header, svc.Header); name != "" {
		return http.StatusBadRequest, "a real credential is set for " + svc.Name + " in " + name + "; use the proxy token instead"
	}
	// Only the agent sets Keystub-Token. The edge prefers it to a token in
	// the auth headers, so a token in Proxy-Authorization decides, as it
	// does when the proxy swaps keys itself.
	req.Header.Del(TokenHeader)
	req.Header.Del(LegacyTokenHeader)
	if proxyToken != "" {
		req.Header.Set(TokenHeader, proxyToken)
	}
	u, err := url.Parse(strings.TrimSuffix(p.Edge.String(), "/") + "/h/" + host + req.URL.EscapedPath())
	if err != nil {
		return http.StatusBadRequest, "bad request path"
	}
	u.RawQuery = req.URL.RawQuery
	req.URL = u
	req.Host = "" // the edge's own host
	return 0, ""
}

// realCredential returns the auth header that holds a credential besides
// a proxy token, or "".
func realCredential(h http.Header, svcHeader string) string {
	names := slices.Clone(swap.AuthHeaders)
	if svcHeader != "" && !slices.Contains(names, http.CanonicalHeaderKey(svcHeader)) {
		names = append(names, http.CanonicalHeaderKey(svcHeader))
	}
	for _, name := range names {
		for _, v := range h.Values(name) {
			if ownCredential(v) {
				return name
			}
		}
	}
	return ""
}

// ownCredential reports whether an auth header value carries something
// besides a proxy token: a value with no token, a second one beside it
// ("Bearer sk-stub-… sk-real…"), or Basic auth whose secret isn't the
// token. A scheme alone ("Bearer") carries nothing, and a template around
// the token ("prod:app|sk-stub-…") is the token's own field.
func ownCredential(v string) bool {
	f := strings.Fields(v)
	if len(f) == 1 && bareScheme(f[0]) || len(f) > 1 && swap.In(f[0]) == "" && isScheme(f[0]) {
		if strings.EqualFold(f[0], "Basic") && len(f) == 2 {
			return !basicIsToken(f[1])
		}
		f = f[1:]
	}
	return slices.ContainsFunc(f, func(x string) bool { return swap.In(x) == "" })
}

// basicIsToken reports whether Basic credentials are a proxy token: as the
// password (git's "x-access-token:sk-stub-…"), or as the user with no
// password or a fixed word (GitHub's "x-oauth-basic", Freshdesk's "X",
// Toggl's "api_token").
func basicIsToken(enc string) bool {
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	user, pass, _ := strings.Cut(string(b), ":")
	isToken := func(s string) bool { return s != "" && swap.In(s) == s }
	return isToken(pass) || (isToken(user) && slices.Contains(basicWords, pass))
}

// isScheme is a word that can name an auth scheme ("Bearer", "Convex",
// "DeepL-Auth-Key"): letters and dashes only, so a real key, which has
// digits, never passes for one.
func isScheme(s string) bool { return schemeWord.MatchString(s) }

var schemeWord = regexp.MustCompile(`^[A-Za-z][A-Za-z-]{0,31}$`)

// bareScheme is a scheme sent with nothing after it ("Bearer" when a
// client has no key). Only well-known ones: a lone word of letters could
// be a key.
func bareScheme(s string) bool {
	return slices.ContainsFunc([]string{"Bearer", "Basic", "Token", "Key", "Bot"}, func(x string) bool { return strings.EqualFold(x, s) })
}

// basicWords are fixed, non-secret passwords some services pair with an
// API key as the Basic user.
var basicWords = []string{"", "X", "x", "api_token", "x-oauth-basic"}

// strayMessage explains a refused request whose token sat outside the auth
// headers, where the service might keep the real key and send it back.
func strayMessage(headers []string) string {
	return "the proxy token is in the " + strings.Join(headers, ", ") + " header; send it only in Authorization or the service's own auth header"
}

// refusal maps an authorization error to a status and a message.
func refusal(err error, svc core.Service, envID string) (int, string) {
	var le *core.LimitError
	switch {
	case errors.Is(err, core.ErrNotLinked):
		return http.StatusBadGateway, "no saved key is linked for " + svc.Name + " in " + envID
	case errors.Is(err, core.ErrKeyUnreadable):
		return http.StatusInternalServerError, "the real key for " + svc.Name + " in " + envID + " can't be decrypted; is Keystub using the master key it was set with?"
	case errors.As(err, &le):
		return http.StatusTooManyRequests, le.Error()
	case errors.Is(err, core.ErrExpired):
		return http.StatusUnauthorized, "this proxy token has expired"
	case errors.Is(err, core.ErrNotAllowed):
		return http.StatusForbidden, "this proxy token can't use " + svc.Name
	case errors.Is(err, core.ErrUnknownKey):
		return http.StatusUnauthorized, "this request has no valid proxy token"
	default:
		return http.StatusInternalServerError, "couldn't check the proxy token"
	}
}

// switchProtocols relays a websocket (or other upgraded) connection.
func (p *Proxy) switchProtocols(conn net.Conn, br *bufio.Reader, resp *http.Response) {
	up, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return
	}
	defer up.Close()
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 101 %s\r\n", http.StatusText(101)); err != nil {
		return
	}
	if err := resp.Header.Write(conn); err != nil {
		return
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		return
	}
	pipe(br, conn, up, up, halfCloseWait, func() { conn.Close(); up.Close() })
}

// plain forwards http:// requests as they are. Keys are never added to
// plain-text requests.
func (p *Proxy) plain(w http.ResponseWriter, r *http.Request) {
	if !p.allowed(w, proxyAuthToken(r.Header.Get("Proxy-Authorization"))) {
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	rt := p.Upstream
	switch {
	case p.BlockPrivate:
		p.plainOnce.Do(func() {
			p.plainPublic = &http.Transport{Proxy: nil, DialContext: publicDialer().DialContext, DisableCompression: true}
		})
		rt = p.plainPublic
	case p.Edge != nil:
		// Upstream reaches the edge and keeps its connection forever;
		// plain HTTP goes to any host, so it gets a transport that lets
		// idle connections go.
		p.plainOnce.Do(func() {
			p.plainPublic = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				IdleConnTimeout: 90 * time.Second, DisableCompression: true}
		})
		rt = p.plainPublic
	}
	resp, err := rt.RoundTrip(out)
	if errors.Is(err, errPrivate) {
		http.Error(w, errPrivate.Error(), http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "keystub: couldn't reach "+r.URL.Host, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

// --- helpers ---

// bufConn reads through the buffered reader left over from the CONNECT
// request, which may already hold the start of the TLS handshake.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

type trackedBody struct {
	io.ReadCloser
	eof    bool
	failed atomic.Bool // reading from the client failed: it went away mid-body
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.eof = true
	} else if err != nil {
		b.failed.Store(true)
	}
	return n, err
}

// halfCloseWait is how long pipe lets one direction run on after the other
// has finished, before closing both.
const halfCloseWait = 30 * time.Second

// pipe copies a→b and b→a until both directions finish. Once one direction
// ends, the other gets wait before closeAll ends it, so a peer that never
// closes can't hold the connection open forever.
func pipe(aR io.Reader, aW io.Writer, bR io.Reader, bW io.Writer, wait time.Duration, closeAll func()) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(bW, aR); closeWrite(bW); done <- struct{}{} }()
	go func() { _, _ = io.Copy(aW, bR); closeWrite(aW); done <- struct{}{} }()
	<-done
	select {
	case <-done:
	case <-time.After(wait):
		closeAll()
		<-done
	}
}

func closeWrite(w io.Writer) {
	switch c := w.(type) {
	case interface{ CloseWrite() error }:
		_ = c.CloseWrite()
	case *bufConn:
		if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
}

func bodyAllowed(status int) bool {
	return status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// IsLoopback reports whether addr (host:port) is on loopback.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isUpgrade(h http.Header) bool {
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// proxyAuthToken reads a proxy token from Proxy-Authorization, as sent for
// HTTPS_PROXY=http://keystub:<key>@host:port.
func proxyAuthToken(h string) string {
	switch {
	case strings.HasPrefix(h, "Basic "):
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
		if err != nil {
			return ""
		}
		user, pass, _ := strings.Cut(string(b), ":")
		if t := swap.In(pass); t != "" {
			return core.Normalize(t)
		}
		return core.Normalize(swap.In(user))
	case strings.HasPrefix(h, "Bearer "):
		return core.Normalize(swap.In(h))
	}
	return ""
}

func writeError(w io.Writer, status int, msg string) {
	b, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "keystub", "message": msg}})
	resp := &http.Response{
		StatusCode: status, ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(string(b))),
		ContentLength: int64(len(b)),
		Close:         true,
	}
	_ = resp.Write(w)
}
