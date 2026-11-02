// Package agent runs Keystub's local proxy against a remote edge, with no
// keys on the box. It decrypts the hosts the edge's catalog names for the
// agent's token and forwards each request to the edge's /h route, where the
// token is checked and the real key swapped in. The box keeps only the
// local CA it decrypts with.
//
// The edge doesn't decide alone what the box decrypts: a host it names for
// a service is decrypted only if Keystub's built-in catalog gives that
// service that host, or the box allows it (AllowHosts). Otherwise a
// compromised edge, or anyone who can add a service there, could have
// every box send it github.com's traffic.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/runenv"
)

// Config is what an agent runs with.
type Config struct {
	Home   string   // where the local CA lives
	Remote *url.URL // the edge, e.g. https://keystub.example.com
	Token  string   // a proxy token, to ask the edge for its catalog
	Listen string   // loopback address for the proxy; default 127.0.0.1:8787
	// Transport reaches the edge; proxy.EdgeTransport() if nil. Catalog
	// requests and forwarded ones share it, and so one connection.
	Transport http.RoundTripper
	// Refresh is how often the catalog is fetched again; default 5 minutes.
	Refresh time.Duration
	// OnRefresh, if set, gets each catalog fetched after the first.
	OnRefresh func(proxy.CatalogResponse)
	// RefreshToken, if set, gives the token for each catalog fetch after
	// the first (a linked machine's, which it renews with the server).
	RefreshToken func(context.Context) (string, error)
	// AllowHosts are hosts beyond the built-in catalog this box agrees to
	// decrypt when the edge names them: "api.internal.example" or
	// "*.internal.example" for a custom service, "gitlab=gitlab.corp.example"
	// for a built-in service's own server.
	AllowHosts []string
}

// Agent is a running local proxy.
type Agent struct {
	Addr       string // where the proxy listens
	CAPath     string // the local CA alone
	BundlePath string // system roots plus the local CA; "" if it couldn't be written
	// Catalog is the edge's answer at start: the token's identity and the
	// services it decrypts (any the agent won't decrypt are left out).
	Catalog proxy.CatalogResponse
	// Ignored lists the hosts the edge named that the agent won't decrypt:
	// not in the built-in catalog for that service, nor allowed on this box.
	Ignored []string

	hosts  *hosts
	srv    *http.Server
	cancel context.CancelFunc
	done   chan struct{}
}

// Start fetches the catalog and starts the proxy. It fails if the edge
// can't be reached or refuses the token, so a bad setup shows at once.
func Start(ctx context.Context, cfg Config) (*Agent, error) {
	if err := CheckRemote(cfg.Remote); err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, errors.New("the agent needs a proxy token to ask the edge which services it serves")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8787"
	}
	if !proxy.IsLoopback(cfg.Listen) {
		// The agent can't check tokens itself, so anyone who reached it
		// could use it to reach the edge's hosts with any token they hold.
		return nil, fmt.Errorf("the agent listens on loopback only, not %s; use keystub serve for a shared proxy", cfg.Listen)
	}
	if cfg.Transport == nil {
		cfg.Transport = proxy.EdgeTransport()
	}
	if cfg.Refresh <= 0 {
		cfg.Refresh = 5 * time.Minute
	}
	for _, h := range cfg.AllowHosts {
		if err := checkAllowHost(h); err != nil {
			return nil, err
		}
	}
	if err := checkPins(cfg.AllowHosts); err != nil {
		return nil, err
	}

	cat, err := FetchCatalog(ctx, cfg.Transport, cfg.Remote, cfg.Token)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Home, 0o700); err != nil {
		return nil, err
	}
	authority, err := ca.LoadOrCreate(cfg.Home)
	if err != nil {
		return nil, err
	}
	bundle := filepath.Join(cfg.Home, "ca-bundle.pem")
	if err := runenv.WriteBundle(bundle, authority.CertPEM()); err != nil {
		_ = os.Remove(bundle)
		bundle = ""
	}

	h := &hosts{trusted: trustedHosts(cfg.AllowHosts)}
	cat, ignored := h.set(cat)
	p := proxy.NewAgent(h, cfg.Remote, authority, nil)
	p.Upstream = cfg.Transport
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	rctx, cancel := context.WithCancel(context.Background())
	a := &Agent{
		Addr: l.Addr().String(), CAPath: filepath.Join(cfg.Home, "ca.pem"), BundlePath: bundle, Catalog: cat, Ignored: ignored,
		hosts: h, srv: &http.Server{Handler: p, ReadHeaderTimeout: 15 * time.Second},
		cancel: cancel, done: make(chan struct{}),
	}
	go func() { _ = a.srv.Serve(l) }()
	go a.refresh(rctx, cfg)
	return a, nil
}

// refresh fetches the catalog again now and then, so services added on
// the server reach a running agent. A failed fetch keeps the last one.
func (a *Agent) refresh(ctx context.Context, cfg Config) {
	defer close(a.done)
	warned := slices.Clone(a.Ignored) // named at start
	t := time.NewTicker(cfg.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if cfg.RefreshToken != nil {
				if tok, err := cfg.RefreshToken(ctx); err == nil {
					cfg.Token = tok
				} else if ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "keystub: warning: couldn't renew the agent's token, keeping the last one:", err)
				}
			}
			if cat, err := FetchCatalog(ctx, cfg.Transport, cfg.Remote, cfg.Token); err == nil {
				var ignored []string
				cat, ignored = a.hosts.set(cat)
				if fresh := newOnly(ignored, warned); len(fresh) > 0 {
					fmt.Fprintln(os.Stderr, "keystub: warning: not decrypting "+strings.Join(fresh, ", ")+", newly listed by the edge: not in Keystub's catalog for that service, and a built-in service's host is decrypted only as that service; to trust another host, allow it on this box (--allow-host HOST for a custom service, SERVICE=HOST for a built-in one's own server)")
					warned = append(warned, fresh...)
				}
				if cfg.OnRefresh != nil {
					cfg.OnRefresh(cat)
				}
			} else if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "keystub: warning: couldn't refresh the catalog, keeping the last one:", err)
			}
		}
	}
}

// Close stops the proxy.
func (a *Agent) Close() error {
	a.cancel()
	<-a.done
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.srv.Shutdown(ctx)
}

// CheckRemote accepts an edge URL: https (or http on loopback), a host,
// and at most a path, since /h/<host>/… and /catalog are appended to it.
func CheckRemote(u *url.URL) error {
	if u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the remote must be an https:// URL")
	}
	if u.Scheme == "http" && !proxy.IsLoopback(net.JoinHostPort(u.Hostname(), "80")) {
		// Tokens and every request and response would cross the network
		// in the clear.
		return fmt.Errorf("the remote %s is plain HTTP off this machine; put TLS in front of it and use https://", u.Host)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("the remote %s://%s must have no user, query or fragment: routes are appended to it", u.Scheme, u.Host)
	}
	return nil
}

// FetchCatalog asks the edge which services token may use.
func FetchCatalog(ctx context.Context, rt http.RoundTripper, edge *url.URL, token string) (proxy.CatalogResponse, error) {
	var out proxy.CatalogResponse
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(edge.String(), "/")+"/catalog", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set(proxy.TokenHeader, token)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return out, fmt.Errorf("can't reach the edge at %s: %w", edge.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
			return out, fmt.Errorf("the edge refused: %s", printable(strings.TrimPrefix(e.Error.Message, "keystub: ")))
		}
		return out, fmt.Errorf("GET %s/catalog: %s", edge.Host, printable(resp.Status))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("the edge's catalog isn't valid: %w", err)
	}
	return clean(out), nil
}

// clean keeps the server from choosing what a command's environment holds
// or which header the box guards. Every service is checked as a server
// would check it (its ID normalized, so "Anthropic" is the built-in
// anthropic), and one that fails is dropped. A built-in service gets the
// built-in catalog's header, variables and base URL, whatever the server
// says. Another may name only variables that hold a key (FOO_KEY,
// FOO_TOKEN…), never KEYSTUB_*, so it can't set BASH_ENV, NODE_OPTIONS or
// HTTPS_PROXY, and gets no base URL: one like PIP_INDEX_URL pointing at
// the server would let it serve code to installers.
func clean(cat proxy.CatalogResponse) proxy.CatalogResponse {
	var out []proxy.CatalogService
	for _, c := range cat.Services {
		c.Name = printable(c.Name)
		c.ID = strings.ToLower(strings.TrimSpace(c.ID))
		if p, ok := catalog.Preset(c.ID); ok {
			c.Header, c.EnvVars, c.BaseURL = p.Header, p.EnvVars, p.BaseURL
		} else {
			var vars []string
			for _, v := range c.EnvVars {
				name, _, _ := strings.Cut(v, "=")
				if keyVar(name) {
					vars = append(vars, v)
				} else {
					cat.Dropped = append(cat.Dropped, c.Name+": "+printable(name))
				}
			}
			c.EnvVars = vars
			c.BaseURL = core.BaseURL{}
		}
		s := c.Service()
		if err := s.Validate(); err != nil {
			cat.Dropped = append(cat.Dropped, c.Name+" (not a valid service: "+printable(err.Error())+")")
			continue
		}
		c.ID, c.Hosts, c.Header = s.ID, s.Hosts, s.Header
		out = append(out, c)
	}
	cat.Services = out
	return cat
}

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// keyVar is a variable name a custom service may set: one that holds a
// key, and not one a built-in service reads (GITHUB_TOKEN, NPM_TOKEN…),
// which would send the proxy token to that service's hosts.
func keyVar(name string) bool {
	up := strings.ToUpper(name)
	return varName.MatchString(name) && !strings.HasPrefix(up, "KEYSTUB_") && !strings.HasPrefix(up, "STUBKEY_") && !builtInVars[up] &&
		slices.ContainsFunc([]string{"_KEY", "_TOKEN", "_SECRET", "_PASSWORD"}, func(s string) bool {
			return strings.HasSuffix(up, s) && len(up) > len(s)
		})
}

var builtInVars = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range catalog.Presets {
		for _, v := range p.EnvVars {
			name, _, _ := strings.Cut(v, "=")
			m[strings.ToUpper(name)] = true
		}
		if p.BaseURL.Var != "" {
			m[strings.ToUpper(p.BaseURL.Var)] = true
		}
	}
	return m
}()

// printable drops control and format characters (a right-to-left
// override, say) from text a server sent, before it reaches a terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// checkAllowHost refuses an --allow-host (HOST or SERVICE=HOST) that
// could never match, names no built-in service, or would trust a whole
// top-level domain.
func checkAllowHost(entry string) error {
	h := entry
	if id, host, ok := strings.Cut(h, "="); ok {
		if _, built := catalog.Preset(strings.ToLower(strings.TrimSpace(id))); !built {
			return fmt.Errorf("--allow-host %q: %q isn't a built-in service; a custom service's host goes in alone", h, id)
		}
		h = host
	}
	h = strings.TrimSpace(h)
	probe := core.Service{ID: "allow", Name: "allow", Hosts: []string{h}}
	if probe.Validate() != nil {
		return fmt.Errorf("--allow-host %q: %q isn't a host like api.example.com or *.example.com (no scheme, port or path)", entry, h)
	}
	if base, ok := strings.CutPrefix(h, "*."); ok && !strings.Contains(base, ".") {
		return fmt.Errorf("--allow-host %q would trust every site under .%s", entry, base)
	}
	return nil
}

// checkPins refuses pins that would let the edge's order choose a host's
// service: a host pinned to a built-in service that another built-in also
// owns (pinned, or in its catalog), or a plain allowed host wholly under
// a pin, which could never be a custom service's.
func checkPins(allow []string) error {
	overlap := func(a, b string) bool { return covers(a, b) || covers(b, a) }
	t := trustedHosts(allow)
	for _, a := range allow {
		id, h, pinned := strings.Cut(a, "=")
		id = strings.ToLower(strings.TrimSpace(id))
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if !pinned {
			continue
		}
		for other, own := range t.byService {
			if other != id && slices.ContainsFunc(own, func(o string) bool { return overlap(o, h) }) {
				return fmt.Errorf("--allow-host %q: %s is also %s's; a host may be only one built-in service's", a, h, other)
			}
		}
		if i := slices.IndexFunc(t.allowed, func(p string) bool { return covers(h, p) }); i >= 0 {
			return fmt.Errorf("--allow-host %q: %s is %s's, so --allow-host %s could never be a custom service's", a, t.allowed[i], id, t.allowed[i])
		}
	}
	return nil
}

// newOnly is what's in a and not in b.
func newOnly(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// hosts is the agent's catalog: the services the edge named, cut down to
// the hosts this box trusts.
type hosts struct {
	trusted trusted

	mu       sync.RWMutex
	services []core.Service
}

// trusted is what the box agrees to decrypt: each built-in service's own
// hosts and any the box gave it (--allow-host gitlab=gitlab.corp.example),
// and hosts the box allows for custom services. The edge never chooses
// which built-in service a host is filed under.
type trusted struct {
	byService map[string][]string
	allowed   []string
}

func trustedHosts(allow []string) trusted {
	t := trusted{byService: map[string][]string{}}
	for _, s := range catalog.Presets {
		for _, h := range s.Hosts {
			t.byService[s.ID] = append(t.byService[s.ID], strings.ToLower(h))
		}
	}
	for _, a := range allow {
		id, h, pinned := strings.Cut(a, "=")
		if !pinned {
			id, h = "", a
		}
		id = strings.ToLower(strings.TrimSpace(id))
		if h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), ".")); h == "" {
			continue
		}
		if _, ok := t.byService[id]; ok {
			t.byService[id] = append(t.byService[id], h)
		} else if !pinned {
			t.allowed = append(t.allowed, h)
		}
	}
	return t
}

// has reports whether service may be decrypted on host: a custom service
// naming github.com is not GitHub, and a built-in service is decrypted
// only on its own hosts and those the box gave it, since its variables
// (GITHUB_TOKEN…) are read by tools that go to them.
func (t trusted) has(service, host string) bool {
	in := func(p string) bool { return covers(p, host) }
	if own, ok := t.byService[service]; ok {
		return slices.ContainsFunc(own, in)
	}
	return slices.ContainsFunc(t.allowed, in)
}

// set takes a catalog and keeps, of each service, the hosts the box
// trusts. It returns the catalog as the agent serves it, so callers set
// variables for nothing it tunnels, and the hosts it ignored.
func (h *hosts) set(cat proxy.CatalogResponse) (proxy.CatalogResponse, []string) {
	var svcs []core.Service
	var kept []proxy.CatalogService
	var ignored []string
	for _, c := range cat.Services {
		s := c.Service()
		if s.Validate() != nil {
			continue
		}
		var ok []string
		for _, host := range s.Hosts {
			switch owner := h.trusted.takesBuiltIn(s.ID, host); {
			case owner != "":
				ignored = append(ignored, host+" (only as "+owner+")")
			case h.trusted.has(s.ID, host):
				ok = append(ok, host)
			default:
				ignored = append(ignored, host)
			}
		}
		if len(ok) == 0 {
			continue
		}
		s.Hosts, c.Hosts = ok, ok
		svcs = append(svcs, s)
		kept = append(kept, c)
	}
	h.mu.Lock()
	h.services = svcs
	h.mu.Unlock()
	cat.Services = kept
	return cat, ignored
}

// covers reports whether the trusted pattern t takes in every host the
// pattern host matches: an exact host, or one under a trusted wildcard. A
// wildcard host is covered only by a wildcard at or above it.
func covers(t, host string) bool {
	if t == host {
		return true
	}
	base, ok := strings.CutPrefix(t, "*.")
	if !ok {
		return false
	}
	host = strings.TrimPrefix(host, "*")
	if !strings.HasPrefix(host, ".") {
		host = "." + host
	}
	return strings.HasSuffix(host, "."+base) && host != "."+base
}

// ServiceForHost implements proxy.Catalog. A host the built-in catalog
// gives a service, or the box pinned to one, is decrypted only as that
// service, whatever else the box allows, so its own auth header is always
// guarded: a custom service under an allowed *.googleapis.com never takes
// generativelanguage.googleapis.com.
func (h *hosts) ServiceForHost(host string) (core.Service, bool) {
	owners := h.trusted.owners(host)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.services {
		if s.Matches(host) && (len(owners) == 0 || slices.Contains(owners, s.ID)) {
			return s, true
		}
	}
	return core.Service{}, false
}

// takesBuiltIn returns the built-in service that host belongs to when it
// isn't id's: an exact host a built-in covers (in the catalog, or pinned
// by the box), or a wildcard wholly under a built-in's (so its variables
// aren't set for what is never decrypted). A wildcard that only overlaps
// one is checked per request.
func (t trusted) takesBuiltIn(id, host string) string {
	var owners []string
	for sid, own := range t.byService {
		if slices.ContainsFunc(own, func(p string) bool { return covers(p, host) }) || !strings.HasPrefix(host, "*.") && (core.Service{Hosts: own}).Matches(host) {
			owners = append(owners, sid)
		}
	}
	if len(owners) == 0 || slices.Contains(owners, id) {
		return ""
	}
	slices.Sort(owners)
	return owners[0]
}

// owners are the built-in services whose hosts, the catalog's or pinned by
// the box, cover host.
func (t trusted) owners(host string) []string {
	var ids []string
	for sid, own := range t.byService {
		if (core.Service{Hosts: own}).Matches(host) {
			ids = append(ids, sid)
		}
	}
	return ids
}
