package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/swap"
	"github.com/vivekverma239/keystub/internal/usage"
)

// TokenHeader carries the proxy token to the edge when the request itself
// holds none, e.g. an agent that took it from Proxy-Authorization.
const TokenHeader = "Keystub-Token"

// LegacyTokenHeader is TokenHeader's name before the rename to Keystub.
// Edges still accept it, so older agents keep working.
const LegacyTokenHeader = "Stubkey-Token"

// takeToken returns the token from TokenHeader (or its old name) and
// removes both, so neither reaches the service.
func takeToken(h http.Header) string {
	t := h.Get(TokenHeader)
	if t == "" {
		t = h.Get(LegacyTokenHeader)
	}
	h.Del(TokenHeader)
	h.Del(LegacyTokenHeader)
	return t
}

// Edge serves the same routes as the hosted Worker, so quick start and
// agents work against a self-hosted server too:
//
//	/s/<service>/<path>  quick start: an SDK's base URL points here
//	/h/<host>/<path>     an agent that already decrypted a request sends it here
//	/catalog             the services a token may use, for agents
//	/link, /link/poll    link a machine (device-code flow)
//	/machine/tokens      a linked machine gets a token per worktree
//
// Only services in the catalog are reachable, so the edge is never an open
// proxy.
type Edge struct {
	Core     DataPlane
	Log      core.Sink
	Upstream http.RoundTripper
	// Link, if set, serves machine linking: POST /link, /link/poll and
	// /machine/tokens.
	Link Linker
	// ClientIPHeader, if set, names the header a reverse proxy in front of
	// the edge puts the client's address in (X-Forwarded-For,
	// CF-Connecting-IP), for the per-source cap on /link. Set it only
	// behind such a proxy: anyone can write the header otherwise.
	ClientIPHeader string
}

// NewEdge returns an edge with a production transport.
func NewEdge(dp DataPlane, l core.Sink) *Edge {
	return &Edge{Core: dp, Log: l, Upstream: New(dp, nil, l).Upstream}
}

// CatalogResponse is the body of GET /catalog: the token's identity and the
// services it may use, so an agent knows which hosts to decrypt and a
// command which variables to set. It never carries a key.
type CatalogResponse struct {
	Token    CatalogToken     `json:"token"`
	Services []CatalogService `json:"services"`
	// Dropped is set by a client that cleaned the catalog up: what it
	// wouldn't take from the server, to warn about. Never sent.
	Dropped []string `json:"-"`
}

// CatalogToken names the token a catalog was asked with.
type CatalogToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Env       string     `json:"env"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// CatalogService is one service in a catalog.
type CatalogService struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Hosts   []string     `json:"hosts"`
	Header  string       `json:"header"` // the service's own auth header, besides Authorization
	EnvVars []string     `json:"envVars"`
	BaseURL core.BaseURL `json:"baseUrl,omitzero"`
}

// Service turns a catalog entry back into a core.Service, as far as an
// agent needs one.
func (c CatalogService) Service() core.Service {
	return core.Service{ID: c.ID, Name: c.Name, Hosts: c.Hosts, Header: c.Header, EnvVars: c.EnvVars, BaseURL: c.BaseURL}
}

func (e *Edge) catalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "keystub: use GET /catalog")
		return
	}
	token := takeToken(r.Header)
	if token == "" {
		token = swap.Find(r.Header, "")
	}
	t, svcs, err := e.Core.TokenServices(token)
	if err != nil {
		status, msg := refusal(err, core.Service{}, "")
		jsonError(w, status, "keystub: "+msg)
		return
	}
	out := CatalogResponse{Token: CatalogToken{ID: t.ID, Name: t.Name, Env: t.EnvID, ExpiresAt: t.ExpiresAt}, Services: []CatalogService{}}
	for _, s := range svcs {
		out.Services = append(out.Services, CatalogService{ID: s.ID, Name: s.Name, Hosts: s.Hosts, Header: s.Header, EnvVars: s.EnvVars, BaseURL: s.BaseURL})
	}
	writeJSON(w, out)
}

func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/catalog" {
		e.catalog(w, r)
		return
	}
	if e.link(w, r) {
		return
	}
	start := time.Now()
	kind, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
	first, rawPath, _ := strings.Cut(rest, "/")
	var svc core.Service
	var host string
	var ok bool
	switch kind {
	case "s":
		svc, ok = e.Core.Service(first)
		host = svc.PrimaryHost()
	case "h":
		host = strings.ToLower(first)
		svc, ok = e.Core.ServiceForHost(host)
	}
	if !ok || host == "" {
		jsonError(w, http.StatusNotFound, "keystub: no such service; use /s/<service>/… or /h/<host>/…")
		return
	}
	target, err := url.Parse("https://" + host + "/" + rawPath)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "keystub: bad path")
		return
	}
	target.RawQuery = r.URL.RawQuery

	entry := core.Entry{Time: start.UTC(), Service: svc.ID, Method: r.Method, Host: host, Path: target.Path}
	var meter *usage.Meter
	defer func() {
		// The response has been relayed (or abandoned) by now.
		entry.DurationMs = time.Since(start).Milliseconds()
		meter.Finish(&entry)
		if entry.Outcome == "" {
			entry.Outcome = usage.Outcome(svc.ID, entry.Status, entry.Note)
		}
		e.Log.Add(entry)
	}()

	token := takeToken(r.Header)
	if stray := swap.Stray(r.Header, svc.Header); len(stray) > 0 {
		msg := strayMessage(stray)
		entry.Status, entry.Note = http.StatusBadRequest, msg
		jsonError(w, http.StatusBadRequest, "keystub: "+msg)
		return
	}
	if token == "" {
		token = swap.Find(r.Header, svc.Header)
	}
	g, err := e.Core.Authorize(context.Background(), token, svc.ID)
	if g.Token.ID != "" {
		entry.Project, entry.Env, entry.TokenID, entry.Key = g.Project.ID, g.Env.ID, g.Token.ID, g.Token.Name
		entry.Principal, entry.SavedKey = g.Token.Principal, g.SavedKey.ID
	}
	if err != nil {
		status, msg := refusal(err, svc, g.Env.ID)
		entry.Status, entry.Note = status, msg
		jsonError(w, status, "keystub: "+msg)
		return
	}

	meter = usage.Start(svc.ID, r.Method, target.Path, start)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL, pr.Out.Host = target, host
			swap.Apply(pr.Out.Header, g.Key, svc.Header, svc.Format)
			usage.Narrow(svc.ID, pr.Out.Header)
			pr.Out.Body = meter.Request(pr.Out.Body, pr.Out.Header)
		},
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			entry.OverheadMs = time.Since(start).Milliseconds()
			return e.Upstream.RoundTrip(req)
		}),
		FlushInterval: -1, // stream every write, for server-sent events
		ModifyResponse: func(resp *http.Response) error {
			entry.Status = resp.StatusCode
			resp.Header.Del(OutcomeHeader) // only Keystub's own answers carry it
			meter.Response(resp)           // scans the body as it is copied to the client
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) || r.Context().Err() != nil {
				// The client hung up first; nobody is left to answer.
				entry.Status, entry.Note, entry.Outcome = 0, "client went away", core.OutcomeCanceled
				return
			}
			entry.Status, entry.Note = http.StatusBadGateway, "upstream unreachable"
			entry.Outcome = core.OutcomeUnreachable
			w.Header().Set(OutcomeHeader, core.OutcomeUnreachable)
			jsonError(w, http.StatusBadGateway, "keystub: couldn't reach "+host)
		},
	}
	rp.ServeHTTP(w, r)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// OutcomeHeader marks a response Keystub's edge wrote itself, with the
// outcome: "refused", or "unreachable" when the service couldn't be
// reached. An agent forwarding to the edge logs that rather than reading
// the status as the service's.
const OutcomeHeader = "Keystub-Outcome"

func jsonError(w http.ResponseWriter, status int, msg string) {
	if w.Header().Get(OutcomeHeader) == "" {
		w.Header().Set(OutcomeHeader, core.OutcomeRefused)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "keystub", "message": msg}})
}
