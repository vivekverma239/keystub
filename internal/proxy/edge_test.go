package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

func newEdge(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string, *reqlog.Log) {
	t.Helper()
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)
	e, _ := coretest.Engine(t, "")
	svc := core.Service{ID: "echo", Name: "Echo", Hosts: []string{"api.echo.test"}, BaseURL: core.BaseURL{Var: "ECHO_BASE_URL", Path: "/v1"}}
	if err := e.AddService(bg, svc); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, e, core.DefaultEnv, "echo", "real-secret-xyz"); err != nil {
		t.Fatal(err)
	}
	token, _, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "quick"})
	l, _ := reqlog.Open("", 50)
	ed := NewEdge(e, l)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	addr := up.Listener.Addr().String()
	ed.Upstream = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr) // every host is the test upstream
		},
	}
	srv := httptest.NewServer(ed)
	t.Cleanup(srv.Close)
	return srv, token, l
}

func TestEdgeQuickStartRoute(t *testing.T) {
	var got *http.Request
	srv, token, l := newEdge(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		_, _ = io.WriteString(w, "hello")
	})
	req, _ := http.NewRequest("POST", srv.URL+"/s/echo/v1/chat/completions?stream=true", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
	if got.Host != "api.echo.test" || got.URL.Path != "/v1/chat/completions" || got.URL.RawQuery != "stream=true" || got.Header.Get("Authorization") != "Bearer real-secret-xyz" {
		t.Fatalf("upstream saw host %q path %q query %q auth %q", got.Host, got.URL.Path, got.URL.RawQuery, got.Header.Get("Authorization"))
	}
	es := waitEntries(t, l, 1) // logged as the handler returns, maybe after the client has the body
	if len(es) != 1 || es[0].Key != "quick" || es[0].Status != 200 || es[0].Host != "api.echo.test" || es[0].OverheadMs < 0 {
		t.Fatalf("log = %+v", es)
	}
}

func TestEdgeAgentRouteUsesTokenHeader(t *testing.T) {
	var got http.Header
	srv, token, _ := newEdge(t, func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	req, _ := http.NewRequest("GET", srv.URL+"/h/api.echo.test/v1/models", nil)
	req.Header.Set(TokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || got.Get("Authorization") != "Bearer real-secret-xyz" || got.Get(TokenHeader) != "" {
		t.Fatalf("status %d, upstream saw %v", resp.StatusCode, got)
	}
}

func TestEdgeRefuses(t *testing.T) {
	srv, token, _ := newEdge(t, func(http.ResponseWriter, *http.Request) { t.Error("request reached upstream") })
	for name, c := range map[string]struct {
		path, auth string
		want       int
	}{
		"host not in the catalog": {"/h/evil.example/x", "Bearer " + token, http.StatusNotFound},
		"unknown service":         {"/s/nope/x", "Bearer " + token, http.StatusNotFound},
		"no token":                {"/s/echo/v1/x", "", http.StatusUnauthorized},
		"not a route":             {"/x", "Bearer " + token, http.StatusNotFound},
		"token in a stray header": {"/s/echo/v1/x", "stray", http.StatusBadRequest},
	} {
		req, _ := http.NewRequest("GET", srv.URL+c.path, nil)
		switch c.auth {
		case "":
		case "stray":
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Request-Id", token)
		default:
			req.Header.Set("Authorization", c.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, c.want)
		}
	}
}

func TestEdgeCatalog(t *testing.T) {
	srv, token, _ := newEdge(t, func(http.ResponseWriter, *http.Request) { t.Error("request reached upstream") })
	get := func(h, v string) (*http.Response, CatalogResponse) {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+"/catalog", nil)
		if h != "" {
			req.Header.Set(h, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var c CatalogResponse
		_ = json.NewDecoder(resp.Body).Decode(&c)
		return resp, c
	}
	for _, h := range [][2]string{{TokenHeader, token}, {"Authorization", "Bearer " + token}, {TokenHeader, core.Compact(token)}} {
		resp, c := get(h[0], h[1])
		if resp.StatusCode != 200 || c.Token.Name != "quick" || c.Token.Env != core.DefaultEnv || len(c.Services) != 1 {
			t.Fatalf("%s: %d %+v", h[0], resp.StatusCode, c)
		}
		s := c.Services[0]
		if s.ID != "echo" || len(s.Hosts) != 1 || s.Hosts[0] != "api.echo.test" || s.Header != "Authorization" || s.BaseURL.Var != "ECHO_BASE_URL" {
			t.Fatalf("service = %+v", s)
		}
	}
	if resp, _ := get("", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	if resp, _ := get(TokenHeader, "sk-stub-00ff"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", resp.StatusCode)
	}
}

func TestEdgeCatalogShowsOnlyTheTokensServices(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	for _, id := range []string{"one", "two"} {
		if err := e.AddService(bg, core.Service{ID: id, Name: id, Hosts: []string{"api." + id + ".test"}}); err != nil {
			t.Fatal(err)
		}
		if err := coretest.SetSecret(bg, e, core.DefaultEnv, id, "real-"+id); err != nil {
			t.Fatal(err)
		}
	}
	scoped, _, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "scoped", Service: "two"})
	gone, tk, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "gone"})
	if err := e.RevokeToken(bg, tk.ID); err != nil {
		t.Fatal(err)
	}
	expired, _, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "short", TTL: time.Minute})
	e.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	l, _ := reqlog.Open("", 5)
	srv := httptest.NewServer(NewEdge(e, l))
	defer srv.Close()
	for name, c := range map[string]struct {
		token string
		want  int
		ids   string
	}{
		"scoped":  {scoped, 200, "two"},
		"revoked": {gone, 401, ""},
		"expired": {expired, 401, ""},
	} {
		req, _ := http.NewRequest("GET", srv.URL+"/catalog", nil)
		req.Header.Set(TokenHeader, c.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var cat CatalogResponse
		_ = json.NewDecoder(resp.Body).Decode(&cat)
		resp.Body.Close()
		var ids []string
		for _, s := range cat.Services {
			ids = append(ids, s.ID)
		}
		if resp.StatusCode != c.want || strings.Join(ids, ",") != c.ids {
			t.Errorf("%s: %d %v", name, resp.StatusCode, ids)
		}
	}
	if es := l.Recent(5); len(es) != 0 {
		t.Fatalf("catalog requests were logged as calls: %+v", es)
	}
}

func TestEdgeStillAcceptsTheOldTokenHeader(t *testing.T) {
	var got http.Header
	srv, token, _ := newEdge(t, func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	req, _ := http.NewRequest("GET", srv.URL+"/h/api.echo.test/v1/models", nil)
	req.Header.Set(LegacyTokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || got.Get("Authorization") != "Bearer real-secret-xyz" || got.Get(LegacyTokenHeader) != "" || got.Get(TokenHeader) != "" {
		t.Fatalf("status %d, upstream saw %v", resp.StatusCode, got)
	}
}
