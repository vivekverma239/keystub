package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

// TestEdgeKeyInURL runs a query-key and a path-key service through the
// edge: the upstream gets the real key in the URL, and the client never
// sees it, though the upstream echoes its URL in a header and the body.
func TestEdgeKeyInURL(t *testing.T) {
	const real = "real:key+1"
	var seen []string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI()+" ae="+r.Header.Get("Accept-Encoding"))
		w.Header().Set("Location", "https://"+r.Host+r.URL.RequestURI())
		b := `{"next":"https://` + r.Host + r.URL.RequestURI() + `","key":"` + real + `"}`
		w.Header().Set("Content-Length", strconv.Itoa(len(b))) // the length changes once scrubbed
		_, _ = io.WriteString(w, b)
	}))
	t.Cleanup(up.Close)
	e, _ := coretest.Engine(t, "")
	for _, svc := range []core.Service{
		{ID: "q", Name: "Q", Hosts: []string{"api.q.test"}, Query: "key"},
		{ID: "p", Name: "P", Hosts: []string{"api.p.test"}, Paths: []string{"/bot{key}/"}},
	} {
		if err := e.AddService(bg, svc); err != nil {
			t.Fatal(err)
		}
		if err := coretest.SetSecret(bg, e, core.DefaultEnv, svc.ID, real); err != nil {
			t.Fatal(err)
		}
	}
	token, _, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "url"})
	l, _ := reqlog.Open("", 50)
	ed := NewEdge(e, l)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	addr := up.Listener.Addr().String()
	ed.Upstream = &http.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	srv := httptest.NewServer(ed)
	t.Cleanup(srv.Close)

	get := func(path string) (int, string, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Location"), string(b)
	}

	status, loc, body := get("/s/q/v1/x?a=1&key=" + token)
	if status != 200 || seen[0] != "/v1/x?a=1&key=real%3Akey%2B1 ae=" {
		t.Fatalf("status %d, upstream saw %q", status, seen)
	}
	if strings.Contains(loc+body, "real") || !strings.Contains(loc, "key="+token) || !strings.Contains(body, `"key":"`+token+`"`) {
		t.Fatalf("client got Location %q, body %q", loc, body)
	}

	status, loc, body = get("/s/p/bot" + token + "/getMe")
	if status != 200 || seen[1] != "/botreal:key+1/getMe ae=" || strings.Contains(loc+body, "real") {
		t.Fatalf("status %d, upstream saw %q, client got %q %q", status, seen, loc, body)
	}

	if status, _, _ = get("/s/q/v1/x?q=" + token); status != http.StatusBadRequest {
		t.Fatalf("token in another parameter: %d", status)
	}
	if status, _, _ = get("/s/p/bot1/getMe/" + token); status != http.StatusBadRequest {
		t.Fatalf("token elsewhere in the path: %d", status)
	}
	for _, en := range waitEntries(t, l, 4) {
		if strings.Contains(en.Path, token) || strings.Contains(en.Path, "real") {
			t.Fatalf("logged path %q", en.Path)
		}
	}
}
