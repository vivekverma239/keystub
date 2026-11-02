package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

func post(t *testing.T, url, auth string, body any, out any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestEdgeLinksMachines(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	l, _ := reqlog.Open("", 5)
	ed := NewEdge(e, l)
	ed.Link = e
	srv := httptest.NewServer(ed)
	defer srv.Close()

	var st LinkStartResponse
	if code := post(t, srv.URL+"/link", "", map[string]string{"name": "devbox"}, &st); code != 200 || st.UserCode == "" || st.DeviceCode == "" || st.ExpiresIn < 500 || st.Interval < 1 {
		t.Fatalf("start: %d %+v", code, st)
	}
	if p := e.PendingLinks(); len(p) != 1 || p[0].From != "127.0.0.1" {
		t.Fatalf("pending = %+v", p)
	}
	if code := post(t, srv.URL+"/link/poll", "", map[string]string{"deviceCode": st.DeviceCode}, nil); code != http.StatusAccepted {
		t.Fatalf("pending poll: %d", code)
	}
	if _, err := e.ApproveLink(bg, st.UserCode, []string{core.DefaultEnv}); err != nil {
		t.Fatal(err)
	}
	var done LinkPollResponse
	if code := post(t, srv.URL+"/link/poll", "", map[string]string{"deviceCode": st.DeviceCode}, &done); code != 200 || done.Machine.Name != "devbox" || done.Credential == "" || done.Machine.Envs[0] != core.DefaultEnv {
		t.Fatalf("poll: %d %+v", code, done)
	}
	if code := post(t, srv.URL+"/link/poll", "", map[string]string{"deviceCode": st.DeviceCode}, nil); code != http.StatusNotFound {
		t.Fatalf("second poll: %d", code)
	}

	var tok MachineTokenResponse
	if code := post(t, srv.URL+"/machine/tokens", done.Credential, map[string]string{"name": "wt"}, &tok); code != 200 || tok.Name != "devbox/wt" || tok.Env != core.DefaultEnv || tok.Token == "" {
		t.Fatalf("token: %d %+v", code, tok)
	}
	if err := e.CheckToken(tok.Token); err != nil {
		t.Fatalf("token doesn't work: %v", err)
	}
	for name, c := range map[string]struct {
		cred, env string
		want      int
	}{
		"no credential":   {"", "", 401},
		"wrong one":       {"skmach_00", "", 401},
		"a proxy token":   {tok.Token, "", 401},
		"env not allowed": {done.Credential, "default/prod", 403},
	} {
		if code := post(t, srv.URL+"/machine/tokens", c.cred, map[string]string{"env": c.env, "name": "wt"}, nil); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	if code := post(t, srv.URL+"/link", "", map[string]string{"name": ""}, nil); code != 400 {
		t.Fatalf("no name: %d", code)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/link", nil)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /link: %d", resp.StatusCode)
	}
}

func TestEdgeWithoutLinker(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	l, _ := reqlog.Open("", 5)
	srv := httptest.NewServer(NewEdge(e, l))
	defer srv.Close()
	if code := post(t, srv.URL+"/link", "", map[string]string{"name": "x"}, nil); code != 404 {
		t.Fatalf("got %d", code)
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/link", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := (&Edge{}).clientIP(r); got != "10.0.0.1" {
		t.Fatalf("no trusted header: %s (a client could pick its own address)", got)
	}
	e := &Edge{ClientIPHeader: "X-Forwarded-For"}
	if got := e.clientIP(r); got != "203.0.113.7" {
		t.Fatalf("trusted header: %s, want the address the proxy added", got)
	}
	for v, want := range map[string]string{"203.0.113.7:5678": "203.0.113.7", "[2001:db8::1]:443": "2001:db8::1", "2001:db8::2": "2001:db8::2"} {
		r.Header.Set("X-Forwarded-For", v)
		if got := e.clientIP(r); got != want {
			t.Errorf("%s: %s", v, got)
		}
	}
	r.Header.Set("X-Forwarded-For", "not an ip")
	if got := e.clientIP(r); got != "10.0.0.1" {
		t.Fatalf("bad header: %s", got)
	}
}

func TestCheckClientIPHeader(t *testing.T) {
	for name, ok := range map[string]bool{"": true, "X-Real-IP": true, "CF-Connecting-IP": true, "X-Forwarded-For": true, "Forwarded": false, "forwarded": false, "X Real": false, "X-IP:": false} {
		if err := CheckClientIPHeader(name); (err == nil) != ok {
			t.Errorf("%q: %v", name, err)
		}
	}
}
