package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
)

// apiRig is a server with openai added, default/dev and default/prod, and
// the saved key "team" linked in dev.
func apiRig(t *testing.T) (*Server, *core.Engine, string) {
	t.Helper()
	s, e := newServer(t)
	p, _ := catalog.Preset("openai")
	if err := e.AddService(bg, p); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddEnvironment(bg, "default", "prod", core.Limits{}); err != nil {
		t.Fatal(err)
	}
	k, err := e.AddKey(bg, core.KeySpec{ServiceID: "openai", Name: "team", Value: "sk-team"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.LinkKey(bg, core.LinkSpec{EnvID: dev, ServiceID: "openai", KeyID: k.ID}); err != nil {
		t.Fatal(err)
	}
	return s, e, k.ID
}

func decodeBody(t *testing.T, w interface{ Body() string }) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(w.Body()), &m); err != nil {
		t.Fatalf("not JSON: %s", w.Body())
	}
	return m
}

type rec struct {
	code int
	body string
}

func (r rec) Body() string { return r.body }

func call(s *Server, method, path, body string) rec {
	w := do(s, method, path, body, admin)
	return rec{w.Code, w.Body.String()}
}

// Every route, as protocol/api.md lists it, with a request that succeeds.
func TestAPIRoutes(t *testing.T) {
	s, _, keyID := apiRig(t)
	routes := []struct {
		method, path, body string
		want               int
		has                string // a key the answer holds
	}{
		{"GET", "/api/me", "", 200, "account"},
		{"GET", "/api/projects", "", 200, "projects"},
		{"POST", "/api/projects", `{"name":"app"}`, 201, "project"},
		{"PATCH", "/api/projects/app", `{"limits":{"dailyRequests":5,"perMinute":0}}`, 200, "ok"},
		{"GET", "/api/environments", "", 200, "environments"},
		{"POST", "/api/environments", `{"project":"app","name":"dev"}`, 201, "environment"},
		{"PATCH", "/api/environments/app/dev", `{"limits":{"dailyRequests":5,"perMinute":0}}`, 200, "ok"},
		{"GET", "/api/catalog", "", 200, "services"},
		{"GET", "/api/services", "", 200, "services"},
		{"POST", "/api/services", `{"catalog":"anthropic"}`, 201, "service"},
		{"POST", "/api/services", `{"name":"Internal","hosts":["api.internal.test"]}`, 201, "service"},
		{"PATCH", "/api/services/internal", `{"hosts":["api2.internal.test"]}`, 200, "service"},
		{"GET", "/api/keys", "", 200, "keys"},
		{"POST", "/api/keys", `{"service":"openai","name":"personal","value":"sk-personal"}`, 201, "key"},
		{"GET", "/api/keys/" + keyID, "", 200, "key"},
		{"PATCH", "/api/keys/" + keyID, `{"limits":{"dailyRequests":100,"perMinute":0}}`, 200, "key"},
		{"PUT", "/api/keys/" + keyID + "/value", `{"value":"sk-team-2"}`, 200, "key"},
		{"GET", "/api/environments/default/dev/links", "", 200, "links"},
		{"PUT", "/api/environments/default/prod/links/openai", `{"key":"` + keyID + `"}`, 200, "token"},
		{"GET", "/api/environments/default%2Fprod/links", "", 200, "links"},
		{"POST", "/api/environments/default/dev/tokens", `{"name":"ci","ttl":"2h"}`, 201, "token"},
		{"POST", "/api/environments/default/dev/tokens", `{"name":"svc","service":"openai"}`, 201, "token"},
		{"GET", "/api/environments/default/dev/tokens", "", 200, "tokens"},
		{"GET", "/api/environments/default/dev/setup", "", 200, "envLines"},
		{"POST", "/api/tokens/ensure", `{"env":"default/dev","name":"wt"}`, 200, "token"},
		{"GET", "/api/usage?by=service,key&range=7d", "", 200, "rows"},
		{"DELETE", "/api/environments/default/prod/links/openai", "", 200, "ok"},
		{"DELETE", "/api/services/internal", "", 200, "ok"},
		{"DELETE", "/api/environments/app/dev", "", 200, "ok"},
	}
	for _, rt := range routes {
		got := call(s, rt.method, rt.path, rt.body)
		if got.code != rt.want {
			t.Errorf("%s %s = %d, want %d: %s", rt.method, rt.path, got.code, rt.want, got.body)
			continue
		}
		if m := decodeBody(t, got); m[rt.has] == nil {
			t.Errorf("%s %s has no %q: %s", rt.method, rt.path, rt.has, got.body)
		}
		if strings.Contains(got.body, "sk-team") || strings.Contains(got.body, "sk-personal") {
			t.Errorf("%s %s returned a key's value: %s", rt.method, rt.path, got.body)
		}
		// With no key, every route is refused, in the API's error shape.
		w := do(s, rt.method, rt.path, rt.body, map[string]string{"Content-Type": "application/json"})
		var e APIError
		if w.Code != http.StatusUnauthorized || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error.Type != "keystub" {
			t.Errorf("%s %s with no key = %d %s", rt.method, rt.path, w.Code, w.Body.String())
		}
	}
	// Created kinds and the link's service token.
	tokens := decodeBody(t, call(s, "GET", "/api/environments/default/dev/tokens", ""))["tokens"].([]any)
	kinds := map[string]string{}
	for _, x := range tokens {
		tk := x.(map[string]any)
		svc, _ := tk["service"].(string)
		kinds[tk["name"].(string)] = tk["kind"].(string) + ":" + svc
	}
	if kinds["ci"] != "environment:" || kinds["svc"] != "service:openai" || kinds["wt"] != "environment:" {
		t.Fatalf("kinds = %v", kinds)
	}
	ca := do(s, "GET", "/api/ca.pem", "", admin)
	if ca.Code != http.StatusNotFound { // this server was made with no CA
		t.Fatalf("ca.pem = %d", ca.Code)
	}
}

func TestAPIErrors(t *testing.T) {
	s, _, keyID := apiRig(t)
	for _, c := range []struct {
		method, path, body string
		hdr                map[string]string
		want               int
		says               string
	}{
		// 415: a body that isn't JSON.
		{"POST", "/api/keys", `service=openai`, map[string]string{"Authorization": "Bearer admintoken", "Content-Type": "application/x-www-form-urlencoded"}, 415, "Content-Type"},
		// 413: too big.
		{"POST", "/api/keys", `{"value":"` + strings.Repeat("x", 300<<10) + `"}`, admin, 413, "too large"},
		// 400: not an object, a bad value, a missing field.
		{"POST", "/api/keys", `[1]`, admin, 400, "object"},
		{"POST", "/api/keys", `{"service":"openai","name":"x","value":"  "}`, admin, 400, "empty"},
		{"PATCH", "/api/environments/default/dev", `{}`, admin, 400, "limits"},
		{"PATCH", "/api/projects/default", `{}`, admin, 400, "limits"},
		{"PATCH", "/api/projects/default", `{"limits":{"dailyRequests":-1}}`, admin, 400, ""},
		{"PUT", "/api/environments/default/dev/links/openai", `{}`, admin, 400, "key"},
		{"POST", "/api/environments/default/dev/tokens", `{"name":"x","ttl":"forever"}`, admin, 400, "lifetime"},
		{"POST", "/api/environments/default/dev/tokens", `{"name":"a\nb"}`, admin, 400, "control"},
		// 404s.
		{"GET", "/api/keys/key_nope", "", admin, 404, "key_nope"},
		{"PATCH", "/api/projects/nope", `{"limits":null}`, admin, 404, ""},
		{"GET", "/api/environments/default/nope/links", "", admin, 404, "no environment"},
		{"DELETE", "/api/environments/default/prod/links/openai", "", admin, 404, "isn't linked"},
		{"GET", "/api/nope", "", admin, 404, "no such API route"},
		{"POST", "/api/services", `{"catalog":"nope"}`, admin, 404, "catalog"},
		{"GET", "/api/usage?range=1y", "", admin, 400, "range"},
		{"GET", "/api/usage?by=colour", "", admin, 400, "by takes"},
		// 405.
		{"POST", "/api/environments/default/dev/links", "", admin, 405, "method"},
		// 409s.
		{"POST", "/api/keys", `{"service":"openai","name":"TEAM","value":"x"}`, admin, 409, "already named"},
		{"POST", "/api/environments/default/prod/tokens", `{"name":"x","service":"openai"}`, admin, 409, "linked"},
		{"POST", "/api/services", `{"catalog":"openai"}`, admin, 409, "already exists"},
		{"POST", "/api/services", `{"name":"OpenAI","hosts":["evil.example"]}`, admin, 409, "catalog service"},
		{"PATCH", "/api/services/openai", `{"hosts":["evil.example"]}`, admin, 409, "catalog service"},
		// 403: a signed-in page's request from another site.
		{"POST", "/api/keys", `{}`, map[string]string{"Cookie": "keystub_session=admintoken", "Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}, 403, "cross-site"},
	} {
		w := do(s, c.method, c.path, c.body, c.hdr)
		var e APIError
		if w.Code != c.want || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Error.Type != "keystub" || !strings.Contains(e.Error.Message, c.says) {
			t.Errorf("%s %s = %d %s, want %d saying %q", c.method, c.path, w.Code, w.Body.String(), c.want, c.says)
		}
	}

	// A linked key: 409 naming where.
	w := do(s, "DELETE", "/api/keys/"+keyID, "", admin)
	var e APIError
	if w.Code != 409 || json.Unmarshal(w.Body.Bytes(), &e) != nil || len(e.Error.LinkedIn) != 1 || e.Error.LinkedIn[0] != dev {
		t.Fatalf("delete linked = %d %s", w.Code, w.Body.String())
	}
	// A custom service with saved keys can't be changed; without, it can.
	call(s, "POST", "/api/services", `{"name":"Internal","hosts":["api.internal.test"]}`)
	call(s, "POST", "/api/keys", `{"service":"internal","name":"k","value":"v"}`)
	if got := call(s, "PATCH", "/api/services/internal", `{"hosts":["evil.example"]}`); got.code != 409 || !strings.Contains(got.body, "saved keys") {
		t.Fatalf("patch with keys = %d %s", got.code, got.body)
	}
	if got := call(s, "POST", "/api/services", `{"name":"internal","hosts":["evil.example"]}`); got.code != 409 {
		t.Fatalf("custom over custom = %d %s", got.code, got.body)
	}
	// A null limits clears them; on an environment it is the only way.
	call(s, "PATCH", "/api/environments/default/dev", `{"limits":{"dailyRequests":5,"perMinute":1}}`)
	if got := call(s, "PATCH", "/api/environments/default/dev", `{"limits":null}`); got.code != 200 {
		t.Fatalf("clear env limits = %d %s", got.code, got.body)
	}
	call(s, "PATCH", "/api/projects/default", `{"limits":{"dailyRequests":5,"perMinute":1}}`)
	if got := call(s, "PATCH", "/api/projects/default", `{"limits":null}`); got.code != 200 {
		t.Fatalf("clear project limits = %d %s", got.code, got.body)
	}
	if got := call(s, "GET", "/api/projects", ""); !strings.Contains(got.body, `"limits":{"dailyRequests":0,"perMinute":0}`) {
		t.Fatalf("projects after clear = %s", got.body)
	}
}

// The CLI login routes are hosted only: here they answer 404 with no key,
// so the CLI can say to use one.
func TestAPICLILoginIsHostedOnly(t *testing.T) {
	s, _ := newServer(t)
	for _, p := range []string{"/api/cli/login", "/api/cli/login/poll"} {
		if w := do(s, "POST", p, `{}`, map[string]string{"Content-Type": "application/json"}); w.Code != http.StatusNotFound {
			t.Errorf("%s = %d", p, w.Code)
		}
	}
}

// What converting older data changed is shown on every page and in /api/me.
func TestConversionNotices(t *testing.T) {
	s, _ := newServer(t)
	s.Notices = []string{"token two (tk_two) in app/prod was revoked"}
	if w := do(s, "GET", "/tokens", "", cookie); !strings.Contains(w.Body.String(), "tk_two") {
		t.Fatalf("page has no notice: %s", w.Body.String())
	}
	me := decodeBody(t, call(s, "GET", "/api/me", ""))
	if ns, _ := me["notices"].([]any); len(ns) != 1 {
		t.Fatalf("me = %v", me)
	}
}

// A token with no kind allows nothing, so it isn't shown as an environment
// token.
func TestAPITokenWithNoKind(t *testing.T) {
	if k := apiToken(core.Token{ID: "tk"}, "active").Kind; k != "unknown" {
		t.Fatalf("kind = %q", k)
	}
}
