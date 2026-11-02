package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

var bg = context.Background()

const dev = core.DefaultEnv

func newServer(t *testing.T) (*Server, *core.Engine) {
	t.Helper()
	st, _ := coretest.Engine(t, "")
	lg, _ := reqlog.Open("", 10)
	s, err := New(&Server{Core: st, Log: lg, Token: "admintoken"})
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

func do(s *Server, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

var (
	cookie = map[string]string{"Cookie": "keystub_session=admintoken"}
	form   = map[string]string{"Cookie": "keystub_session=admintoken", "Content-Type": "application/x-www-form-urlencoded"}
	admin  = map[string]string{"Authorization": "Bearer admintoken", "Content-Type": "application/json"}
)

func TestPagesNeedToken(t *testing.T) {
	s, _ := newServer(t)
	if w := do(s, "GET", "/services", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(s, "GET", "/login?token=wrong", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", w.Code)
	}
	w := do(s, "GET", "/login?token=admintoken", "", nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Set-Cookie"), "keystub_session=admintoken") {
		t.Fatalf("login: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	for _, p := range []string{"/services", "/keys", "/tokens", "/projects", "/requests", "/setup"} {
		if w := do(s, "GET", p, "", cookie); w.Code != http.StatusOK {
			t.Fatalf("%s: %d\n%s", p, w.Code, w.Body.String())
		}
	}
}

func TestRealKeysAreSetPerEnvironment(t *testing.T) {
	s, st := newServer(t)
	p, _ := catalog.Preset("openai")
	_ = st.AddService(bg, p)
	prod, _ := st.AddEnvironment(bg, "default", "prod", core.Limits{})

	body := url.Values{"key": {"sk-prod"}, "env": {prod.ID}}.Encode()
	h := map[string]string{"Origin": "https://evil.example"}
	for k, v := range form {
		h[k] = v
	}
	if w := do(s, "POST", "/services/openai/key", body, h); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", w.Code)
	}
	h["Origin"], h["Sec-Fetch-Site"] = "null", "same-origin" // browsers may send Origin: null
	if w := do(s, "POST", "/services/openai/key", body, h); w.Code != http.StatusSeeOther {
		t.Fatalf("same-origin post: %d", w.Code)
	}
	if got, _ := st.RealKey(bg, prod.ID, "openai"); got != "sk-prod" {
		t.Fatalf("prod key = %q", got)
	}
	if _, err := st.RealKey(bg, dev, "openai"); err == nil {
		t.Fatal("setting prod also set dev")
	}
	w := do(s, "GET", "/services?env="+url.QueryEscape(prod.ID), "", cookie)
	if strings.Contains(w.Body.String(), "sk-prod") {
		t.Fatal("services page shows the real key")
	}
}

func TestTokenForm(t *testing.T) {
	s, st := newServer(t)
	p, _ := catalog.Preset("openai")
	_ = st.AddService(bg, p)
	body := url.Values{"env": {dev}, "name": {"run-1"}, "service": {"openai"}, "dailyRequests": {"10"}, "ttl": {"2h"}}.Encode()
	if w := do(s, "POST", "/tokens", body, form); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no saved key linked") {
		t.Fatalf("service token for a service not linked: %d", w.Code)
	}
	_ = coretest.SetSecret(bg, st, dev, "openai", "sk-real")
	w := do(s, "POST", "/tokens", body, form)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), core.TokenPrefix) {
		t.Fatalf("create: %d\n%s", w.Code, w.Body.String())
	}
	toks := st.Tokens(dev)
	if len(toks) != 1 || toks[0].Limits.DailyRequests != 10 || toks[0].ExpiresAt == nil || toks[0].Kind != core.KindService || toks[0].Service != "openai" {
		t.Fatalf("tokens = %+v", toks)
	}
	body = url.Values{"env": {dev}, "name": {"bad"}, "ttl": {"soon"}}.Encode()
	if w := do(s, "POST", "/tokens", body, form); w.Code != http.StatusBadRequest {
		t.Fatalf("bad lifetime: %d", w.Code)
	}
	page := do(s, "GET", "/tokens?env="+url.QueryEscape(dev), "", cookie).Body.String()
	if !strings.Contains(page, "run-1") || strings.Contains(page, toks[0].TokenHash) {
		t.Fatal("tokens page")
	}
}

func TestEnsureAndServicesAPI(t *testing.T) {
	s, st := newServer(t)
	p, _ := catalog.Preset("github")
	_ = st.AddService(bg, p)
	_ = coretest.SetSecret(bg, st, dev, "github", "ghp_real")

	var a, b TokenResponse
	_ = json.Unmarshal(do(s, "POST", "/api/tokens/ensure", `{"env":"default/dev","name":"wt-a"}`, admin).Body.Bytes(), &a)
	_ = json.Unmarshal(do(s, "POST", "/api/tokens/ensure", `{"name":"wt-a"}`, admin).Body.Bytes(), &b)
	if a.Token == "" || a.Token != b.Token || a.Env != dev {
		t.Fatalf("ensure gave %+v then %+v", a, b)
	}
	if w := do(s, "POST", "/api/tokens/ensure", `{"env":"nope/x","name":"wt"}`, admin); w.Code != http.StatusNotFound {
		t.Fatalf("missing env: %d", w.Code)
	}
	body := do(s, "GET", "/api/services", "", admin).Body.String()
	if strings.Contains(body, "ghp_real") || !strings.Contains(body, "GH_TOKEN") || !strings.HasPrefix(body, `{"services":[`) {
		t.Fatalf("services API: %s", body)
	}
	if w := do(s, "GET", "/api/services", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("API without token: %d", w.Code)
	}
}

func TestProjectsPage(t *testing.T) {
	s, st := newServer(t)
	if w := do(s, "POST", "/projects", url.Values{"name": {"My App"}, "dailyRequests": {"1000"}}.Encode(), form); w.Code != http.StatusSeeOther {
		t.Fatalf("add project: %d", w.Code)
	}
	if w := do(s, "POST", "/environments", url.Values{"project": {"my-app"}, "name": {"prod"}, "perMinute": {"60"}}.Encode(), form); w.Code != http.StatusSeeOther {
		t.Fatalf("add env: %d", w.Code)
	}
	v, ok := st.Environment("my-app/prod")
	if !ok || v.Limits.PerMinute != 60 {
		t.Fatalf("env = %+v", v)
	}
	if w := do(s, "POST", "/environments/limits", url.Values{"id": {"my-app/prod"}, "dailyRequests": {"-3"}}.Encode(), form); w.Code != http.StatusBadRequest {
		t.Fatalf("negative limit: %d", w.Code)
	}
}

func TestParseTTL(t *testing.T) {
	for in, ok := range map[string]bool{"": true, "30m": true, "2h": true, "7d": true, "0d": false, "soon": false, "-1h": false, "3650d": true, "3651d": false, "213504d": false, "99999h": false} {
		if _, err := parseTTL(in); (err == nil) != ok {
			t.Errorf("parseTTL(%q) err = %v", in, err)
		}
	}
}

func TestUnknownEnvironmentIsRefusedNotRedirected(t *testing.T) {
	s, st := newServer(t)
	p, _ := catalog.Preset("stripe")
	_ = st.AddService(bg, p)
	body := url.Values{"key": {"sk_live_real"}, "env": {"default/prd"}}.Encode()
	if w := do(s, "POST", "/services/stripe/key", body, form); w.Code != http.StatusBadRequest {
		t.Fatalf("key for a missing environment: %d", w.Code)
	}
	if _, err := st.RealKey(bg, dev, "stripe"); err == nil {
		t.Fatal("the key landed in default/dev")
	}
	body = url.Values{"env": {"default/prd"}, "name": {"x"}}.Encode()
	if w := do(s, "POST", "/tokens", body, form); w.Code != http.StatusBadRequest || len(st.Tokens(dev)) != 0 {
		t.Fatalf("token for a missing environment: %d", w.Code)
	}
	if len(st.Keys()) != 0 {
		t.Fatal("a key was saved for a missing environment")
	}
	if w := do(s, "GET", "/api/environments/default/prd/links", "", admin); w.Code != http.StatusNotFound {
		t.Fatalf("links API for a missing environment: %d", w.Code)
	}
}

func TestEnvironmentLinksAreEscapedOnce(t *testing.T) {
	s, _ := newServer(t)
	page := do(s, "GET", "/services?env="+url.QueryEscape(dev), "", cookie).Body.String()
	if strings.Contains(page, "%252") || !strings.Contains(strings.ToLower(page), "/tokens?env=default%2fdev") {
		t.Fatalf("nav links are not escaped once:\n%s", page)
	}
}

func TestMachinesPage(t *testing.T) {
	s, st := newServer(t)
	start, err := st.StartLink("devbox", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	page := do(s, "GET", "/machines", "", cookie).Body.String()
	if !strings.Contains(page, "devbox") || !strings.Contains(page, "10.0.0.5") || strings.Contains(page, start.UserCode) {
		t.Fatalf("pending list (must not show the code):\n%s", page)
	}
	if w := do(s, "POST", "/machines/approve", url.Values{"code": {"BBBB-BBBB"}, "envs": {dev}}.Encode(), form); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: %d", w.Code)
	}
	if w := do(s, "POST", "/machines/approve", url.Values{"code": {start.UserCode}}.Encode(), form); w.Code != http.StatusBadRequest {
		t.Fatalf("no environment: %d", w.Code)
	}
	// Typing the code shows which machine it is first.
	w := do(s, "POST", "/machines/check", url.Values{"code": {start.UserCode}}.Encode(), form)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "belongs to <strong>devbox</strong>") || !strings.Contains(w.Body.String(), "10.0.0.5") || !strings.Contains(w.Body.String(), "only limit") {
		t.Fatalf("check: %d\n%s", w.Code, w.Body.String())
	}
	if _, _, err := st.PollLink(start.DeviceCode); !errors.Is(err, core.ErrLinkPending) {
		t.Fatalf("checking approved it: %v", err)
	}
	if w := do(s, "POST", "/machines/check", url.Values{"code": {"BBBB-BBBB"}}.Encode(), form); w.Code != http.StatusBadRequest {
		t.Fatalf("check a wrong code: %d", w.Code)
	}
	w = do(s, "POST", "/machines/approve", url.Values{"code": {start.UserCode}, "envs": {dev}, "action": {"approve"}}.Encode(), form)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "is linked") {
		t.Fatalf("approve: %d\n%s", w.Code, w.Body.String())
	}
	m, cred, err := st.PollLink(start.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.EnsureMachineToken(bg, cred, "", "wt"); err != nil {
		t.Fatal(err)
	}
	page = do(s, "GET", "/machines", "", cookie).Body.String()
	if !strings.Contains(page, m.ID) || !strings.Contains(page, "<td>1</td>") {
		t.Fatalf("linked list:\n%s", page)
	}
	if w := do(s, "POST", "/machines/"+m.ID+"/revoke", "", form); w.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", w.Code)
	}
	if ts := st.Tokens(dev); len(ts) != 1 || ts[0].RevokedAt == nil {
		t.Fatalf("machine's token still live: %+v", ts)
	}

	// Turning one down.
	start, _ = st.StartLink("stranger", "")
	if w := do(s, "POST", "/machines/approve", url.Values{"code": {start.UserCode}, "action": {"deny"}}.Encode(), form); w.Code != http.StatusSeeOther {
		t.Fatalf("deny: %d", w.Code)
	}
	if _, _, err := st.PollLink(start.DeviceCode); err == nil {
		t.Fatal("a turned-down machine got a credential")
	}
	// Or from the list, without the code.
	start, _ = st.StartLink("stranger", "10.0.0.6")
	id := st.PendingLinks()[0].ID
	if page := do(s, "GET", "/machines", "", cookie).Body.String(); !strings.Contains(page, "/machines/pending/"+id+"/deny") {
		t.Fatalf("no Turn down on the row:\n%s", page)
	}
	if w := do(s, "POST", "/machines/pending/"+id+"/deny", "", form); w.Code != http.StatusSeeOther {
		t.Fatalf("deny from the list: %d", w.Code)
	}
	if _, _, err := st.PollLink(start.DeviceCode); err == nil {
		t.Fatal("a turned-down machine got a credential")
	}
	if w := do(s, "POST", "/machines/pending/"+id+"/deny", "", form); w.Code != http.StatusBadRequest {
		t.Fatalf("deny a gone request: %d", w.Code)
	}
	// Pages need the admin token.
	if w := do(s, "POST", "/machines/approve", url.Values{"code": {start.UserCode}}.Encode(), nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", w.Code)
	}
}

func TestMachinesConfirmKeepsTheOpenEnvironment(t *testing.T) {
	s, st := newServer(t)
	if _, err := st.AddEnvironment(bg, "default", "prod", core.Limits{}); err != nil {
		t.Fatal(err)
	}
	start, _ := st.StartLink("devbox", "10.0.0.5")
	w := do(s, "POST", "/machines/check", url.Values{"code": {start.UserCode}, "env": {"default/prod"}}.Encode(), form)
	body := w.Body.String()
	if !strings.Contains(body, `value="default/prod" checked`) || strings.Contains(body, `value="`+dev+`" checked`) || !strings.Contains(body, `name="env" value="default/prod"`) {
		t.Fatalf("confirm step lost the open environment:\n%s", body)
	}
}

func TestMachinesListIsCapped(t *testing.T) {
	s, st := newServer(t)
	for i := range maxPendingRows + 5 {
		if _, err := st.StartLink("m", fmt.Sprintf("10.%d.%d.1", i/256, i%256)); err != nil {
			t.Fatal(err)
		}
	}
	if page := do(s, "GET", "/machines", "", cookie).Body.String(); !strings.Contains(page, "And 5 more waiting") || strings.Count(page, "/deny") != maxPendingRows {
		t.Fatal("pending list not capped")
	}
}

// failingTokens fails PutToken while *fail is set.
type failingTokens struct {
	core.Repository
	fail *bool
}

func (f failingTokens) PutToken(ctx context.Context, t core.Token) error {
	if *f.fail {
		return errors.New("disk full")
	}
	return f.Repository.PutToken(ctx, t)
}

func TestRetryRevokeIsOffered(t *testing.T) {
	var fail bool
	st, _ := coretest.EngineWith(t, "", func(r core.Repository) core.Repository { return failingTokens{r, &fail} })
	lg, _ := reqlog.Open("", 10)
	s, err := New(&Server{Core: st, Log: lg, Token: "admintoken"})
	if err != nil {
		t.Fatal(err)
	}
	start, _ := st.StartLink("box", "")
	m, _ := st.ApproveLink(bg, start.UserCode, []string{dev})
	_, cred, _ := st.PollLink(start.DeviceCode)
	if _, _, err := st.EnsureMachineToken(bg, cred, "", "wt"); err != nil {
		t.Fatal(err)
	}
	fail = true
	if w := do(s, "POST", "/machines/"+m.ID+"/revoke", "", form); w.Code != http.StatusBadRequest {
		t.Fatalf("revoke with a failing store: %d", w.Code)
	}
	if page := do(s, "GET", "/machines", "", cookie).Body.String(); !strings.Contains(page, "Retry revoke") {
		t.Fatalf("no retry offered:\n%s", page)
	}
	fail = false
	if w := do(s, "POST", "/machines/"+m.ID+"/revoke", "", form); w.Code != http.StatusSeeOther {
		t.Fatalf("retry: %d", w.Code)
	}
	if page := do(s, "GET", "/machines", "", cookie).Body.String(); strings.Contains(page, "Retry revoke") {
		t.Fatal("retry still offered after it worked")
	}
}

func TestFailedApprovalKeepsTheTicks(t *testing.T) {
	s, st := newServer(t)
	if _, err := st.AddEnvironment(bg, "default", "prod", core.Limits{}); err != nil {
		t.Fatal(err)
	}
	start, _ := st.StartLink("devbox", "10.0.0.5")
	w := do(s, "POST", "/machines/approve", url.Values{"code": {start.UserCode}, "envs": {"default/prod", "gone/env"}, "action": {"approve"}}.Encode(), form)
	body := w.Body.String()
	if w.Code != http.StatusBadRequest || !strings.Contains(body, `value="default/prod" checked`) || strings.Contains(body, `value="`+dev+`" checked`) {
		t.Fatalf("%d, ticks lost:\n%s", w.Code, body)
	}
}

func TestFailedApprovalWithNoneTickedStaysUnticked(t *testing.T) {
	s, st := newServer(t)
	start, _ := st.StartLink("devbox", "10.0.0.5")
	w := do(s, "POST", "/machines/approve", url.Values{"code": {start.UserCode}, "action": {"approve"}}.Encode(), form)
	if body := w.Body.String(); w.Code != http.StatusBadRequest || strings.Contains(body, `value="`+dev+`" checked`) || !strings.Contains(body, start.UserCode) {
		t.Fatalf("%d, the default came back ticked:\n%s", w.Code, body)
	}
}
