package core_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
)

var ctx = context.Background()

const dev = core.DefaultEnv

func addService(t *testing.T, e *core.Engine, id string) {
	t.Helper()
	p, _ := catalog.Preset(id)
	if err := e.AddService(ctx, p); err != nil {
		t.Fatal(err)
	}
}

func TestFreshInstallHasDefaultEnvironment(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	if _, ok := e.Environment(dev); !ok {
		t.Fatal("no default/dev environment")
	}
}

func TestRealKeysAreSealedAndPerEnvironment(t *testing.T) {
	e, dir := coretest.Engine(t, "")
	addService(t, e, "stripe")
	prod, err := e.AddEnvironment(ctx, "default", "prod", core.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(ctx, e, dev, "stripe", "sk_test_123"); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(ctx, e, prod.ID, "stripe", "sk_live_456"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), "sk_test_123") || strings.Contains(string(raw), "sk_live_456") {
		t.Fatal("real key stored in plain text")
	}
	if got, _ := e.RealKey(ctx, dev, "stripe"); got != "sk_test_123" {
		t.Fatalf("dev key = %q", got)
	}
	if got, _ := e.RealKey(ctx, prod.ID, "stripe"); got != "sk_live_456" {
		t.Fatalf("prod key = %q", got)
	}
	e2, _ := coretest.Engine(t, dir)
	if got, _ := e2.RealKey(ctx, prod.ID, "stripe"); got != "sk_live_456" {
		t.Fatalf("after reload = %q", got)
	}
	for _, ls := range e.LinkStatuses(dev) {
		if ls.Service.ID == "stripe" && (!ls.Linked || ls.Key.Secret != nil || ls.Key.Name != dev+" stripe") {
			t.Fatalf("status = %+v", ls)
		}
	}
}

func TestWrongMasterKeyFailsClearly(t *testing.T) {
	e, dir := coretest.Engine(t, "")
	addService(t, e, "openai")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	_ = os.Remove(filepath.Join(dir, "master.key"))
	e2, _ := coretest.Engine(t, dir)
	if _, err := e2.RealKey(ctx, dev, "openai"); err == nil || !strings.Contains(err.Error(), "different master key") {
		t.Fatalf("got %v", err)
	}
}

func TestTokenScopeRevokeAndExpiry(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	addService(t, e, "openai")
	addService(t, e, "github")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	now := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	e.SetClock(func() time.Time { return now })

	secret, tok, err := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "ci-agent", Service: "openai", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt == nil || !tok.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("expires = %v", tok.ExpiresAt)
	}
	g, err := e.Authorize(ctx, secret, "openai")
	if err != nil || g.Token.ID != tok.ID || g.Env.ID != dev || g.Project.ID != "default" {
		t.Fatalf("grant = %+v, %v", g, err)
	}
	if _, err := e.Authorize(ctx, secret, "github"); !errors.Is(err, core.ErrNotAllowed) {
		t.Fatalf("github through openai-only token: %v", err)
	}
	if _, err := e.Authorize(ctx, core.Compact(secret), "openai"); err != nil {
		t.Fatal("compact form rejected:", err)
	}
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "x", Service: "nope"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown service: %v", err)
	}

	now = now.Add(2 * time.Hour)
	if _, err := e.Authorize(ctx, secret, "openai"); !errors.Is(err, core.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if st := e.TokenState(tok.ID); st != "expired" {
		t.Fatalf("state = %s", st)
	}

	other, otherTok, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "ci"})
	if err := e.RevokeToken(ctx, otherTok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Authorize(ctx, other, "openai"); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("revoked token still works: %v", err)
	}
	if st := e.TokenState(otherTok.ID); st != "revoked" {
		t.Fatalf("state = %s", st)
	}
}

func TestLimitsAtEveryLevel(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	addService(t, e, "openai")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	if err := e.SetEnvironmentLimits(ctx, dev, core.Limits{DailyRequests: 3}); err != nil {
		t.Fatal(err)
	}
	a, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "a", Limits: core.Limits{DailyRequests: 1}})
	b, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "b"})
	if _, err := e.Authorize(ctx, a, "openai"); err != nil {
		t.Fatal(err)
	}
	var le *core.LimitError
	if _, err := e.Authorize(ctx, a, "openai"); !errors.As(err, &le) || le.Scope != "token a" {
		t.Fatalf("token limit: %v", err)
	}
	_, _ = e.Authorize(ctx, b, "openai")
	_, _ = e.Authorize(ctx, b, "openai")
	if _, err := e.Authorize(ctx, b, "openai"); !errors.As(err, &le) || le.Scope != "environment "+dev {
		t.Fatalf("environment limit: %v", err)
	}
	if n := e.UsedToday(ctx, "env:"+dev); n != 3 {
		t.Fatalf("environment used %d, want 3 (refused requests don't count)", n)
	}
}

func TestEnsureTokenReusesUntilRevoked(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	s1, t1, err := e.EnsureToken(ctx, dev, "wt-jepsen")
	if err != nil || !strings.HasPrefix(s1, core.TokenPrefix) {
		t.Fatalf("EnsureToken = %q, %v", s1, err)
	}
	if s2, _, _ := e.EnsureToken(ctx, dev, "wt-jepsen"); s2 != s1 {
		t.Fatal("made a second token for the same name")
	}
	_ = e.RevokeToken(ctx, t1.ID)
	if s3, _, _ := e.EnsureToken(ctx, dev, "wt-jepsen"); s3 == s1 {
		t.Fatal("returned a revoked token")
	}
	for _, tk := range e.Tokens("") {
		if tk.Token != nil {
			t.Fatal("Tokens() leaked a sealed token")
		}
	}
}

func TestProjectsAndEnvironments(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	p, err := e.AddProject(ctx, "My App", core.Limits{})
	if err != nil || p.ID != "my-app" {
		t.Fatalf("project = %+v, %v", p, err)
	}
	if _, err := e.AddProject(ctx, "my app", core.Limits{}); err != core.ErrNameTaken {
		t.Fatalf("duplicate: %v", err)
	}
	v, err := e.AddEnvironment(ctx, p.ID, "Prod", core.Limits{PerMinute: 60})
	if err != nil || v.ID != "my-app/prod" {
		t.Fatalf("env = %+v, %v", v, err)
	}
	if _, err := e.AddEnvironment(ctx, "nope", "dev", core.Limits{}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("env in missing project: %v", err)
	}
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: "nope/dev", Name: "x"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("token in missing env: %v", err)
	}
}

func TestHostMatchingAndServiceValidation(t *testing.T) {
	svc := core.Service{Hosts: []string{"api.openai.com", "*.convex.cloud"}}
	for host, want := range map[string]bool{
		"api.openai.com": true, "API.OpenAI.com.": true, "openai.com": false,
		"happy-cat.convex.cloud": true, "convex.cloud": false, "evilconvex.cloud": false,
	} {
		if got := svc.Matches(host); got != want {
			t.Errorf("Matches(%q) = %v, want %v", host, got, want)
		}
	}
	e, _ := coretest.Engine(t, "")
	base := core.Service{ID: "acme", Name: "Acme", Hosts: []string{"api.acme.com"}, Header: "Authorization"}
	for i, mutate := range []func(*core.Service){
		func(v *core.Service) { v.ID = "acme/v2" },
		func(v *core.Service) { v.EnvVars = []string{"NOT VALID"} },
		func(v *core.Service) { v.EnvVars = []string{"DEPLOY_KEY=prod:app|nokey"} },
		func(v *core.Service) { v.Format = "Bearer" },
		func(v *core.Service) { v.Hosts = []string{"api.acme.com@collector.example"} },
		func(v *core.Service) { v.Hosts = []string{"api.acme.com/path"} },
		func(v *core.Service) { v.Hosts = []string{"api.acme.com:443"} },
		func(v *core.Service) { v.Hosts = []string{"*."} },
	} {
		v := base
		mutate(&v)
		if err := e.AddService(ctx, v); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestRemoveServiceDropsItsKeys(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	addService(t, e, "openai")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	if err := e.RemoveService(ctx, "openai"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RealKey(ctx, dev, "openai"); !errors.Is(err, core.ErrNotLinked) {
		t.Fatalf("key survived its service: %v", err)
	}
}

func TestMissingRealKeyUsesNoLimit(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	addService(t, e, "openai")
	secret, tok, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "ci", Limits: core.Limits{DailyRequests: 1}})
	for range 3 {
		if _, err := e.Authorize(ctx, secret, "openai"); !errors.Is(err, core.ErrNotLinked) {
			t.Fatalf("no real key: %v", err)
		}
	}
	if n := e.UsedToday(ctx, "token:"+tok.ID); n != 0 {
		t.Fatalf("refused requests counted: %d", n)
	}
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	if _, err := e.Authorize(ctx, secret, "openai"); err != nil {
		t.Fatalf("after the key is set: %v", err)
	}
}

func TestNamesTooLongSayWhy(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	long := strings.Repeat("a", 70)
	if _, err := e.AddProject(ctx, long, core.Limits{}); err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("project: %v", err)
	}
	if _, err := e.AddEnvironment(ctx, "default", long, core.Limits{}); err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("environment: %v", err)
	}
}

// slowRepo holds PutToken until release is closed.
type slowRepo struct {
	core.Repository
	entered, release chan struct{}
}

func (r slowRepo) PutToken(ctx context.Context, tk core.Token) error {
	close(r.entered)
	<-r.release
	return r.Repository.PutToken(ctx, tk)
}

func TestWritesDontBlockTheDataPlane(t *testing.T) {
	sr := slowRepo{entered: make(chan struct{}), release: make(chan struct{})}
	e, _ := coretest.EngineWith(t, "", func(r core.Repository) core.Repository { sr.Repository = r; return sr })
	addService(t, e, "openai")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	wrote := make(chan struct{})
	go func() { _, _, _ = e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "slow"}); close(wrote) }()
	<-sr.entered
	done := make(chan struct{})
	go func() {
		_, _ = e.Authorize(ctx, core.TokenPrefix+"unknown", "openai")
		_, _ = e.ServiceForHost("api.openai.com")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the data plane waited on a storage write")
	}
	close(sr.release)
	<-wrote
}

// failRepo fails DeleteService.
type failRepo struct{ core.Repository }

func (failRepo) DeleteService(context.Context, string) error { return errors.New("disk full") }

func TestRemoveServiceFailingPartWayKeepsMemoryTrue(t *testing.T) {
	e, dir := coretest.EngineWith(t, "", func(r core.Repository) core.Repository { return failRepo{r} })
	addService(t, e, "openai")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	if err := e.RemoveService(ctx, "openai"); err == nil {
		t.Fatal("want the storage error")
	}
	if _, err := e.RealKey(ctx, dev, "openai"); !errors.Is(err, core.ErrNotLinked) {
		t.Fatalf("memory still has the deleted key: %v", err)
	}
	if _, ok := e.ServiceForHost("api.openai.com"); !ok {
		t.Fatal("memory dropped a service storage kept")
	}
	e2, _ := coretest.Engine(t, dir)
	if _, err := e2.RealKey(ctx, dev, "openai"); !errors.Is(err, core.ErrNotLinked) {
		t.Fatalf("storage and memory disagree: %v", err)
	}
}

func TestUnreadableKeyUsesNoLimit(t *testing.T) {
	e, dir := coretest.Engine(t, "")
	addService(t, e, "openai")
	_ = coretest.SetSecret(ctx, e, dev, "openai", "sk-real")
	_ = os.Remove(filepath.Join(dir, "master.key"))
	e2, _ := coretest.Engine(t, dir)
	secret, tok, _ := e2.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "ci"})
	if _, err := e2.Authorize(ctx, secret, "openai"); !errors.Is(err, core.ErrKeyUnreadable) {
		t.Fatalf("wrong master key: %v", err)
	}
	if n := e2.UsedToday(ctx, "token:"+tok.ID); n != 0 {
		t.Fatalf("refused request counted: %d", n)
	}
}

func TestHostsAreNormalised(t *testing.T) {
	s := core.Service{ID: "acme", Hosts: []string{" API.Acme.COM. ", "*.Acme.dev"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Hosts[0] != "api.acme.com" || s.Hosts[1] != "*.acme.dev" {
		t.Fatalf("hosts = %q", s.Hosts)
	}
}

func TestTokenServices(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	addService(t, e, "openai")
	addService(t, e, "github")
	addService(t, e, "stripe")
	for _, id := range []string{"openai", "github"} { // stripe has no key in dev
		if err := coretest.SetSecret(ctx, e, core.DefaultEnv, id, "real-"+id); err != nil {
			t.Fatal(err)
		}
	}
	all, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: core.DefaultEnv, Name: "all"})
	if _, svcs, _ := e.TokenServices(all); len(svcs) != 2 || svcs[0].ID != "github" || svcs[1].ID != "openai" {
		t.Fatalf("services with a key in dev, and only those: %+v", svcs)
	}
	scoped, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: core.DefaultEnv, Name: "scoped", Service: "github"})
	tk, svcs, err := e.TokenServices(core.Compact(scoped))
	if err != nil || tk.Name != "scoped" || tk.Token != nil || len(svcs) != 1 || svcs[0].ID != "github" {
		t.Fatalf("scoped: %+v %+v %v", tk, svcs, err)
	}
	short, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: core.DefaultEnv, Name: "short", TTL: time.Minute})
	gone, g, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: core.DefaultEnv, Name: "gone"})
	_ = e.RevokeToken(ctx, g.ID)
	e.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	if _, _, err := e.TokenServices(short); !errors.Is(err, core.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	for _, tok := range []string{gone, "sk-stub-00ff", "nope"} {
		if _, _, err := e.TokenServices(tok); !errors.Is(err, core.ErrUnknownKey) {
			t.Fatalf("%s: %v", tok, err)
		}
	}
}
