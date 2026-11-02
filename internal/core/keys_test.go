package core_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
)

// keysRig has openai and github, environments default/dev and
// default/prod, and saved openai keys "team" and "personal".
func keysRig(t *testing.T) (*core.Engine, core.SavedKey, core.SavedKey, string) {
	t.Helper()
	e, dir := coretest.Engine(t, "")
	addService(t, e, "openai")
	addService(t, e, "github")
	if _, err := e.AddEnvironment(ctx, "default", "prod", core.Limits{}); err != nil {
		t.Fatal(err)
	}
	team, err := e.AddKey(ctx, core.KeySpec{ServiceID: "openai", Name: "team", Value: "sk-team"})
	if err != nil {
		t.Fatal(err)
	}
	personal, err := e.AddKey(ctx, core.KeySpec{ServiceID: "openai", Name: "personal", Value: "sk-personal"})
	if err != nil {
		t.Fatal(err)
	}
	return e, team, personal, dir
}

const prod = "default/prod"

func linkSvc(t *testing.T, e *core.Engine, env, svc, keyID string) core.LinkResult {
	t.Helper()
	res, err := e.LinkKey(ctx, core.LinkSpec{EnvID: env, ServiceID: svc, KeyID: keyID})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func grantKey(t *testing.T, e *core.Engine, token, svc string) string {
	t.Helper()
	g, err := e.Authorize(ctx, token, svc)
	if err != nil {
		t.Fatalf("authorize %s: %v", svc, err)
	}
	return g.Key
}

func TestSavedKeysAreNeverReturnedOrStoredPlain(t *testing.T) {
	e, team, _, dir := keysRig(t)
	if team.Secret != nil || team.Version != 1 || !strings.HasPrefix(team.ID, "key_") {
		t.Fatalf("added = %+v", team)
	}
	for _, k := range e.Keys() {
		if k.Secret != nil {
			t.Fatal("Keys() returned a sealed value")
		}
	}
	if k, _ := e.Key(team.ID); k.Secret != nil {
		t.Fatal("Key() returned a sealed value")
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, "state.json")); strings.Contains(string(raw), "sk-team") {
		t.Fatal("a saved key is stored in plain text")
	}
}

func TestKeyNamesAreUniquePerService(t *testing.T) {
	e, _, personal, _ := keysRig(t)
	if _, err := e.AddKey(ctx, core.KeySpec{ServiceID: "openai", Name: "TEAM", Value: "x"}); !errors.Is(err, core.ErrNameTaken) {
		t.Fatalf("same name, other case: %v", err)
	}
	if _, err := e.AddKey(ctx, core.KeySpec{ServiceID: "github", Name: "team", Value: "x"}); err != nil {
		t.Fatalf("same name, other service: %v", err)
	}
	name := "team"
	if _, err := e.UpdateKey(ctx, personal.ID, core.KeyChange{Name: &name}); !errors.Is(err, core.ErrNameTaken) {
		t.Fatalf("rename onto a taken name: %v", err)
	}
	for _, bad := range []core.KeySpec{
		{ServiceID: "openai", Name: " ", Value: "x"},
		{ServiceID: "openai", Name: "ok", Value: "  "},
		{ServiceID: "openai", Name: "a\nb", Value: "x"},
		{ServiceID: "openai", Name: "ok", Value: "x", Limits: core.Limits{PerMinute: -1}},
	} {
		if _, err := e.AddKey(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := e.AddKey(ctx, core.KeySpec{ServiceID: "nope", Name: "x", Value: "x"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown service: %v", err)
	}
}

func TestOneKeyLinkedInTwoEnvironmentsRotatesOnce(t *testing.T) {
	e, team, _, dir := keysRig(t)
	linkSvc(t, e, dev, "openai", team.ID)
	linkSvc(t, e, prod, "openai", team.ID)
	devTok, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "d"})
	prodTok, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: prod, Name: "p"})
	if got := grantKey(t, e, devTok, "openai"); got != "sk-team" {
		t.Fatalf("dev = %q", got)
	}
	if got := grantKey(t, e, prodTok, "openai"); got != "sk-team" {
		t.Fatalf("prod = %q", got)
	}
	if got := e.KeyLinkedIn(team.ID); !slices.Equal(got, []string{dev, prod}) {
		t.Fatalf("linked in %v", got)
	}

	k, err := e.ReplaceKey(ctx, team.ID, "sk-team-2")
	if err != nil || k.Version != 2 {
		t.Fatalf("replace = %+v, %v", k, err)
	}
	for _, tok := range []string{devTok, prodTok} {
		if got := grantKey(t, e, tok, "openai"); got != "sk-team-2" {
			t.Fatalf("after replace: %q", got)
		}
	}
	e2, _ := coretest.Engine(t, dir)
	if got := grantKey(t, e2, prodTok, "openai"); got != "sk-team-2" {
		t.Fatalf("after reload: %q", got)
	}
}

func TestSwitchingALinkMovesItsTokens(t *testing.T) {
	e, team, personal, _ := keysRig(t)
	first := linkSvc(t, e, dev, "openai", team.ID)
	if !first.Created || first.Link.Version != 1 {
		t.Fatalf("first link = %+v", first)
	}
	envTok, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "env"})
	svcTok, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "svc", Service: "openai"})
	same := linkSvc(t, e, dev, "openai", team.ID)
	if same.Created || same.Link.Version != 1 {
		t.Fatalf("linking the same key again changed it: %+v", same)
	}
	sw, err := e.LinkKey(ctx, core.LinkSpec{EnvID: dev, ServiceID: "openai", KeyID: personal.ID, ServiceToken: true})
	if err != nil || sw.Created || sw.Link.Version != 2 || sw.Token != nil {
		t.Fatalf("switch = %+v, %v", sw, err)
	}
	for _, tok := range []string{envTok, svcTok} {
		if got := grantKey(t, e, tok, "openai"); got != "sk-personal" {
			t.Fatalf("after switch: %q", got)
		}
	}
	if len(e.Links(dev)) != 1 {
		t.Fatalf("links = %+v", e.Links(dev))
	}
	g, _ := e.Authorize(ctx, envTok, "openai")
	if g.SavedKey.ID != personal.ID || g.SavedKey.Secret != nil {
		t.Fatalf("grant names %+v", g.SavedKey)
	}
}

func TestServiceTokensOnlyWorkForTheirService(t *testing.T) {
	e, team, _, _ := keysRig(t)
	gh, _ := e.AddKey(ctx, core.KeySpec{ServiceID: "github", Name: "bot", Value: "ghp-bot"})
	linkSvc(t, e, dev, "openai", team.ID)
	linkSvc(t, e, dev, "github", gh.ID)
	svc, tok, err := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "only-openai", Service: "openai"})
	if err != nil || tok.Kind != core.KindService || tok.Service != "openai" {
		t.Fatalf("service token = %+v, %v", tok, err)
	}
	if got := grantKey(t, e, svc, "openai"); got != "sk-team" {
		t.Fatalf("own service: %q", got)
	}
	if _, err := e.Authorize(ctx, svc, "github"); !errors.Is(err, core.ErrNotAllowed) {
		t.Fatalf("other service: %v", err)
	}
	env, etok, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "everything"})
	if etok.Kind != core.KindEnvironment || etok.Service != "" {
		t.Fatalf("environment token = %+v", etok)
	}
	if grantKey(t, e, env, "openai") != "sk-team" || grantKey(t, e, env, "github") != "ghp-bot" {
		t.Fatal("environment token doesn't cover every linked service")
	}
	if _, svcs, _ := e.TokenServices(svc); len(svcs) != 1 || svcs[0].ID != "openai" {
		t.Fatalf("service token's services = %+v", svcs)
	}
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: prod, Name: "x", Service: "openai"}); !errors.Is(err, core.ErrNotLinked) {
		t.Fatalf("service token where it isn't linked: %v", err)
	}
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "x", Service: "nope"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("service token for an unknown service: %v", err)
	}
}

func TestEnsureTokenNeverHandsOutAServiceToken(t *testing.T) {
	e, team, _, _ := keysRig(t)
	res, err := e.LinkKey(ctx, core.LinkSpec{EnvID: dev, ServiceID: "openai", KeyID: team.ID, ServiceToken: true})
	if err != nil || res.Token.Name != "openai" {
		t.Fatalf("link = %+v, %v", res, err)
	}
	// A worktree folder called "openai" must not get the link's token,
	// nor any token EnsureToken didn't make.
	if _, _, err := e.EnsureToken(ctx, dev, "openai"); !errors.Is(err, core.ErrNameTaken) {
		t.Fatalf("ensure over a service token: %v", err)
	}
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "ci"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.EnsureToken(ctx, dev, "ci"); !errors.Is(err, core.ErrNameTaken) {
		t.Fatalf("ensure over a CI token: %v", err)
	}
	s, tok, err := e.EnsureToken(ctx, dev, "my-app")
	if err != nil || tok.Kind != core.KindEnvironment || tok.Principal != core.PrincipalRun {
		t.Fatalf("ensure = %+v, %v", tok, err)
	}
	if again, _, _ := e.EnsureToken(ctx, dev, "my-app"); again != s {
		t.Fatal("a second ensure made a new token")
	}
}

func TestUnlinkRefusesUntilLinkedAgain(t *testing.T) {
	e, team, _, _ := keysRig(t)
	linkSvc(t, e, dev, "openai", team.ID)
	env, envTok, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "env", Limits: core.Limits{DailyRequests: 5}})
	svc, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "svc", Service: "openai"})
	_ = grantKey(t, e, env, "openai")
	if err := e.Unlink(ctx, dev, "openai"); err != nil {
		t.Fatal(err)
	}
	if err := e.Unlink(ctx, dev, "openai"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("second unlink: %v", err)
	}
	for _, tok := range []string{env, svc} {
		if _, err := e.Authorize(ctx, tok, "openai"); !errors.Is(err, core.ErrNotLinked) {
			t.Fatalf("after unlink: %v", err)
		}
	}
	if n := e.UsedToday(ctx, "token:"+envTok.ID); n != 1 {
		t.Fatalf("refused requests counted: %d", n)
	}
	if _, svcs, _ := e.TokenServices(env); len(svcs) != 0 {
		t.Fatalf("services after unlink: %+v", svcs)
	}
	if _, ok := e.Key(team.ID); !ok {
		t.Fatal("unlinking deleted the saved key")
	}
	linkSvc(t, e, dev, "openai", team.ID)
	if got := grantKey(t, e, svc, "openai"); got != "sk-team" {
		t.Fatalf("linked again: %q", got)
	}
}

func TestLinkedKeysCantBeDeleted(t *testing.T) {
	e, team, personal, _ := keysRig(t)
	linkSvc(t, e, dev, "openai", team.ID)
	linkSvc(t, e, prod, "openai", team.ID)
	err := e.DeleteKey(ctx, team.ID)
	var inUse *core.KeyInUseError
	if !errors.As(err, &inUse) || !errors.Is(err, core.ErrKeyInUse) || !slices.Equal(inUse.Envs, []string{dev, prod}) {
		t.Fatalf("delete linked: %v", err)
	}
	if err := e.DeleteKey(ctx, personal.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteKey(ctx, personal.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	_ = e.Unlink(ctx, dev, "openai")
	_ = e.Unlink(ctx, prod, "openai")
	if err := e.DeleteKey(ctx, team.ID); err != nil {
		t.Fatalf("delete after unlinking: %v", err)
	}
}

func TestLinkChecks(t *testing.T) {
	e, team, _, _ := keysRig(t)
	for _, spec := range []core.LinkSpec{
		{EnvID: "default/nope", ServiceID: "openai", KeyID: team.ID},
		{EnvID: dev, ServiceID: "nope", KeyID: team.ID},
		{EnvID: dev, ServiceID: "openai", KeyID: "key_nope"},
	} {
		if _, err := e.LinkKey(ctx, spec); !errors.Is(err, core.ErrNotFound) {
			t.Errorf("%+v: %v", spec, err)
		}
	}
	if _, err := e.LinkKey(ctx, core.LinkSpec{EnvID: dev, ServiceID: "github", KeyID: team.ID}); err == nil || !strings.Contains(err.Error(), "is for openai") {
		t.Fatalf("an openai key for github: %v", err)
	}
	if len(e.Links("")) != 0 {
		t.Fatal("a refused link was kept")
	}
}

func TestNewLinkMakesAServiceToken(t *testing.T) {
	e, team, _, _ := keysRig(t)
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "openai"}); err != nil {
		t.Fatal(err)
	}
	res, err := e.LinkKey(ctx, core.LinkSpec{EnvID: dev, ServiceID: "openai", KeyID: team.ID, ServiceToken: true})
	if err != nil || res.Token == nil || res.Token.Name != "openai-2" || res.Token.Kind != core.KindService || !strings.HasPrefix(res.Secret, core.TokenPrefix) {
		t.Fatalf("link = %+v, %v", res, err)
	}
	if grantKey(t, e, res.Secret, "openai") != "sk-team" {
		t.Fatal("the link's token doesn't work")
	}
	// A name asked for that is taken fails before anything is written.
	if _, err := e.LinkKey(ctx, core.LinkSpec{EnvID: prod, ServiceID: "openai", KeyID: team.ID, ServiceToken: true, TokenName: "x"}); err != nil {
		t.Fatal(err)
	}
	_ = e.Unlink(ctx, prod, "openai")
	if _, err := e.LinkKey(ctx, core.LinkSpec{EnvID: prod, ServiceID: "openai", KeyID: team.ID, ServiceToken: true, TokenName: "x"}); !errors.Is(err, core.ErrNameTaken) {
		t.Fatalf("taken token name: %v", err)
	}
	if len(e.Links(prod)) != 0 {
		t.Fatal("linked although its token name was taken")
	}
}

func TestSavedKeyLimitsCoverEveryEnvironmentAndCountOnlyWhenSet(t *testing.T) {
	e, team, _, _ := keysRig(t)
	linkSvc(t, e, dev, "openai", team.ID)
	linkSvc(t, e, prod, "openai", team.ID)
	d, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: dev, Name: "d"})
	p, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: prod, Name: "p"})
	_ = grantKey(t, e, d, "openai")
	if n := e.UsedToday(ctx, "key:"+team.ID); n != 0 {
		t.Fatalf("a key with no limit was counted: %d", n)
	}
	l := core.Limits{DailyRequests: 2}
	if _, err := e.UpdateKey(ctx, team.ID, core.KeyChange{Limits: &l}); err != nil {
		t.Fatal(err)
	}
	_ = grantKey(t, e, d, "openai")
	_ = grantKey(t, e, p, "openai")
	var le *core.LimitError
	if _, err := e.Authorize(ctx, d, "openai"); !errors.As(err, &le) || le.Scope != "the saved key for openai" || le.Kind != "daily" {
		t.Fatalf("shared key limit: %v", err)
	}
	if n := e.UsedToday(ctx, "key:"+team.ID); n != 2 {
		t.Fatalf("key used %d", n)
	}
	// The refusal counted nowhere: dev's project, environment and token
	// are where they were before it.
	devTok, _ := tokenByName(e, dev, "d")
	for scope, want := range map[string]int{"project:default": 3, "env:" + dev: 2, "token:" + devTok.ID: 2} {
		if n := e.UsedToday(ctx, scope); n != want {
			t.Errorf("%s used %d, want %d", scope, n, want)
		}
	}
}

func tokenByName(e *core.Engine, env, name string) (core.Token, bool) {
	for _, t := range e.Tokens(env) {
		if t.Name == name {
			return t, true
		}
	}
	return core.Token{}, false
}

func TestDeleteEnvironment(t *testing.T) {
	e, team, _, _ := keysRig(t)
	linkSvc(t, e, prod, "openai", team.ID)
	tok, _, _ := e.CreateToken(ctx, core.TokenSpec{EnvID: prod, Name: "p"})
	_, cred := link(t, e, "box", dev, prod)
	if err := e.DeleteEnvironment(ctx, prod); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Environment(prod); ok {
		t.Fatal("still there")
	}
	if _, err := e.Authorize(ctx, tok, "openai"); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("its token: %v", err)
	}
	if len(e.Links(prod)) != 0 || len(e.KeyLinkedIn(team.ID)) != 0 {
		t.Fatal("its links stayed")
	}
	if _, ok := e.Key(team.ID); !ok {
		t.Fatal("the saved key went with it")
	}
	if ms := e.Machines(); len(ms) != 1 || !slices.Equal(ms[0].Envs, []string{dev}) {
		t.Fatalf("machines = %+v", ms)
	}
	// Made again, the environment brings back none of it.
	if _, err := e.AddEnvironment(ctx, "default", "prod", core.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, prod, "x"); !errors.Is(err, core.ErrNotAllowed) {
		t.Fatalf("machine in the new prod: %v", err)
	}
	if err := e.DeleteEnvironment(ctx, prod+"x"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestRemoveServiceDropsItsSavedKeys(t *testing.T) {
	e, team, _, _ := keysRig(t)
	linkSvc(t, e, dev, "openai", team.ID)
	if err := e.RemoveService(ctx, "openai"); err != nil {
		t.Fatal(err)
	}
	if len(e.Keys()) != 0 || len(e.Links("")) != 0 {
		t.Fatalf("keys %+v links %+v", e.Keys(), e.Links(""))
	}
}

func TestUpgradeOldTokens(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	for _, c := range []struct {
		services      []string
		kind, service string
		revoked       bool
	}{
		{nil, core.KindEnvironment, "", false},
		{[]string{"openai"}, core.KindService, "openai", false},
		{[]string{"openai", "github"}, core.KindEnvironment, "", true},
	} {
		got, revoked := core.OldToken{Token: core.Token{ID: "tk"}, Services: c.services}.Upgrade(now)
		if got.Kind != c.kind || got.Service != c.service || revoked != c.revoked || (got.RevokedAt != nil) != c.revoked {
			t.Errorf("%v: %+v %v", c.services, got, revoked)
		}
	}
	if all, _ := (core.OldToken{Token: core.Token{ID: "tk"}}).Upgrade(now); all.Principal != core.PrincipalRun {
		t.Fatalf("an unrestricted old token isn't marked as keystub run's: %+v", all)
	}
	if m, _ := (core.OldToken{Token: core.Token{ID: "tk", Principal: "machine:m_1"}}).Upgrade(now); m.Principal != "machine:m_1" {
		t.Fatalf("a machine's token lost its principal: %+v", m)
	}
	// A multi-service token never reaches a service it wasn't limited to.
	two, _ := core.OldToken{Token: core.Token{ID: "tk"}, Services: []string{"openai", "github"}}.Upgrade(now)
	if two.Usable(now) {
		t.Fatal("a token limited to two services is still usable")
	}
	// Already revoked or expired: revoked as it was, and nothing to report.
	old, revoked := core.OldToken{Token: core.Token{ID: "tk", RevokedAt: &past}, Services: []string{"a", "b"}}.Upgrade(now)
	if revoked || !old.RevokedAt.Equal(past) {
		t.Fatalf("already revoked: %+v %v", old, revoked)
	}
	if _, revoked := (core.OldToken{Token: core.Token{ID: "tk", ExpiresAt: &past}, Services: []string{"a", "b"}}).Upgrade(now); revoked {
		t.Fatal("reported an expired token")
	}
	if got, _ := (core.OldToken{Token: core.Token{Kind: core.KindService, Service: "x"}}).Upgrade(now); got.Service != "x" {
		t.Error("upgraded a new token")
	}

	// The notes name each token revoked and the live ones marked as
	// keystub run's, so an operator can check them.
	ts, notes := core.UpgradeTokens([]core.OldToken{
		{Token: core.Token{ID: "tk_all", Name: "all", EnvID: "app/dev"}},
		{Token: core.Token{ID: "tk_dead", Name: "dead", EnvID: "app/dev", RevokedAt: &past}},
		{Token: core.Token{ID: "tk_m", Name: "box/wt", EnvID: "app/dev", Principal: "machine:m_1"}},
		{Token: core.Token{ID: "tk_two", Name: "two", EnvID: "app/dev"}, Services: []string{"a", "b"}},
	}, now)
	if len(ts) != 4 || len(notes) != 2 || !strings.Contains(notes[0], "tk_two") || !strings.Contains(notes[1], "all (tk_all) in app/dev") ||
		strings.Contains(notes[1], "tk_dead") || strings.Contains(notes[1], "tk_m") {
		t.Fatalf("notes = %q", notes)
	}
}

func TestUnknownTokenKindsAllowNothing(t *testing.T) {
	for _, tok := range []core.Token{{}, {Kind: "machine"}, {Kind: "Environment"}} {
		if tok.Allows("openai") {
			t.Errorf("%q allows openai", tok.Kind)
		}
	}
}
