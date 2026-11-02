package core_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
)

// link runs the whole device-code flow and returns the machine and its
// credential.
func link(t *testing.T, e *core.Engine, name string, envs ...string) (core.Machine, string) {
	t.Helper()
	st, err := e.StartLink(name, "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.PollLink(st.DeviceCode); !errors.Is(err, core.ErrLinkPending) {
		t.Fatalf("before approval: %v", err)
	}
	// The admin types the code, in whatever case and spacing.
	typed := strings.ToLower(strings.ReplaceAll(st.UserCode, "-", " "))
	if _, err := e.ApproveLink(ctx, typed, envs); err != nil {
		t.Fatal(err)
	}
	m, cred, err := e.PollLink(st.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	return m, cred
}

func TestLinkFlow(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	st, _ := e.StartLink("devbox", "10.0.0.5")
	if p := e.PendingLinks(); len(p) != 1 || p[0].Name != "devbox" || p[0].From != "10.0.0.5" {
		t.Fatalf("pending = %+v", p)
	}
	if len(st.UserCode) != 9 || st.UserCode[4] != '-' || len(st.DeviceCode) != 64 {
		t.Fatalf("codes = %+v", st)
	}
	if _, err := e.ApproveLink(ctx, st.UserCode, nil); err == nil {
		t.Fatal("approved with no environment")
	}
	if _, err := e.ApproveLink(ctx, st.UserCode, []string{"nope/dev"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown env: %v", err)
	}
	if _, err := e.ApproveLink(ctx, "BBBB-BBBB", []string{core.DefaultEnv}); err == nil {
		t.Fatal("approved a code nobody is waiting with")
	}
	m, err := e.ApproveLink(ctx, st.UserCode, []string{core.DefaultEnv})
	if err != nil || m.CredentialHash != "" || m.Name != "devbox" {
		t.Fatalf("approve: %+v %v", m, err)
	}
	if _, err := e.ApproveLink(ctx, st.UserCode, []string{core.DefaultEnv}); err == nil {
		t.Fatal("approved twice")
	}
	got, cred, err := e.PollLink(st.DeviceCode)
	if err != nil || got.ID != m.ID || !strings.HasPrefix(cred, core.MachinePrefix) {
		t.Fatalf("poll: %+v %q %v", got, cred, err)
	}
	// The credential is handed over once.
	if _, _, err := e.PollLink(st.DeviceCode); !errors.Is(err, core.ErrLinkExpired) {
		t.Fatalf("second poll: %v", err)
	}
	if ms := e.Machines(); len(ms) != 1 || ms[0].CredentialHash != "" {
		t.Fatalf("machines = %+v", ms)
	}
	if mm, err := e.Machine(cred); err != nil || mm.ID != m.ID {
		t.Fatalf("lookup: %v", err)
	}
	if p := e.PendingLinks(); len(p) != 0 {
		t.Fatalf("still pending: %+v", p)
	}
}

func TestMachinesPersist(t *testing.T) {
	e, dir := coretest.Engine(t, "")
	m, cred := link(t, e, "devbox", core.DefaultEnv)
	e2, _ := coretest.Engine(t, dir)
	if got, err := e2.Machine(cred); err != nil || got.ID != m.ID || got.Envs[0] != core.DefaultEnv {
		t.Fatalf("after reopen: %+v %v", got, err)
	}
}

func TestLinkDeniedAndExpired(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	st, _ := e.StartLink("box", "")
	if err := e.DenyLink(st.UserCode); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.PollLink(st.DeviceCode); !errors.Is(err, core.ErrLinkDenied) {
		t.Fatalf("denied: %v", err)
	}
	st, _ = e.StartLink("box", "")
	e.SetClock(func() time.Time { return time.Now().Add(core.LinkLifetime + time.Second) })
	if _, _, err := e.PollLink(st.DeviceCode); !errors.Is(err, core.ErrLinkExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := e.ApproveLink(ctx, st.UserCode, []string{core.DefaultEnv}); err == nil {
		t.Fatal("approved an expired request")
	}
	if _, _, err := e.PollLink("not-a-device-code"); !errors.Is(err, core.ErrLinkExpired) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestLinkRequestsAreCapped(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	var err error
	n := 0
	for ; n < 20000 && err == nil; n++ {
		_, err = e.StartLink("spam", fmt.Sprintf("10.%d.%d.1", n/256, n%256))
	}
	if !errors.Is(err, core.ErrTooManyLinks) || n != 10001 {
		t.Fatalf("got %v after %d", err, n)
	}
	// One address gets 3, so it can't take every slot from the others.
	e, _ = coretest.Engine(t, "")
	var spam []string
	for i := range 3 {
		st, err := e.StartLink("spam", "10.9.9.9")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		spam = append(spam, st.DeviceCode)
	}
	if _, err := e.StartLink("spam", "10.9.9.9"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatalf("a 4th from one address: %v", err)
	}
	if _, err := e.StartLink("real", "10.1.1.1"); err != nil {
		t.Fatalf("another address: %v", err)
	}
	// Turned down, a request leaves the list at once, holding no slot, and
	// its poll keeps being told no.
	for _, p := range e.PendingLinks() {
		if p.From == "10.9.9.9" {
			if err := e.DenyLinkRequest(p.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if p := e.PendingLinks(); len(p) != 1 || p[0].Name != "real" {
		t.Fatalf("pending after turning down = %+v", p)
	}
	for _, d := range spam {
		for range 2 {
			if _, _, err := e.PollLink(d); !errors.Is(err, core.ErrLinkDenied) {
				t.Fatalf("poll after turning down: %v", err)
			}
		}
	}
	// One IPv6 host holds a whole /64: it counts as one source.
	for i := range 3 {
		if _, err := e.StartLink("v6", fmt.Sprintf("2001:db8:1:2::%x", i+1)); err != nil {
			t.Fatalf("v6 %d: %v", i, err)
		}
	}
	if _, err := e.StartLink("v6", "2001:db8:1:2:ffff::9"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatalf("a 4th from one /64: %v", err)
	}
	if _, err := e.StartLink("v6", "2001:db8:1:3::1"); err != nil {
		t.Fatalf("another /64: %v", err)
	}
	// One home or tunnel holds many /64s, or a /24: a network gets 10.
	e, _ = coretest.Engine(t, "")
	for i := range 10 {
		if _, err := e.StartLink("v6", fmt.Sprintf("2001:db8:7:%x::1", i)); err != nil {
			t.Fatalf("/64 %d: %v", i, err)
		}
	}
	if _, err := e.StartLink("v6", "2001:db8:7:ff::1"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatalf("an 11th from one /48: %v", err)
	}
	for i := range 10 {
		if _, err := e.StartLink("v4", fmt.Sprintf("192.0.2.%d", i+1)); err != nil {
			t.Fatalf("v4 %d: %v", i, err)
		}
	}
	if _, err := e.StartLink("v4", "192.0.2.99"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatalf("an 11th from one /24: %v", err)
	}
	// Filling the whole list takes far more than a few networks: 25 IPv6
	// /48s (one /40) still leave room for everyone else.
	e, _ = coretest.Engine(t, "")
	for n := range 25 {
		for i := range 10 {
			if _, err := e.StartLink("v6", fmt.Sprintf("2001:db8:%x:%x::1", n, i)); err != nil {
				t.Fatalf("/48 %d, request %d: %v", n, i, err)
			}
		}
	}
	if _, err := e.StartLink("real", "203.0.113.5"); err != nil {
		t.Fatalf("a real box after one /40 filled its share: %v", err)
	}
	// Written differently, the same address is the same source.
	e, _ = coretest.Engine(t, "")
	for _, a := range []string{"198.51.100.7", "::ffff:198.51.100.7", "198.51.100.7"} {
		if _, err := e.StartLink("m", a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.StartLink("m", "::ffff:198.51.100.7"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatalf("an IPv4-mapped address counted apart: %v", err)
	}
	for _, a := range []string{"fe80::1%en0", "fe80::2%en1", "fe80::3"} {
		if _, err := e.StartLink("m", a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.StartLink("m", "fe80::4%en2"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatalf("zoned addresses counted apart: %v", err)
	}
	if _, err := e.StartLink("", ""); err == nil {
		t.Fatal("a machine with no name")
	}
	if _, err := e.StartLink("a/b", ""); err == nil {
		t.Fatal("a machine name with a slash")
	}
}

func TestMachineTokens(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	if _, err := e.AddEnvironment(ctx, "default", "prod", core.Limits{}); err != nil {
		t.Fatal(err)
	}
	m, cred := link(t, e, "devbox", core.DefaultEnv)

	tok, tk, err := e.EnsureMachineToken(ctx, cred, "", "my-worktree")
	if err != nil || tk.Name != "devbox/my-worktree" || tk.Principal != "machine:"+m.ID || tk.EnvID != core.DefaultEnv {
		t.Fatalf("ensure: %+v %v", tk, err)
	}
	again, _, err := e.EnsureMachineToken(ctx, cred, core.DefaultEnv, "my-worktree")
	if err != nil || again != tok {
		t.Fatalf("ensure again gave a different token: %v", err)
	}
	// The token is "devbox/<name>", at most 128 characters: the name gets 121.
	if _, tk, err := e.EnsureMachineToken(ctx, cred, "", strings.Repeat("w", 121)); err != nil || len(tk.Name) != 128 {
		t.Fatalf("longest name: %+v %v", tk, err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, "", strings.Repeat("w", 122)); err == nil || !strings.Contains(err.Error(), "at most 121 characters") {
		t.Fatalf("too long: %v", err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, "default/prod", "x"); !errors.Is(err, core.ErrNotAllowed) {
		t.Fatalf("env not allowed: %v", err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, "skmach_00", "", "x"); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("bad credential: %v", err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, tok, "", "x"); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("a proxy token as a credential: %v", err)
	}
	if ms := e.Machines(); ms[0].LastSeen == nil {
		t.Fatal("last seen not recorded")
	}
	// Revoking the machine stops all of its tokens, and the credential.
	other2, _, _ := e.EnsureMachineToken(ctx, cred, "", "second")
	if err := e.RevokeMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	for _, x := range []string{tok, other2} {
		if err := e.CheckToken(x); !errors.Is(err, core.ErrUnknownKey) {
			t.Fatalf("token still works after revoking the machine: %v", err)
		}
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, "", "my-worktree"); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("revoked machine got a token: %v", err)
	}
	if _, err := e.Machine(cred); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("revoked machine: %v", err)
	}
	if err := e.RevokeMachine(ctx, "m_nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown machine: %v", err)
	}
}

func TestMachineTokenIgnoresOtherPrincipals(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	_, cred := link(t, e, "devbox", core.DefaultEnv)
	// Someone made a token with the same name by hand: the machine doesn't
	// get it, and can't get a second live one with that name.
	if _, _, err := e.CreateToken(ctx, core.TokenSpec{EnvID: core.DefaultEnv, Name: "devbox/wt"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, "", "wt"); !errors.Is(err, core.ErrNameTaken) {
		t.Fatalf("got %v", err)
	}
}

func TestDenyFromTheList(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	st, _ := e.StartLink("stranger", "10.0.0.9")
	p := e.PendingLinks()
	if len(p) != 1 || p[0].ID == "" {
		t.Fatalf("pending = %+v", p)
	}
	if err := e.DenyLinkRequest(p[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.PollLink(st.DeviceCode); !errors.Is(err, core.ErrLinkDenied) {
		t.Fatalf("poll: %v", err)
	}
	if err := e.DenyLinkRequest("lr_nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestApprovedAtTheLastSecond(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	st, _ := e.StartLink("box", "")
	base := time.Now()
	e.SetClock(func() time.Time { return base.Add(core.LinkLifetime - time.Second) })
	if _, err := e.ApproveLink(ctx, st.UserCode, []string{core.DefaultEnv}); err != nil {
		t.Fatal(err)
	}
	e.SetClock(func() time.Time { return base.Add(core.LinkLifetime + 2*time.Second) }) // the CLI's next poll
	if _, cred, err := e.PollLink(st.DeviceCode); err != nil || cred == "" {
		t.Fatalf("the approved machine's credential was lost: %v", err)
	}
}

func TestSameNamedMachinesDontCollide(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	a, credA := link(t, e, "MacBook-Pro", core.DefaultEnv)
	b, credB := link(t, e, "MacBook-Pro", core.DefaultEnv)
	if a.Name != "MacBook-Pro" || b.Name != "MacBook-Pro-2" {
		t.Fatalf("names %q %q", a.Name, b.Name)
	}
	for _, cred := range []string{credA, credB} {
		if _, _, err := e.EnsureMachineToken(ctx, cred, "", "app"); err != nil {
			t.Fatalf("same worktree name on both: %v", err)
		}
	}
	// A revoked machine's name is free again.
	if err := e.RevokeMachine(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := link(t, e, "MacBook-Pro", core.DefaultEnv); c.Name != "MacBook-Pro" {
		t.Fatalf("after revoke: %q", c.Name)
	}
}

func TestMachineTokenLimits(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	_, cred := link(t, e, "box", core.DefaultEnv)
	if _, _, err := e.EnsureMachineToken(ctx, cred, "", strings.Repeat("x", 129)); err == nil {
		t.Fatal("a 129-character name")
	}
	for i := range 100 {
		if _, _, err := e.EnsureMachineToken(ctx, cred, "", fmt.Sprint("wt", i)); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, "", "wt100"); !errors.Is(err, core.ErrNotAllowed) {
		t.Fatalf("101st: %v", err)
	}
	if _, _, err := e.EnsureMachineToken(ctx, cred, "", "wt7"); err != nil {
		t.Fatalf("an existing one at the cap: %v", err)
	}
}

// noEnvs is a store whose machines lost their environments (a hand-edited
// state.json).
type noEnvs struct{ core.Repository }

func (r noEnvs) ListMachines(ctx context.Context) ([]core.Machine, error) {
	ms, err := r.Repository.ListMachines(ctx)
	for i := range ms {
		ms[i].Envs = nil
	}
	return ms, err
}

func TestMachineWithNoEnvironments(t *testing.T) {
	e, dir := coretest.Engine(t, "")
	_, cred := link(t, e, "box", core.DefaultEnv)
	e2, _ := coretest.EngineWith(t, dir, func(r core.Repository) core.Repository { return noEnvs{r} })
	if _, _, err := e2.EnsureMachineToken(ctx, cred, "", "wt"); !errors.Is(err, core.ErrNotAllowed) {
		t.Fatalf("got %v", err)
	}
}

func TestPendingLinkShowsTheMachine(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	st, _ := e.StartLink("devbox", "10.0.0.5")
	r, err := e.PendingLink(strings.ToLower(st.UserCode))
	if err != nil || r.Name != "devbox" || r.From != "10.0.0.5" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := e.PendingLink("BBBB-BBBB"); err == nil {
		t.Fatal("a code nobody is waiting with")
	}
	if _, _, err := e.PollLink(st.DeviceCode); !errors.Is(err, core.ErrLinkPending) {
		t.Fatalf("looking it up approved it: %v", err)
	}
}

func TestMachineTokensExpire(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	_, cred := link(t, e, "box", core.DefaultEnv)
	tok, tk, err := e.EnsureMachineToken(ctx, cred, "", "wt")
	if err != nil || tk.ExpiresAt == nil {
		t.Fatalf("no lifetime: %+v %v", tk, err)
	}
	e.SetClock(func() time.Time { return time.Now().Add(core.MachineTokenLifetime + time.Hour) })
	again, _, err := e.EnsureMachineToken(ctx, cred, "", "wt")
	if err != nil || again == tok {
		t.Fatalf("an expired token wasn't replaced: %v", err)
	}
}

// failTokens is a store that can't save tokens.
type failTokens struct{ core.Repository }

func (failTokens) PutToken(context.Context, core.Token) error { return errors.New("disk full") }

func TestRevokedMachineStopsItsTokensEvenIfSavingFails(t *testing.T) {
	var fail bool
	e, _ := coretest.EngineWith(t, "", func(r core.Repository) core.Repository {
		return switchable{r, &fail}
	})
	m, cred := link(t, e, "box", core.DefaultEnv)
	tok, _, err := e.EnsureMachineToken(ctx, cred, "", "wt")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.AddService(ctx, core.Service{ID: "echo", Name: "Echo", Hosts: []string{"api.echo.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(ctx, e, core.DefaultEnv, "echo", "real"); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := e.RevokeMachine(ctx, m.ID); err == nil {
		t.Fatal("revoke reported no error though its tokens couldn't be saved")
	}
	// The machine is revoked, its token isn't marked: it must stop anyway.
	if err := e.CheckToken(tok); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("check: %v", err)
	}
	if _, err := e.Authorize(ctx, tok, "echo"); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("authorize: %v", err)
	}
	if _, _, err := e.TokenServices(tok); !errors.Is(err, core.ErrUnknownKey) {
		t.Fatalf("catalog: %v", err)
	}
	if ts := e.Tokens(core.DefaultEnv); e.TokenState(ts[0].ID) != "revoked" {
		t.Fatalf("shown as %s", e.TokenState(ts[0].ID))
	}
	// And the retry still marks it.
	fail = false
	if err := e.RevokeMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if ts := e.Tokens(core.DefaultEnv); ts[0].RevokedAt == nil {
		t.Fatal("retry didn't revoke the token")
	}
}

// switchable fails PutToken while *fail is set.
type switchable struct {
	core.Repository
	fail *bool
}

func (s switchable) PutToken(ctx context.Context, t core.Token) error {
	if *s.fail {
		return failTokens{}.PutToken(ctx, t)
	}
	return s.Repository.PutToken(ctx, t)
}

func TestMachineNamesAreVisible(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	for _, n := range []string{"box\u202egnp.exe", "box\u200b", "box\x1b[2J", "a/b"} {
		if _, err := e.StartLink(n, ""); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if _, err := e.StartLink("Ada's MacBook-Pro (2)", ""); err != nil {
		t.Fatal(err)
	}
}

func TestMachineTokenRenewsWhenUsed(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	_, cred := link(t, e, "box", core.DefaultEnv)
	base := time.Now()
	tok, first, _ := e.EnsureMachineToken(ctx, cred, "", "wt")
	// Asked again on day 20: same token, a full lifetime from now.
	e.SetClock(func() time.Time { return base.Add(20 * 24 * time.Hour) })
	again, tk, err := e.EnsureMachineToken(ctx, cred, "", "wt")
	if err != nil || again != tok || !tk.ExpiresAt.After(first.ExpiresAt.Add(19*24*time.Hour)) {
		t.Fatalf("not renewed: %v %v -> %v", err, first.ExpiresAt, tk.ExpiresAt)
	}
	// Asked again on day 21: more than half is left, so nothing is saved.
	e.SetClock(func() time.Time { return base.Add(21 * 24 * time.Hour) })
	_, tk2, _ := e.EnsureMachineToken(ctx, cred, "", "wt")
	if !tk2.ExpiresAt.Equal(*tk.ExpiresAt) {
		t.Fatalf("renewed again: %v -> %v", tk.ExpiresAt, tk2.ExpiresAt)
	}
}

func TestLinkSlotsComeBack(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	ctx := context.Background()
	now := time.Now()
	e.SetClock(func() time.Time { return now })
	var codes []core.LinkStart
	for range 3 {
		st, err := e.StartLink("box", "10.4.4.4")
		if err != nil {
			t.Fatal(err)
		}
		codes = append(codes, st)
	}
	if _, err := e.StartLink("box", "10.4.4.4"); !errors.Is(err, core.ErrTooManyLinks) {
		t.Fatal("a 4th")
	}
	// Approved and picked up, a request frees its slot.
	if _, err := e.ApproveLink(ctx, codes[0].UserCode, []string{core.DefaultEnv}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ApproveLink(ctx, codes[0].UserCode, []string{core.DefaultEnv}); err == nil {
		t.Fatal("approved twice")
	}
	if _, _, err := e.PollLink(codes[0].DeviceCode); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartLink("box", "10.4.4.4"); err != nil {
		t.Fatalf("after a pickup: %v", err)
	}
	// Expired, they all do.
	now = now.Add(core.LinkLifetime + time.Second)
	for range 3 {
		if _, err := e.StartLink("box", "10.4.4.4"); err != nil {
			t.Fatalf("after expiry: %v", err)
		}
	}
	if p := e.PendingLinks(); len(p) != 3 {
		t.Fatalf("pending = %d", len(p))
	}
}
