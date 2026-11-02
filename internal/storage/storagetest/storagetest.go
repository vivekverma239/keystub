// Package storagetest is the contract every core.Repository must pass.
// A new storage adapter (SQLite, Postgres) calls Run from its own tests.
package storagetest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

// Run checks a repository. reopen must return a repository over the same
// data as the last one it returned (or a fresh one on the first call).
func Run(t *testing.T, reopen func() core.Repository) {
	ctx := context.Background()
	r := reopen()
	at := time.Unix(1, 0).UTC()

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.PutProject(ctx, core.Project{ID: "app", Name: "App", CreatedAt: at}))
	must(r.PutProject(ctx, core.Project{ID: "app", Name: "App", Limits: core.Limits{DailyRequests: 5}, CreatedAt: at}))
	must(r.PutEnvironment(ctx, core.Environment{ID: "app/dev", ProjectID: "app", Name: "dev", CreatedAt: at}))
	must(r.PutService(ctx, core.Service{ID: "openai", Name: "OpenAI", Hosts: []string{"api.openai.com"}, Header: "Authorization", Format: "Bearer {key}"}))
	must(r.PutService(ctx, core.Service{ID: "openai", Name: "OpenAI (renamed)", Hosts: []string{"api.openai.com"}, Header: "Authorization", Format: "Bearer {key}"}))
	must(r.PutEnvironment(ctx, core.Environment{ID: "app/prod", ProjectID: "app", Name: "prod", CreatedAt: at}))
	key := core.SavedKey{ID: "key_1", Name: "team", ServiceID: "openai", Secret: &core.Sealed{Sealer: "envelope", WrappedKey: []byte{1}, Ciphertext: []byte{2}},
		Version: 1, SetAt: at, CreatedAt: at}
	must(r.PutKey(ctx, key))
	key.Secret, key.Version, key.Limits = &core.Sealed{Ciphertext: []byte{9}}, 2, core.Limits{DailyRequests: 7}
	must(r.PutKey(ctx, key))
	must(r.PutKey(ctx, core.SavedKey{ID: "key_2", Name: "personal", ServiceID: "openai", Secret: &core.Sealed{Ciphertext: []byte{4}}, Version: 1, SetAt: at, CreatedAt: at}))
	must(r.PutLink(ctx, core.Link{EnvID: "app/dev", ServiceID: "openai", KeyID: "key_2", Version: 1, SetAt: at}))
	must(r.PutLink(ctx, core.Link{EnvID: "app/dev", ServiceID: "openai", KeyID: "key_1", Version: 2, SetAt: at})) // switched: still one link
	must(r.PutLink(ctx, core.Link{EnvID: "app/prod", ServiceID: "openai", KeyID: "key_1", Version: 1, SetAt: at}))
	exp := time.Unix(5, 0).UTC()
	tok := core.Token{ID: "tk_1", Name: "wt", EnvID: "app/dev", Kind: core.KindService, Service: "openai",
		Limits: core.Limits{PerMinute: 3}, ExpiresAt: &exp, TokenHash: "abc", Token: &core.Sealed{Ciphertext: []byte{3}}, CreatedAt: at}
	must(r.PutToken(ctx, tok))
	rev := time.Unix(2, 0).UTC()
	tok.RevokedAt = &rev
	must(r.PutToken(ctx, tok))

	seen := time.Unix(3, 0).UTC()
	m := core.Machine{ID: "m_1", Name: "devbox", Envs: []string{"app/dev"}, CredentialHash: "def", CreatedAt: at}
	must(r.PutMachine(ctx, m))
	m.LastSeen, m.RevokedAt = &seen, &seen
	must(r.PutMachine(ctx, m))

	r = reopen() // everything must survive
	ps, _ := r.ListProjects(ctx)
	if len(ps) != 1 || ps[0].Limits.DailyRequests != 5 {
		t.Fatalf("projects = %+v", ps)
	}
	es, _ := r.ListEnvironments(ctx)
	if len(es) != 2 || es[0].ProjectID != "app" {
		t.Fatalf("environments = %+v", es)
	}
	ss, _ := r.ListServices(ctx)
	if len(ss) != 1 || ss[0].Name != "OpenAI (renamed)" {
		t.Fatalf("services = %+v", ss)
	}
	ks, _ := r.ListKeys(ctx)
	if len(ks) != 2 || ks[0].ID != "key_1" || string(ks[0].Secret.Ciphertext) != "\x09" || ks[0].Version != 2 || ks[0].Limits.DailyRequests != 7 || ks[0].Name != "team" {
		t.Fatalf("keys = %+v", ks)
	}
	ls, _ := r.ListLinks(ctx)
	if len(ls) != 2 {
		t.Fatalf("links = %+v", ls)
	}
	for _, l := range ls {
		if l.KeyID != "key_1" || (l.EnvID == "app/dev") != (l.Version == 2) {
			t.Fatalf("links = %+v", ls)
		}
	}
	ts, _ := r.ListTokens(ctx)
	if len(ts) != 1 || ts[0].RevokedAt == nil || ts[0].ExpiresAt == nil || ts[0].Limits.PerMinute != 3 || ts[0].Kind != core.KindService || ts[0].Service != "openai" {
		t.Fatalf("tokens = %+v", ts)
	}

	ms, _ := r.ListMachines(ctx)
	if len(ms) != 1 || ms[0].Name != "devbox" || ms[0].CredentialHash != "def" || len(ms[0].Envs) != 1 || ms[0].LastSeen == nil || ms[0].RevokedAt == nil {
		t.Fatalf("machines = %+v", ms)
	}

	must(r.DeleteLink(ctx, "app/dev", "openai"))
	if err := r.DeleteLink(ctx, "app/dev", "openai"); err != core.ErrNotFound {
		t.Fatalf("second link delete: %v, want ErrNotFound", err)
	}
	must(r.DeleteKey(ctx, "key_2"))
	if err := r.DeleteKey(ctx, "key_2"); err != core.ErrNotFound {
		t.Fatalf("second key delete: %v, want ErrNotFound", err)
	}
	must(r.DeleteEnvironment(ctx, "app/prod"))
	if err := r.DeleteEnvironment(ctx, "app/prod"); err != core.ErrNotFound {
		t.Fatalf("second environment delete: %v, want ErrNotFound", err)
	}
	must(r.DeleteService(ctx, "openai"))
	if err := r.DeleteService(ctx, "openai"); err != core.ErrNotFound {
		t.Fatalf("second service delete: %v, want ErrNotFound", err)
	}
	r = reopen()
	if ss, _ := r.ListServices(ctx); len(ss) != 0 {
		t.Fatalf("delete didn't persist: %+v", ss)
	}
	if ls, _ := r.ListLinks(ctx); len(ls) != 1 || ls[0].EnvID != "app/prod" {
		t.Fatalf("link delete didn't persist: %+v", ls)
	}
	if ks, _ := r.ListKeys(ctx); len(ks) != 1 || ks[0].ID != "key_1" {
		t.Fatalf("key delete didn't persist: %+v", ks)
	}
	if es, _ := r.ListEnvironments(ctx); len(es) != 1 || es[0].ID != "app/dev" {
		t.Fatalf("environment delete didn't persist: %+v", es)
	}
}

// CheckConverted checks a repository converted from one from before saved
// keys, holding openai bindings in app/dev and app/prod, and tokens tk_all (no
// services), tk_one (openai) and tk_two (openai, github), and machine m_1:
// tk_two can be neither kind without reaching more, so it is revoked.
func CheckConverted(t *testing.T, r core.Repository) {
	t.Helper()
	ctx := context.Background()
	ks, _ := r.ListKeys(ctx)
	ls, _ := r.ListLinks(ctx)
	if len(ks) != 2 || len(ls) != 2 {
		t.Fatalf("keys %+v links %+v", ks, ls)
	}
	names := map[string]string{}
	for _, k := range ks {
		if k.ServiceID != "openai" || k.Version != 1 || !strings.HasPrefix(k.ID, "key_") {
			t.Fatalf("key = %+v", k)
		}
		names[k.ID] = k.Name
	}
	for _, l := range ls {
		if names[l.KeyID] != l.EnvID+" openai" || l.Version != 1 {
			t.Fatalf("link %+v to %q", l, names[l.KeyID])
		}
	}
	ts, _ := r.ListTokens(ctx)
	kinds := map[string]string{}
	for _, tk := range ts {
		kinds[tk.ID] = tk.Kind + ":" + tk.Service
		if live := tk.RevokedAt == nil; live != (tk.ID != "tk_two") {
			t.Fatalf("token %s revoked at %v", tk.ID, tk.RevokedAt)
		}
	}
	if kinds["tk_all"] != "environment:" || kinds["tk_one"] != "service:openai" || kinds["tk_two"] != "environment:" {
		t.Fatalf("tokens = %v", kinds)
	}
	if ms, _ := r.ListMachines(ctx); len(ms) != 1 {
		t.Fatalf("machines = %+v", ms)
	}
}
