package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/limit/limittest"
	"github.com/vivekverma239/keystub/internal/storage/jsonfile"
	"github.com/vivekverma239/keystub/internal/storage/storagetest"
)

func open(t *testing.T, path string) *DB {
	t.Helper()
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestRepositoryContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystub.db")
	storagetest.Run(t, func() core.Repository { return open(t, path) })
}

func TestLimiterContract(t *testing.T) {
	limittest.Run(t, func(now func() time.Time) core.Limiter {
		l := NewLimiter(open(t, filepath.Join(t.TempDir(), "keystub.db")))
		l.Now = now
		return l
	})
}

func TestLimitsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keystub.db")
	s := []core.Scope{{Key: "token:a", Label: "token a", Limits: core.Limits{DailyRequests: 1}}}
	d := open(t, path)
	if err := NewLimiter(d).Allow(ctx, s); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if err := NewLimiter(open(t, path)).Allow(ctx, s); err == nil {
		t.Fatal("the count was lost on restart")
	}
}

func TestConcurrentAllowNeverOvercounts(t *testing.T) {
	ctx := context.Background()
	l := NewLimiter(open(t, filepath.Join(t.TempDir(), "keystub.db")))
	s := []core.Scope{{Key: "token:a", Label: "token a", Limits: core.Limits{DailyRequests: 10}}}
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow(ctx, s) == nil {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n, _ := l.UsedToday(ctx, "token:a"); allowed != 10 || n != 10 {
		t.Fatalf("allowed %d, counted %d, want 10", allowed, n)
	}
}

func TestEventsNewestFirstAndPruned(t *testing.T) {
	ev := NewEvents(open(t, filepath.Join(t.TempDir(), "keystub.db")), time.Hour)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	ev.Now = func() time.Time { return now }
	ev.Add(core.Entry{Time: now.Add(-2 * time.Hour), Path: "/old"})
	ev.lastPrune = time.Time{}
	ev.Add(core.Entry{Time: now, Path: "/a"})
	ev.Add(core.Entry{Time: now, Path: "/b"})
	got := ev.Recent(10)
	if len(got) != 2 || got[0].Path != "/b" || got[1].Path != "/a" {
		t.Fatalf("recent = %+v", got)
	}
}

func TestImportFromJSONFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	js, err := jsonfile.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = js.PutProject(ctx, core.Project{ID: "default", Name: "Default"})
	_ = js.PutEnvironment(ctx, core.Environment{ID: core.DefaultEnv, ProjectID: "default", Name: "dev"})
	_ = js.PutService(ctx, core.Service{ID: "openai", Name: "OpenAI", Hosts: []string{"api.openai.com"}})
	_ = js.PutKey(ctx, core.SavedKey{ID: "key_1", Name: "team", ServiceID: "openai", Secret: &core.Sealed{Ciphertext: []byte{1}}, Version: 1})
	_ = js.PutLink(ctx, core.Link{EnvID: core.DefaultEnv, ServiceID: "openai", KeyID: "key_1", Version: 1})
	_ = js.PutToken(ctx, core.Token{ID: "tk_1", Name: "wt", EnvID: core.DefaultEnv, Kind: core.KindEnvironment, TokenHash: "h"})

	d := open(t, filepath.Join(dir, "keystub.db"))
	if empty, _ := d.Empty(ctx); !empty {
		t.Fatal("new database isn't empty")
	}
	if err := d.Import(ctx, js); err != nil {
		t.Fatal(err)
	}
	if empty, _ := d.Empty(ctx); empty {
		t.Fatal("still empty after import")
	}
	ks, _ := d.ListKeys(ctx)
	ls, _ := d.ListLinks(ctx)
	ts, _ := d.ListTokens(ctx)
	if len(ks) != 1 || len(ls) != 1 || ls[0].KeyID != "key_1" || len(ts) != 1 || ts[0].TokenHash != "h" {
		t.Fatalf("keys %+v links %+v tokens %+v", ks, ls, ts)
	}
}

// A database from before saved keys: a bindings table, and tokens that may list services.
func TestConvertsBindingsAndTokens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keystub.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE bindings (env_id TEXT NOT NULL, service_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (env_id, service_id))",
		"CREATE TABLE tokens (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
		"CREATE TABLE machines (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
		`INSERT INTO bindings VALUES ('app/dev', 'openai', '{"envId":"app/dev","serviceId":"openai","secret":{"ciphertext":"AQ=="},"setAt":"2026-10-30T11:00:00Z"}')`,
		`INSERT INTO bindings VALUES ('app/prod', 'openai', '{"envId":"app/prod","serviceId":"openai","secret":{"ciphertext":"Ag=="},"setAt":"2026-10-30T12:00:00Z"}')`,
		`INSERT INTO tokens VALUES ('tk_all', '{"id":"tk_all","name":"all","envId":"app/dev","tokenHash":"h1"}')`,
		`INSERT INTO tokens VALUES ('tk_one', '{"id":"tk_one","name":"one","envId":"app/dev","services":["openai"],"tokenHash":"h2"}')`,
		`INSERT INTO tokens VALUES ('tk_two', '{"id":"tk_two","name":"two","envId":"app/prod","services":["openai","github"],"tokenHash":"h3"}')`,
		`INSERT INTO machines VALUES ('m_1', '{"id":"m_1","name":"box","envs":["app/dev"]}')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	raw.Close()

	d := open(t, path)
	if n := d.Notes(); len(n) != 2 || !strings.Contains(n[0], "two (tk_two) in app/prod was revoked") || !strings.Contains(n[1], "all (tk_all) in app/dev were marked") {
		t.Fatalf("notes = %q", n)
	}
	storagetest.CheckConverted(t, d)
	var tables int
	_ = d.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'bindings'").Scan(&tables)
	if tables != 0 {
		t.Fatal("bindings table kept")
	}
	// What an older build does at start fails, so it can't run without
	// the saved keys.
	if _, err := d.db.Exec("CREATE TABLE IF NOT EXISTS bindings (env_id TEXT NOT NULL, service_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (env_id, service_id))"); err != nil {
		t.Fatal(err)
	}
	if rows, err := d.db.Query("SELECT data FROM bindings"); err == nil {
		rows.Close()
		t.Fatal("an older build could read bindings")
	}
	if _, err := d.db.Exec("INSERT INTO bindings (env_id, service_id, data) VALUES ('a', 'b', '{}')"); err == nil {
		t.Fatal("an older build could write bindings")
	}
	d.Close()
	d = open(t, path) // converting again changes nothing
	if len(d.Notes()) != 0 {
		t.Fatalf("notes = %q", d.Notes())
	}
	storagetest.CheckConverted(t, d)
	d.Close()

	// Bindings made again (the guard dropped, an older build run): an
	// environment that links a key keeps it and gets no stray key; one that
	// doesn't is converted.
	raw, _ = sql.Open("sqlite", path)
	for _, q := range []string{
		"DROP VIEW bindings",
		"CREATE TABLE bindings (env_id TEXT NOT NULL, service_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (env_id, service_id))",
		`INSERT INTO bindings VALUES ('app/dev', 'openai', '{"envId":"app/dev","serviceId":"openai","secret":{"ciphertext":"BQ=="},"setAt":"2026-10-31T11:00:00Z"}')`,
		`INSERT INTO bindings VALUES ('app/dev', 'github', '{"envId":"app/dev","serviceId":"github","secret":{"ciphertext":"Bg=="},"setAt":"2026-10-31T11:00:00Z"}')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	raw.Close()
	d = open(t, path)
	if n := d.Notes(); len(n) != 1 || !strings.Contains(n[0], "openai in app/dev was dropped") {
		t.Fatalf("notes = %q", n)
	}
	ks, _ := d.ListKeys(ctx)
	ls, _ := d.ListLinks(ctx)
	if len(ks) != 3 || len(ls) != 3 {
		t.Fatalf("after converting again: keys %+v links %+v", ks, ls)
	}
}

func TestEventsConcurrentAdd(t *testing.T) {
	ev := NewEvents(open(t, filepath.Join(t.TempDir(), "keystub.db")), 0)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); ev.Add(core.Entry{Time: time.Now(), Path: "/x"}) }()
	}
	wg.Wait()
	if n := len(ev.Recent(100)); n != 20 {
		t.Fatalf("recorded %d of 20", n)
	}
}

func TestAwkwardPathsAndPrivateFile(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"q?mark", "hash#x", "pct%41", "with space"} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "keystub.db")
		d, err := Open(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := d.PutProject(ctx, core.Project{ID: "p"}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var mode string
		_ = d.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
		d.Close()
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: database not at %s: %v", name, path, err)
		}
		if st.Mode().Perm() != 0o600 || mode != "wal" {
			t.Errorf("%s: mode %v, journal %q", name, st.Mode().Perm(), mode)
		}
		ents, _ := os.ReadDir(filepath.Dir(dir))
		if len(ents) != 1 {
			t.Errorf("%s: stray files beside the folder: %v", name, ents)
		}
	}
}
