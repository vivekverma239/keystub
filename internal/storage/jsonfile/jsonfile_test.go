package jsonfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/storage/storagetest"
)

func TestContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	storagetest.Run(t, func() core.Repository {
		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return r
	})
}

// A stage 0 file, as written by the version merged in #212.
const v1 = `{
  "services": [
    {"id": "openai", "name": "OpenAI", "hosts": ["api.openai.com"], "header": "Authorization", "format": "Bearer {key}",
     "envVars": ["OPENAI_API_KEY"], "secret": {"sealer": "envelope", "wrappedKey": "AQ==", "ciphertext": "Ag=="},
     "secretSetAt": "2026-10-30T10:00:00Z"},
    {"id": "stripe", "name": "Stripe", "hosts": ["api.stripe.com"], "header": "Authorization", "format": "Bearer {key}"}
  ],
  "keys": [
    {"id": "vk_1", "name": "wt-a", "tokenHash": "h1", "token": {"ciphertext": "Aw=="}, "dailyLimit": 50, "createdAt": "2026-10-30T10:00:00Z"},
    {"id": "vk_2", "name": "old", "tokenHash": "h2", "token": {"ciphertext": "BA=="}, "dailyLimit": 0, "createdAt": "2026-10-29T10:00:00Z", "revokedAt": "2026-10-30T09:00:00Z"}
  ]
}`

func TestMigratesStage0File(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path + ".v1"); string(b) != v1 {
		t.Fatal("old file not kept")
	}
	envs, _ := r.ListEnvironments(ctx)
	if len(envs) != 1 || envs[0].ID != core.DefaultEnv {
		t.Fatalf("environments = %+v", envs)
	}
	ks, _ := r.ListKeys(ctx)
	if len(ks) != 1 || ks[0].ServiceID != "openai" || ks[0].Name != "default/dev openai" || string(ks[0].Secret.Ciphertext) != "\x02" {
		t.Fatalf("keys = %+v", ks)
	}
	ls, _ := r.ListLinks(ctx)
	if len(ls) != 1 || ls[0].EnvID != core.DefaultEnv || ls[0].KeyID != ks[0].ID {
		t.Fatalf("links = %+v", ls)
	}
	ts, _ := r.ListTokens(ctx)
	if len(ts) != 2 || ts[0].TokenHash != "h1" || ts[0].Limits.DailyRequests != 50 || ts[1].RevokedAt == nil || ts[0].EnvID != core.DefaultEnv || ts[0].Kind != core.KindEnvironment {
		t.Fatalf("tokens = %+v", ts)
	}
	// Reopening reads the new format without migrating again.
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}
}

// A version 2 file, as written before saved keys: bindings, and tokens that may
// list services.
const v2 = `{
  "version": 2,
  "projects": [{"id": "app", "name": "App", "createdAt": "2026-10-30T10:00:00Z"}],
  "environments": [
    {"id": "app/dev", "projectId": "app", "name": "dev", "createdAt": "2026-10-30T10:00:00Z"},
    {"id": "app/prod", "projectId": "app", "name": "prod", "createdAt": "2026-10-30T10:00:00Z"}
  ],
  "services": [
    {"id": "openai", "name": "OpenAI", "hosts": ["api.openai.com"], "header": "Authorization", "format": "Bearer {key}"},
    {"id": "github", "name": "GitHub", "hosts": ["api.github.com"], "header": "Authorization", "format": "Bearer {key}"}
  ],
  "bindings": [
    {"envId": "app/dev", "serviceId": "openai", "secret": {"sealer": "envelope", "ciphertext": "AQ=="}, "setAt": "2026-10-30T11:00:00Z"},
    {"envId": "app/prod", "serviceId": "openai", "secret": {"sealer": "envelope", "ciphertext": "Ag=="}, "setAt": "2026-10-30T12:00:00Z"}
  ],
  "tokens": [
    {"id": "tk_all", "name": "all", "envId": "app/dev", "tokenHash": "h1", "token": {"ciphertext": "Aw=="}, "createdAt": "2026-10-30T10:00:00Z"},
    {"id": "tk_one", "name": "one", "envId": "app/dev", "services": ["openai"], "tokenHash": "h2", "token": {"ciphertext": "Aw=="}, "createdAt": "2026-10-30T10:00:00Z"},
    {"id": "tk_two", "name": "two", "envId": "app/prod", "services": ["openai", "github"], "tokenHash": "h3", "token": {"ciphertext": "Aw=="}, "createdAt": "2026-10-30T10:00:00Z"}
  ],
  "machines": [{"id": "m_1", "name": "box", "envs": ["app/dev"], "credentialHash": "c", "createdAt": "2026-10-30T10:00:00Z"}]
}`

func TestConvertsBindingsAndTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	r, notes, err := OpenNotes(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path + ".v2"); string(b) != v2 {
		t.Fatal("old file not kept")
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "two (tk_two) in app/prod was revoked") || !strings.Contains(notes[0], "openai, github") ||
		!strings.Contains(notes[1], "all (tk_all) in app/dev were marked as keystub run's") {
		t.Fatalf("notes = %q", notes)
	}
	storagetest.CheckConverted(t, r)
	// Reopening reads the new format without converting again.
	r2, notes, err := OpenNotes(path)
	if err != nil || len(notes) != 0 {
		t.Fatal(notes, err)
	}
	storagetest.CheckConverted(t, r2)

	// A build from before saved keys can't read the file.
	b, _ := os.ReadFile(path)
	var older struct {
		Bindings []core.Binding `json:"bindings"`
	}
	if err := json.Unmarshal(b, &older); err == nil {
		t.Fatal("an older build could read the converted file")
	}
	// Nor can this build read a newer one.
	if err := os.WriteFile(path, []byte(`{"version": 4}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenNotes(path); err == nil || !strings.Contains(err.Error(), "newer Keystub") {
		t.Fatalf("newer file: %v", err)
	}
}

// A start that kept the copy and stopped before saving leaves the old
// file and its copy; the next start converts again, cleanly.
func TestConvertsAgainAfterACrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, p := range []string{path, path + ".v2"} {
		if err := os.WriteFile(p, []byte(v2), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, _, err := OpenNotes(path)
	if err != nil {
		t.Fatal(err)
	}
	storagetest.CheckConverted(t, r)
	if m, _ := filepath.Glob(path + ".v2*"); len(m) != 1 {
		t.Fatalf("copies = %v", m)
	}
	// Data that went back to an older build and came again: the earlier
	// copy isn't overwritten.
	again := strings.Replace(v2, `"name": "all"`, `"name": "all-again"`, 1)
	if err := os.WriteFile(path, []byte(again), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenNotes(path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path + ".v2"); string(b) != v2 {
		t.Fatal("the first copy was overwritten")
	}
	if m, _ := filepath.Glob(path + ".v2.*"); len(m) != 1 {
		t.Fatalf("second copy = %v", m)
	}
}

func TestFailedSaveChangesNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.path = filepath.Join(dir, "missing", "state.json") // every save fails
	if err := r.PutToken(ctx, core.Token{ID: "tk_lost", EnvID: core.DefaultEnv}); err == nil {
		t.Fatal("want a save error")
	}
	if err := r.PutProject(ctx, core.Project{ID: "lost"}); err == nil {
		t.Fatal("want a save error")
	}
	r.path = path
	if err := r.PutService(ctx, core.Service{ID: "openai"}); err != nil {
		t.Fatal(err)
	}
	r2, _ := Open(path)
	if ts, _ := r2.ListTokens(ctx); len(ts) != 0 {
		t.Fatalf("a failed write was saved later: %+v", ts)
	}
	if ps, _ := r2.ListProjects(ctx); len(ps) != 0 {
		t.Fatalf("a failed write was saved later: %+v", ps)
	}
}

func TestListAndPutConcurrently(t *testing.T) {
	ctx := context.Background()
	r, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			_ = r.PutToken(ctx, core.Token{ID: fmt.Sprint("tk_", i)})
		}
	}()
	for range 50 {
		_, _ = r.ListTokens(ctx)
	}
	<-done
}
