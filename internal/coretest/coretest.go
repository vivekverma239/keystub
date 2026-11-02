// Package coretest builds a real Engine for tests: JSON storage in a temp
// folder, envelope encryption with a file master key, an in-memory limiter.
package coretest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/limit"
	"github.com/vivekverma239/keystub/internal/secrets"
	"github.com/vivekverma239/keystub/internal/storage/jsonfile"
)

// Engine returns an engine over dir (a new temp folder if dir is "").
func Engine(t *testing.T, dir string) (*core.Engine, string) {
	t.Helper()
	return EngineWith(t, dir, nil)
}

// EngineWith is Engine with the repository wrapped, e.g. to make writes
// slow or fail.
func EngineWith(t *testing.T, dir string, wrap func(core.Repository) core.Repository) (*core.Engine, string) {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	ctx := context.Background()
	repo, err := jsonfile.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	sealer, _, _, err := secrets.Open(ctx, "file", dir)
	if err != nil {
		t.Fatal(err)
	}
	var r core.Repository = repo
	if wrap != nil {
		r = wrap(repo)
	}
	e, err := core.NewEngine(ctx, r, sealer, limit.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	return e, dir
}

// SetSecret saves value as a key named "<env> <service>" and links it
// into envID, replacing the value if that key exists: the one-step setup
// tests used before saved keys.
func SetSecret(ctx context.Context, e *core.Engine, envID, serviceID, value string) error {
	name := envID + " " + serviceID
	for _, k := range e.Keys() {
		if k.ServiceID == serviceID && k.Name == name {
			if _, err := e.ReplaceKey(ctx, k.ID, value); err != nil {
				return err
			}
			_, err := e.LinkKey(ctx, core.LinkSpec{EnvID: envID, ServiceID: serviceID, KeyID: k.ID})
			return err
		}
	}
	k, err := e.AddKey(ctx, core.KeySpec{ServiceID: serviceID, Name: name, Value: value})
	if err != nil {
		return err
	}
	_, err = e.LinkKey(ctx, core.LinkSpec{EnvID: envID, ServiceID: serviceID, KeyID: k.ID})
	return err
}
