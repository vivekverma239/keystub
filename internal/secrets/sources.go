package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/vivekverma239/keystub/internal/legacy"
	"os"
	"path/filepath"
	"strings"

	"github.com/vivekverma239/keystub/internal/core"
)

// MasterKeySource loads the 32-byte master key, creating it on first use
// where that makes sense.
type MasterKeySource interface {
	Name() string // shown on the dashboard, e.g. "macOS Keychain"
	Load(ctx context.Context) ([]byte, error)
}

func newKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func decodeKey(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("the master key must be 64 hex characters")
	}
	return b, nil
}

// File keeps the master key in a file next to the data. Fine for tests and
// as a last resort; anyone who can read the folder can decrypt everything.
type File struct{ Path string }

func (f File) Name() string { return "file " + f.Path }

func (f File) Load(context.Context) ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: want 32 bytes, got %d", f.Path, len(b))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b, err = newKey()
	if err != nil {
		return nil, err
	}
	return b, os.WriteFile(f.Path, b, 0o600)
}

// Env reads the master key, as 64 hex characters, from an environment
// variable: a Fly or Railway secret, or a Kubernetes secret. It never
// creates one, since the platform has to hold it.
type Env struct{ Var string }

func (e Env) Name() string { return "env " + e.Var }

func (e Env) Load(context.Context) ([]byte, error) {
	v := legacy.Getenv(e.Var)
	if v == "" {
		return nil, fmt.Errorf("%s isn't set; create one with: openssl rand -hex 32", e.Var)
	}
	return decodeKey(v)
}

// MasterKeyEnv is the variable the env source reads.
const MasterKeyEnv = "KEYSTUB_MASTER_KEY"

// sources maps a --secrets name to its source, for the data folder home.
var sources = map[string]func(home string) MasterKeySource{
	"file":     func(home string) MasterKeySource { return File{Path: filepath.Join(home, "master.key")} },
	"env":      func(string) MasterKeySource { return Env{Var: MasterKeyEnv} },
	"keychain": func(home string) MasterKeySource { return newKeychain(home) },
}

// Names lists the --secrets choices.
func Names() []string { return []string{"auto", "keychain", "env", "file"} }

// Auto picks the best source available here: the env var if it's set
// (servers), the OS keychain if there is one (laptops), else the file.
func Auto(home string) (MasterKeySource, string) {
	if legacy.Getenv(MasterKeyEnv) != "" {
		return sources["env"](home), ""
	}
	if keychainAvailable() {
		return sources["keychain"](home), ""
	}
	return sources["file"](home), "no OS keychain here, so the master key is a file next to the data"
}

// Open returns the envelope sealer with its master key from the named
// source ("auto" picks one). The note is a warning to show, if any.
func Open(ctx context.Context, name, home string) (core.Sealer, MasterKeySource, string, error) {
	var src MasterKeySource
	note := ""
	if name == "" || name == "auto" {
		src, note = Auto(home)
	} else if f, ok := sources[name]; ok {
		src = f(home)
	} else {
		return nil, nil, "", fmt.Errorf("unknown secrets source %q (choose %s)", name, strings.Join(Names(), ", "))
	}
	master, err := src.Load(ctx)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%s: %w", src.Name(), err)
	}
	s, err := NewEnvelope(master)
	return s, src, note, err
}
