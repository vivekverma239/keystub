package secrets

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvelopeRoundTripAndWrongKey(t *testing.T) {
	ctx := context.Background()
	k1, _ := newKey()
	k2, _ := newKey()
	a, _ := NewEnvelope(k1)
	b, _ := NewEnvelope(k2)
	v, err := a.Seal(ctx, []byte("sk-real"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(v.Ciphertext)+string(v.WrappedKey), "sk-real") {
		t.Fatal("plaintext visible in sealed value")
	}
	if got, err := a.Open(ctx, v); err != nil || string(got) != "sk-real" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := b.Open(ctx, v); err == nil {
		t.Fatal("a different master key opened the value")
	}
}

func TestFileSourceCreatesOnceAndReloads(t *testing.T) {
	ctx := context.Background()
	f := File{Path: filepath.Join(t.TempDir(), "master.key")}
	k1, err := f.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := f.Load(ctx)
	if hex.EncodeToString(k1) != hex.EncodeToString(k2) {
		t.Fatal("file source made a new key on reload")
	}
	if st, _ := os.Stat(f.Path); st.Mode().Perm() != 0o600 {
		t.Fatalf("master.key mode %v", st.Mode().Perm())
	}
}

func TestEnvSource(t *testing.T) {
	ctx := context.Background()
	e := Env{Var: "KEYSTUB_TEST_MASTER"}
	t.Setenv("KEYSTUB_TEST_MASTER", "")
	if _, err := e.Load(ctx); err == nil {
		t.Fatal("empty env accepted")
	}
	t.Setenv("KEYSTUB_TEST_MASTER", "abcd")
	if _, err := e.Load(ctx); err == nil {
		t.Fatal("short key accepted")
	}
	t.Setenv("KEYSTUB_TEST_MASTER", strings.Repeat("ab", 32))
	if k, err := e.Load(ctx); err != nil || len(k) != 32 {
		t.Fatalf("Load = %d bytes, %v", len(k), err)
	}
}

func TestAutoPrefersEnv(t *testing.T) {
	t.Setenv(MasterKeyEnv, strings.Repeat("cd", 32))
	src, _ := Auto(t.TempDir())
	if src.Name() != "env "+MasterKeyEnv {
		t.Fatalf("auto picked %s", src.Name())
	}
}

func TestOpenRejectsUnknownSource(t *testing.T) {
	if _, _, _, err := Open(context.Background(), "vault", t.TempDir()); err == nil {
		t.Fatal("unknown source accepted")
	}
}
