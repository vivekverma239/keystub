package secrets

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Writes to the real login keychain, so it only runs when asked:
// KEYSTUB_TEST_KEYCHAIN=1 go test ./internal/secrets/
func TestKeychainImportsFileAndReloads(t *testing.T) {
	if os.Getenv("KEYSTUB_TEST_KEYCHAIN") != "1" {
		t.Skip("set KEYSTUB_TEST_KEYCHAIN=1 to test against the login keychain")
	}
	ctx := context.Background()
	dir := t.TempDir()
	file := filepath.Join(dir, "master.key")
	old, _ := newKey()
	if err := os.WriteFile(file, old, 0o600); err != nil {
		t.Fatal(err)
	}
	k := Keychain{Service: "dev.keystub.test", Account: dir, ImportFrom: file}
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-generic-password", "-s", k.Service, "-a", k.Account).Run()
	})

	got, err := k.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatal("imported key differs from master.key")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("master.key still on disk after import")
	}
	again, err := k.Load(ctx)
	if err != nil || !bytes.Equal(again, old) {
		t.Fatalf("reload = %v", err)
	}
}

// Also writes to the real login keychain; same switch.
func TestKeychainItems(t *testing.T) {
	if os.Getenv("KEYSTUB_TEST_KEYCHAIN") != "1" {
		t.Skip("set KEYSTUB_TEST_KEYCHAIN=1 to test against the login keychain")
	}
	ctx := context.Background()
	k := KeychainItems{Service: "dev.keystub.test-items"}
	account := t.TempDir()
	t.Cleanup(func() { _ = k.Delete(ctx, account) })
	if _, ok, err := k.Get(ctx, account); ok || err != nil {
		t.Fatalf("before set: %v %v", ok, err)
	}
	if err := k.Set(ctx, account, "test", "skmach_one"); err != nil {
		t.Fatal(err)
	}
	if err := k.Set(ctx, account, "test", "skmach_two"); err != nil { // replaces
		t.Fatal(err)
	}
	if v, ok, err := k.Get(ctx, account); !ok || err != nil || v != "skmach_two" {
		t.Fatalf("get: %q %v %v", v, ok, err)
	}
	if err := k.Delete(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete(ctx, account); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestKeychainMovesItemsFromTheOldName(t *testing.T) {
	if os.Getenv("KEYSTUB_TEST_KEYCHAIN") != "1" {
		t.Skip("set KEYSTUB_TEST_KEYCHAIN=1 to test against the login keychain")
	}
	ctx := context.Background()
	dir := t.TempDir()
	oldName, newName := "dev.keystub.test-legacy-old", "dev.keystub.test-legacy-new"
	t.Cleanup(func() {
		for _, s := range []string{oldName, newName} {
			_ = exec.Command("security", "delete-generic-password", "-s", s, "-a", dir).Run()
			_ = exec.Command("security", "delete-generic-password", "-s", s, "-a", "machine").Run()
		}
	})

	// The master key.
	old := Keychain{Service: oldName, Account: dir}
	want, err := old.Load(ctx) // creates a key under the old name
	if err != nil {
		t.Fatal(err)
	}
	k := Keychain{Service: newName, Account: dir, Legacy: oldName}
	got, err := k.Load(ctx)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("moved key differs: %v", err)
	}
	if exec.Command("security", "find-generic-password", "-s", oldName, "-a", dir).Run() == nil {
		t.Fatal("the old item is still there")
	}

	// A machine credential.
	if err := (KeychainItems{Service: oldName}).Set(ctx, "machine", "test", "skmach_x"); err != nil {
		t.Fatal(err)
	}
	items := KeychainItems{Service: newName, Legacy: oldName}
	if v, ok, err := items.Get(ctx, "machine"); err != nil || !ok || v != "skmach_x" {
		t.Fatalf("get = %q %v %v", v, ok, err)
	}
	if _, ok, _ := (KeychainItems{Service: oldName}).Get(ctx, "machine"); ok {
		t.Fatal("the old machine item is still there")
	}
	if _, ok, _ := (KeychainItems{Service: newName}).Get(ctx, "machine"); !ok {
		t.Fatal("not moved to the new name")
	}
}
