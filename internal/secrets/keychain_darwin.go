package secrets

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Keychain keeps the master key in the macOS login keychain, through the
// built-in `security` tool. The key goes in on stdin, never as an argument,
// so it doesn't show in the process list. Each data folder gets its own item.
type Keychain struct {
	Service, Account string
	// ImportFrom is a master.key file from before the keychain was used. It
	// moves into the keychain on first use, then the file is deleted.
	ImportFrom string
	// Legacy is the item's service name from before the rename to Keystub.
	// An item found there moves to Service on first use.
	Legacy string
}

const keychainService = "dev.keystub.master-key"

// legacyKeychainService is the master key's item name before the rename.
const legacyKeychainService = "dev.stubkey.master-key"

func newKeychain(home string) MasterKeySource {
	abs, err := filepath.Abs(home)
	if err != nil {
		abs = home
	}
	return Keychain{Service: keychainService, Account: abs, ImportFrom: filepath.Join(home, "master.key"), Legacy: legacyKeychainService}
}

func keychainAvailable() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

func (k Keychain) Name() string { return "macOS Keychain" }

func (k Keychain) Load(ctx context.Context) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", k.Service, "-a", k.Account, "-w").Output()
	if err == nil {
		return decodeKey(string(out))
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 44 { // 44: no such item
		return nil, fmt.Errorf("read the Keychain: %w", err)
	}

	key, imported, err := k.initialKey(ctx)
	if err != nil {
		return nil, err
	}
	if err := k.store(ctx, key); err != nil {
		return nil, err
	}
	// Read it back before deleting anything, so a failed write can't lose the key.
	out, err = exec.CommandContext(ctx, "security", "find-generic-password", "-s", k.Service, "-a", k.Account, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("read back the Keychain item: %w", err)
	}
	if got, err := decodeKey(string(out)); err != nil || !bytes.Equal(got, key) {
		return nil, errors.New("the Keychain item didn't read back correctly; leaving master.key in place")
	}
	switch imported {
	case fromFile:
		if err := os.Remove(k.ImportFrom); err != nil {
			return nil, fmt.Errorf("moved the master key into the Keychain but couldn't delete %s: %w", k.ImportFrom, err)
		}
	case fromLegacy:
		if err := (KeychainItems{Service: k.Legacy}).Delete(ctx, k.Account); err != nil {
			return nil, fmt.Errorf("moved the master key to %s but couldn't delete the old %s item: %w", k.Service, k.Legacy, err)
		}
	}
	return key, nil
}

// Where initialKey found the key.
const (
	fresh = iota
	fromFile
	fromLegacy
)

// initialKey is the key under the old Keychain name if there is one, else
// the old master.key, else a new key.
func (k Keychain) initialKey(ctx context.Context) ([]byte, int, error) {
	if k.Legacy != "" {
		out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", k.Legacy, "-a", k.Account, "-w").Output()
		if err == nil {
			key, err := decodeKey(string(out))
			return key, fromLegacy, err
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 44 {
			return nil, fresh, fmt.Errorf("read the Keychain: %w", err)
		}
	}
	if k.ImportFrom != "" {
		b, err := os.ReadFile(k.ImportFrom)
		if err == nil {
			if len(b) != 32 {
				return nil, fresh, fmt.Errorf("%s: want 32 bytes, got %d", k.ImportFrom, len(b))
			}
			return b, fromFile, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fresh, err
		}
	}
	b, err := newKey()
	return b, fresh, err
}

func (k Keychain) store(ctx context.Context, key []byte) error {
	h := hex.EncodeToString(key)
	cmd := exec.CommandContext(ctx, "security", "add-generic-password", "-s", k.Service, "-a", k.Account,
		"-l", "Keystub master key", "-U", "-w") // -w last: read the password from stdin
	cmd.Stdin = strings.NewReader(h + "\n" + h + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write the Keychain item: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// KeychainItems keeps small secrets other than the master key (a linked
// machine's credential) in the login keychain, under service, one item per
// account. Values go in on stdin, never as arguments. An item still under
// Legacy (its name before the rename to Keystub) moves to Service when read.
type KeychainItems struct{ Service, Legacy string }

// Available reports whether the keychain can be used here.
func (KeychainItems) Available() bool { return keychainAvailable() }

// Get returns the item for account; ok is false if there is none.
func (k KeychainItems) Get(ctx context.Context, account string) (string, bool, error) {
	v, ok, err := k.get(ctx, k.Service, account)
	if ok || err != nil || k.Legacy == "" {
		return v, ok, err
	}
	v, ok, err = k.get(ctx, k.Legacy, account)
	if !ok || err != nil {
		return v, ok, err
	}
	// Move it to the new name; if that fails, the old item still works.
	if k.Set(ctx, account, "Keystub", v) == nil {
		if got, ok, err := k.get(ctx, k.Service, account); err == nil && ok && got == v {
			_ = (KeychainItems{Service: k.Legacy}).Delete(ctx, account)
		}
	}
	return v, true, nil
}

func (k KeychainItems) get(ctx context.Context, service, account string) (string, bool, error) {
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	if err == nil {
		return strings.TrimSpace(string(out)), true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 44 {
		return "", false, nil
	}
	return "", false, fmt.Errorf("read the Keychain: %w", err)
}

// Set stores value for account, replacing any old one.
func (k KeychainItems) Set(ctx context.Context, account, label, value string) error {
	cmd := exec.CommandContext(ctx, "security", "add-generic-password", "-s", k.Service, "-a", account, "-l", label, "-U", "-w")
	cmd.Stdin = strings.NewReader(value + "\n" + value + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write the Keychain item: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Delete removes the item for account, if there is one.
func (k KeychainItems) Delete(ctx context.Context, account string) error {
	for _, service := range []string{k.Service, k.Legacy} {
		if service == "" {
			continue
		}
		err := exec.CommandContext(ctx, "security", "delete-generic-password", "-s", service, "-a", account).Run()
		var ee *exec.ExitError
		if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 44) {
			return fmt.Errorf("delete the Keychain item: %w", err)
		}
	}
	return nil
}
