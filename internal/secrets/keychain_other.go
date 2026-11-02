//go:build !darwin

package secrets

import (
	"context"
	"errors"
)

// Keychain is only implemented on macOS so far. Windows Credential Manager
// and Linux Secret Service are the next adapters behind the same interface.
type Keychain struct{}

func newKeychain(string) MasterKeySource { return Keychain{} }

func keychainAvailable() bool { return false }

func (Keychain) Name() string { return "OS keychain" }

func (Keychain) Load(context.Context) ([]byte, error) {
	return nil, errors.New("the OS keychain isn't supported on this platform yet; use --secrets env or file")
}

// KeychainItems is only implemented on macOS; elsewhere callers fall back
// to a 0600 file.
type KeychainItems struct{ Service, Legacy string }

func (KeychainItems) Available() bool { return false }

func (KeychainItems) Get(context.Context, string) (string, bool, error) {
	return "", false, errors.New("the OS keychain isn't supported on this platform yet")
}

func (KeychainItems) Set(context.Context, string, string, string) error {
	return errors.New("the OS keychain isn't supported on this platform yet")
}

func (KeychainItems) Delete(context.Context, string) error { return nil }
