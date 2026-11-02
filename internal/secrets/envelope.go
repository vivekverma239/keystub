// Package secrets holds Sealer adapters and the places a master key can
// come from. The envelope sealer encrypts each value with its own data key
// and wraps that key with a master key; where the master key lives (a file,
// the OS keychain, an env var) is a MasterKeySource. A KMS sealer that asks
// the cloud to wrap each value is the next adapter.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/vivekverma239/keystub/internal/core"
)

// Envelope implements core.Sealer with AES-256-GCM envelope encryption.
type Envelope struct{ master []byte }

// NewEnvelope returns a sealer around a 32-byte master key.
func NewEnvelope(master []byte) (*Envelope, error) {
	if len(master) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	return &Envelope{master: master}, nil
}

func (e *Envelope) Name() string { return "envelope" }

func (e *Envelope) Seal(_ context.Context, plaintext []byte) (core.Sealed, error) {
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return core.Sealed{}, err
	}
	wrapped, err := gcmSeal(e.master, dataKey)
	if err != nil {
		return core.Sealed{}, err
	}
	ct, err := gcmSeal(dataKey, plaintext)
	if err != nil {
		return core.Sealed{}, err
	}
	return core.Sealed{WrappedKey: wrapped, Ciphertext: ct}, nil
}

func (e *Envelope) Open(_ context.Context, v core.Sealed) ([]byte, error) {
	dataKey, err := gcmOpen(e.master, v.WrappedKey)
	if err != nil {
		return nil, errors.New("can't unwrap: this data was sealed with a different master key")
	}
	return gcmOpen(dataKey, v.Ciphertext)
}

func gcmSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func gcmOpen(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}
