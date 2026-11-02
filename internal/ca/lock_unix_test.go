//go:build unix

package ca

import (
	"fmt"
	"syscall"
	"testing"
)

func TestNoLocksCarriesOn(t *testing.T) {
	for _, err := range []error{syscall.ENOLCK, syscall.EOPNOTSUPP, fmt.Errorf("wrapped: %w", syscall.ENOTSUP)} {
		if !noLocks(err) {
			t.Errorf("%v: a filesystem without locks stops the CA", err)
		}
	}
	if noLocks(syscall.EBADF) {
		t.Error("EBADF taken for a filesystem without locks")
	}
}
