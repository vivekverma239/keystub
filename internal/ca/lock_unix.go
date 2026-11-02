//go:build unix

package ca

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lock takes an exclusive lock on path, waiting for it. The lock goes
// when the process does, so a crash leaves nothing to clean up. On a
// filesystem without locks (some network and FUSE mounts) it carries on
// unlocked, as before locking was added.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		if noLocks(err) {
			return func() {}, nil
		}
		return nil, fmt.Errorf("ca: lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}

func noLocks(err error) bool {
	return errors.Is(err, syscall.ENOLCK) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP)
}
