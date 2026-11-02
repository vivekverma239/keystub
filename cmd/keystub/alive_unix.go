//go:build unix

package main

import (
	"errors"
	"syscall"
)

// processAlive reports whether pid is a running process (one owned by
// another user counts).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
