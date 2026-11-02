//go:build !unix

package main

import "os"

// processAlive reports whether pid is a running process: on Windows,
// finding it fails once it has exited.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	p.Release()
	return true
}
