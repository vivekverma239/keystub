//go:build !unix

package ca

// lock is a no-op where flock doesn't exist: parallel first starts may
// then race to create the CA.
func lock(string) (func(), error) { return func() {}, nil }
