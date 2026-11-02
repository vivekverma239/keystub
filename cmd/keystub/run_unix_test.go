//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestSIGINTReachesTheChildWithoutATerminal(t *testing.T) {
	old := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = old }()
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()
	err := runChild("/bin/sh", []string{"sh", "-c", `trap "exit 42" INT; i=0; while [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done; exit 1`}, nil)
	if c, ok := err.(exitCode); !ok || c != 42 {
		t.Fatalf("got %v, want the child's exit 42 from its INT trap", err)
	}
}

func TestNohupKeepsSIGHUPIgnored(t *testing.T) {
	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)
	for _, s := range stopSignals() {
		if s == syscall.SIGHUP {
			t.Fatal("SIGHUP is caught though the process ignores it")
		}
	}
	err := runChild("/bin/sh", []string{"sh", "-c", `kill -HUP $$; exit 3`}, nil)
	if c, ok := err.(exitCode); !ok || c != 3 {
		t.Fatalf("got %v: the child didn't keep ignoring SIGHUP", err)
	}
}
