package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vivekverma239/keystub/internal/cli"
	"github.com/vivekverma239/keystub/internal/legacy"
)

// cliMain runs one of the API commands (keys, envs, tokens…) and exits
// with its code.
func cliMain(cmd string, args []string) {
	dir, err := homeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keystub:", err)
		os.Exit(cli.ExitError)
	}
	host, _ := os.Hostname()
	os.Exit(cli.Main(cli.Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: legacy.Getenv, Home: dir, Hostname: host,
		StdinTerminal: isTerminal(os.Stdin), ReadSecret: readSecret,
	}, cmd, args))
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// readSecret reads a line from the terminal with echo off, using stty so
// no terminal library is needed.
func readSecret(prompt string) (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("no terminal to read from; pipe the value on stdin or use --from-env VAR")
	}
	defer tty.Close()
	stty := func(arg string) error {
		c := exec.Command("stty", arg)
		c.Stdin = tty
		return c.Run()
	}
	if err := stty("-echo"); err != nil {
		return "", fmt.Errorf("can't turn off echo; pipe the value on stdin or use --from-env VAR")
	}
	defer func() { _ = stty("echo"); fmt.Fprintln(os.Stderr) }()
	// Ctrl-C would end the process before the deferred stty, leaving the
	// shell with echo off, so turn it back on first.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	type read struct {
		line string
		err  error
	}
	got := make(chan read, 1)
	fmt.Fprint(os.Stderr, prompt)
	go func() {
		line, err := bufio.NewReader(tty).ReadString('\n')
		got <- read{line, err}
	}()
	select {
	case r := <-got:
		if r.err != nil && r.line == "" {
			return "", r.err
		}
		return strings.TrimRight(r.line, "\r\n"), nil
	case <-sig:
		_ = stty("echo")
		fmt.Fprintln(os.Stderr)
		os.Exit(130)
		return "", nil
	}
}
