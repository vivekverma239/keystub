package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/vivekverma239/keystub/internal/legacy"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/runenv"
	"github.com/vivekverma239/keystub/internal/secrets"
)

// machineInfo is machine.json: which server this machine is linked to. The
// credential is in the Keychain on a Mac, else in this file (0600).
type machineInfo struct {
	Server     string   `json:"server"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Envs       []string `json:"envs"`
	Credential string   `json:"credential,omitempty"` // only when there is no keychain
}

var machineKeychain = secrets.KeychainItems{Service: "dev.keystub.machine", Legacy: "dev.stubkey.machine"}

// useKeychain is whether the credential goes in the Keychain: on a Mac,
// unless $KEYSTUB_SECRETS=file (a headless box whose keychain is locked).
func useKeychain() bool {
	return machineKeychain.Available() && legacy.Getenv("KEYSTUB_SECRETS") != "file"
}

func keychainAccount(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// edgeCall posts JSON to an edge route and decodes the answer. It returns
// the status, so callers can tell "pending" from a refusal.
func edgeCall(ctx context.Context, server, path, credential string, body, out any) (int, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(server, "/")+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: proxy.EdgeTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("can't reach %s: %w", server, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(rb, &e) == nil && e.Error.Message != "" {
			return resp.StatusCode, errors.New(strings.TrimPrefix(e.Error.Message, "keystub: "))
		}
		return resp.StatusCode, fmt.Errorf("POST %s: %s", path, resp.Status)
	}
	return resp.StatusCode, json.Unmarshal(rb, out)
}

func linkCmd(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	host, _ := os.Hostname()
	name := fs.String("name", strings.Split(host, ".")[0], "what the dashboard calls this machine")
	force := fs.Bool("force", false, "link again though this box is already linked")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: keystub link [--name NAME] [--force] SERVER_URL")
	}
	u, err := parseRemote(fs.Arg(0))
	if err != nil {
		return err
	}
	server := u.String()
	dir, err := homeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var old machineInfo
	if readJSON(filepath.Join(dir, "machine.json"), &old) == nil && !*force {
		return fmt.Errorf("this box is already linked to %s as %s (%s); run keystub unlink first (and revoke it on that server), or pass --force", old.Server, old.Name, old.ID)
	}

	var st proxy.LinkStartResponse
	if _, err := edgeCall(context.Background(), server, "/link", "", map[string]string{"name": *name}, &st); err != nil {
		return err
	}
	fmt.Printf("Linking %s to %s.\n\n  Code: %s\n\nAsk an admin to type this code on the Machines page of its dashboard. Waiting…\n", *name, server, st.UserCode)

	interval := time.Duration(max(st.Interval, 1)) * time.Second
	deadline := pollDeadline(time.Now(), st.ExpiresIn)
	var done proxy.LinkPollResponse
	for {
		time.Sleep(interval)
		status, err := edgeCall(context.Background(), server, "/link/poll", "", map[string]string{"deviceCode": st.DeviceCode}, &done)
		if err == nil {
			break
		}
		switch {
		case (status == http.StatusAccepted || status == 0) && time.Now().Before(deadline):
			continue // waiting, or the server blinked
		case status == http.StatusAccepted, status == http.StatusNotFound:
			return errors.New("the code expired before it was approved; run keystub link again")
		}
		return err
	}

	mi := machineInfo{Server: server, ID: done.Machine.ID, Name: done.Machine.Name, Envs: done.Machine.Envs}
	where := "the macOS Keychain"
	if useKeychain() {
		if err := machineKeychain.Set(context.Background(), keychainAccount(dir), "Keystub machine credential", done.Credential); err != nil {
			return err
		}
	} else {
		mi.Credential = done.Credential
		where = filepath.Join(dir, "machine.json")
	}
	b, _ := json.MarshalIndent(mi, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "machine.json"), b); err != nil {
		return err
	}
	fmt.Printf("Linked as %s (%s), for %s. The credential is in %s.\n\nRun a command:  keystub run -- npm run dev\n", mi.Name, mi.ID, strings.Join(mi.Envs, ", "), where)
	return nil
}

// pollDeadline is when the CLI stops waiting on its own. The server says
// when the request has expired (404); this only stops a CLI whose server
// went quiet, so it is well past the server's expiry and the minute an
// approval in its last seconds is kept.
func pollDeadline(start time.Time, expiresIn int) time.Time {
	return start.Add(time.Duration(expiresIn)*time.Second + 2*time.Minute)
}

// sameServer reports whether two edge URLs name the same server, whatever
// the case of the host, a default port or a trailing slash.
func sameServer(a, b string) bool {
	key := func(s string) string {
		u, err := url.Parse(s)
		if err != nil {
			return s
		}
		port := u.Port()
		if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			port = ""
		}
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port + strings.TrimSuffix(u.EscapedPath(), "/")
	}
	return key(a) == key(b)
}

func unlinkCmd(args []string) error {
	fs := flag.NewFlagSet("unlink", flag.ExitOnError)
	_ = fs.Parse(args)
	dir, err := homeDir()
	if err != nil {
		return err
	}
	// Wherever link put the credential, whatever $KEYSTUB_SECRETS says now.
	var mi machineInfo
	_ = readJSON(filepath.Join(dir, "machine.json"), &mi)
	if mi.Credential == "" && machineKeychain.Available() {
		if err := machineKeychain.Delete(context.Background(), keychainAccount(dir)); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(dir, "machine.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("Unlinked. Revoke the machine on the server's Machines page to stop its tokens too.")
	return nil
}

// linkedMachine returns this machine's link and credential, or nil if it
// isn't linked.
func linkedMachine(dir string) (*machineInfo, string, error) {
	var mi machineInfo
	if err := readJSON(filepath.Join(dir, "machine.json"), &mi); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("machine.json: %w", err)
	}
	cred := mi.Credential
	if cred == "" {
		c, ok, err := machineKeychain.Get(context.Background(), keychainAccount(dir))
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "", errors.New("this machine's credential is missing from the Keychain; run keystub link again")
		}
		cred = c
	}
	return &mi, cred, nil
}

// machineToken asks the linked server for this machine's token called name
// in envID ("" for the machine's first environment).
func machineToken(ctx context.Context, mi *machineInfo, cred, envID, name string) (string, error) {
	if name == "" {
		name = runenv.DefaultKeyName()
	}
	if envID == "" {
		envID = legacy.Getenv("KEYSTUB_ENV")
	}
	var t proxy.MachineTokenResponse
	if _, err := edgeCall(ctx, mi.Server, "/machine/tokens", cred, map[string]string{"env": envID, "name": name}, &t); err != nil {
		return "", fmt.Errorf("%s: %w", mi.Server, err)
	}
	if !strings.HasPrefix(t.Token, core.TokenPrefix) {
		return "", errors.New("the server sent no proxy token")
	}
	return t.Token, nil
}
