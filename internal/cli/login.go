package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// credentials is what `keystub login` keeps in cli.json (mode 0600): the
// server it signed in to and the skcli_ token that acts as that user.
type credentials struct {
	Server  string `json:"server"`
	Token   string `json:"token"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
	User struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
}

func (c *ctx) credentialsPath() string { return filepath.Join(c.Home, credentialsFile) }

func (c *ctx) loadCredentials() (credentials, error) {
	var cr credentials
	b, err := os.ReadFile(c.credentialsPath())
	if err != nil {
		return cr, err
	}
	return cr, json.Unmarshal(b, &cr)
}

func (c *ctx) saveCredentials(cr credentials) error {
	if err := os.MkdirAll(c.Home, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(cr, "", "  ")
	tmp := c.credentialsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil { // an older file's mode doesn't carry over
		return err
	}
	return os.Rename(tmp, c.credentialsPath())
}

// login signs in with a code approved in the browser, against the hosted
// /api/cli/login routes (protocol/api.md).
func (c *ctx) login(args []string) error {
	p, err := parse(args, []string{"name"}, []string{"no-browser"})
	if err != nil {
		return err
	}
	if err := p.want(0, 0, "login [--name NAME] [--server URL] [--no-browser]"); err != nil {
		return err
	}
	if local := c.localServer(); local != "" && sameServer(local, c.server) {
		return c.emit(map[string]any{"server": c.server, "selfHosted": true}, func(w io.Writer) {
			fmt.Fprintf(w, "%s is the keystub serve on this machine: the CLI uses its admin API key, so there's nothing to sign in to.\n", c.server)
		})
	}
	name := p.flags["name"]
	if name == "" {
		name = c.Hostname
	}
	var start struct {
		Code      string `json:"code"`
		URL       string `json:"url"`
		Poll      string `json:"poll"`
		Interval  int    `json:"interval"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := c.send("POST", "/api/cli/login", "", map[string]string{"name": name}, &start); err != nil {
		var ce *Error
		if errors.As(err, &ce) && ce.Code == ExitNotFound {
			return &Error{Code: ExitNoAuth, Message: c.server + " doesn't sign in with a code: set KEYSTUB_API_KEY to an API key it gave you (for a self-hosted server, the key in its admin.token)"}
		}
		return err
	}
	if start.Poll == "" || start.Code == "" {
		return errors.New("the server's login answer has no code")
	}
	fmt.Fprintf(c.Stderr, "Approve the code %s at %s\n", start.Code, start.URL)
	if !p.has("no-browser") && c.OpenURL != nil && c.OpenURL(start.URL) == nil {
		fmt.Fprintln(c.Stderr, "(opened in your browser)")
	}
	fmt.Fprintln(c.Stderr, "Waiting…")
	interval := 5 * time.Second // RFC 8628's default, so a missing interval never means a tight loop
	if start.Interval > 0 {
		interval = time.Duration(start.Interval) * time.Second
	}
	deadline := time.Now().Add(time.Duration(max(start.ExpiresIn, 1)) * time.Second)
	for {
		resp, err := c.do("POST", "/api/cli/login/poll", "", map[string]string{"poll": start.Poll})
		if err != nil {
			return err
		}
		switch resp.StatusCode {
		case http.StatusAccepted:
			resp.Body.Close()
			if time.Now().After(deadline) {
				return &Error{Code: ExitNoAuth, Message: "the code expired before it was approved; run keystub login again"}
			}
			c.Sleep(interval)
			continue
		case http.StatusGone:
			resp.Body.Close()
			return &Error{Code: ExitNoAuth, Message: "the code expired or was turned down; run keystub login again"}
		}
		cr := credentials{}
		err = decodeAnswer(resp, &cr)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if !strings.HasPrefix(cr.Token, "skcli_") {
			return errors.New("the server's login answer has no token")
		}
		cr.Server = c.server
		if err := c.saveCredentials(cr); err != nil {
			return err
		}
		out := map[string]any{"server": cr.Server, "account": cr.Account, "user": cr.User}
		return c.emit(out, func(w io.Writer) {
			fmt.Fprintf(w, "Signed in to %s as %s, in %s.\n", cr.Server, cr.User.Name, cr.Account.Name)
		})
	}
}

func (c *ctx) logout(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if err := p.want(0, 0, "logout"); err != nil {
		return err
	}
	cr, err := c.loadCredentials()
	if errors.Is(err, os.ErrNotExist) {
		return c.emit(map[string]any{"ok": true, "signedIn": false}, func(w io.Writer) { fmt.Fprintln(w, "Not signed in.") })
	}
	ended := c.endSession(cr)
	if err := os.Remove(c.credentialsPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return c.emit(map[string]any{"ok": true, "server": cr.Server, "ended": ended}, func(w io.Writer) {
		if ended {
			fmt.Fprintf(w, "Signed out of %s.\n", cr.Server)
			return
		}
		fmt.Fprintf(w, "Signed out here, but %s didn't confirm the session ended; revoke it on the dashboard's Account page.\n", cr.Server)
	})
}

// endSession asks the server the login came from, and only that one, to
// end its CLI session. A 401 means it had already ended.
func (c *ctx) endSession(cr credentials) bool {
	if cr.Server == "" || cr.Token == "" {
		return false
	}
	// Not the client's 30 seconds: signing out here shouldn't wait on a slow server.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(cr.Server, "/")+"/api/cli/logout", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cr.Token)
	resp, err := c.Client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
}

func (c *ctx) whoami(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if err := p.want(0, 0, "whoami"); err != nil {
		return err
	}
	var me map[string]any
	if err := c.call("GET", "/api/me", nil, &me); err != nil {
		return err
	}
	me["serverUrl"] = c.server
	delete(me, "csrf") // a browser session's, of no use here
	return c.emit(me, func(w io.Writer) {
		name := func(v any) string {
			m, _ := v.(map[string]any)
			for _, k := range []string{"name", "login", "id"} {
				if s, ok := m[k].(string); ok && s != "" {
					return s
				}
			}
			return ""
		}
		fmt.Fprintf(w, "Server:   %s\n", c.server)
		if u := name(me["user"]); u != "" {
			fmt.Fprintf(w, "User:     %s\n", u)
		}
		if a := name(me["account"]); a != "" {
			fmt.Fprintf(w, "Account:  %s\n", a)
		}
		if k := name(me["apiKey"]); k != "" {
			fmt.Fprintf(w, "API key:  %s\n", k)
		}
		if ns, _ := me["notices"].([]any); len(ns) > 0 {
			fmt.Fprintln(w, "\nNotices:")
			for _, n := range ns {
				fmt.Fprintf(w, "  - %v\n", n)
			}
		}
	})
}
