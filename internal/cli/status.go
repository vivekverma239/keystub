package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/skills"
)

const statusUsage = "status [PROJECT/ENV] [--env-file FILE] [--json]"

// statusService is one service the environment links.
type statusService struct {
	ID string `json:"id"`
	// How it reaches a program: stand-in (a token, the real key stays in
	// Keystub), minted (a short-lived credential) or secret (the value as
	// it is). Only a token for every service fetches minted and secret ones.
	Kind string `json:"kind"`
	Key  string `json:"key"` // the saved key's name
}

// statusToken is one live token of the environment.
type statusToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Covers    []string   `json:"covers"` // null: every service the environment links
	Delivery  bool       `json:"delivery,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

// statusFile is what the env file holds, by name only.
type statusFile struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	// Variables a service reads that still hold a real key; null when it
	// can't be told (signed out, or the catalog didn't answer).
	RealKeys []string `json:"realKeys"`
	Tokens   []string `json:"tokens"` // variables that hold a Keystub token
}

// status gathers, in one answer, what an agent needs before it decides
// anything: who is signed in, this folder's environment, its services and
// live tokens, what the env file holds, the skill, and what to do next.
// It changes nothing and prints no value; a missing piece is reported, not
// an error.
func (c *ctx) status(args []string) error {
	p, err := parse(args, []string{"env-file"}, nil)
	if err != nil {
		return err
	}
	if err := p.want(0, 1, statusUsage); err != nil {
		return err
	}
	file := p.flags["env-file"]
	if file == "" {
		file = ".env"
	}
	// The environment: named, else the folder's .keystub.json, else <folder>/dev.
	env := readProjectFile(filepath.Dir(file))
	if env == "" {
		env = defaultEnv(file)
	}
	if len(p.args) == 1 {
		env = p.args[0]
	}
	path, err := envPath(env)
	if err != nil {
		return err
	}
	// The arguments the suggested commands need to land on the same
	// environment and file: init and doctor don't read .keystub.json.
	var target []string
	if env != defaultEnv(file) {
		target = append(target, env)
	}
	if p.flags["env-file"] != "" {
		target = append(target, "--env-file", file)
	}
	suggest := func(cmd string, more ...string) string {
		words := append(append([]string{"keystub", cmd}, target...), more...)
		for i, w := range words {
			words[i] = shellQuote(w)
		}
		return strings.Join(words, " ")
	}

	out := map[string]any{"server": c.server, "env": env}
	var next []string

	// The env file, by names only: no value leaves this function. Tokens
	// show by their prefix; which variables are keys needs the catalog.
	sf := statusFile{Path: file, Tokens: []string{}}
	names, values, ferr := dotenvNames(file)
	sf.Exists = ferr == nil
	for _, n := range names {
		if holdsToken(values[n]) {
			sf.Tokens = append(sf.Tokens, n)
		}
	}

	var me struct {
		User    map[string]any `json:"user"`
		Account map[string]any `json:"account"`
	}
	signedIn := true
	if err := c.call("GET", "/api/me", nil, &me); err != nil {
		// Signed out, a key with no server named, or a server that
		// doesn't answer: all reported, so the agent gets a next step.
		signedIn = false
		out["signInError"] = err.Error()
		var ce *Error
		if errors.As(err, &ce) && ce.Code == ExitNoAuth {
			next = append(next, "keystub login --json (a person approves it in the browser); with no browser, set KEYSTUB_API_KEY and KEYSTUB_SERVER")
		} else {
			next = append(next, "fix the sign-in first: "+err.Error())
		}
	}
	out["signedIn"] = signedIn
	if signedIn {
		if me.User != nil {
			out["user"] = me.User["login"]
		}
		if me.Account != nil {
			out["account"] = me.Account["name"]
		}
		next = c.statusEnv(out, path, env, names, values, &sf, suggest, p.flags["env-file"])
	}
	sort.Strings(sf.RealKeys)
	sort.Strings(sf.Tokens)
	out["file"] = sf

	// The skill, wherever it is installed, for every project or this one.
	home := c.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	project, _ := filepath.Abs(filepath.Dir(file))
	copies := skills.Installed(home, project)
	if copies == nil {
		copies = []skills.Copy{}
	}
	out["skill"] = copies
	for _, s := range copies {
		if !s.Current {
			next = append(next, "ask the user, then: keystub skill install (an installed Keystub skill doesn't match this CLI; start a new agent session after)")
			break
		}
	}
	if next == nil {
		next = []string{}
	}
	out["next"] = next

	return c.emit(out, func(w io.Writer) {
		fmt.Fprintf(w, "Server       %s\n", c.server)
		if !signedIn {
			fmt.Fprintln(w, "Signed in    no")
		} else {
			fmt.Fprintf(w, "Signed in    %v (%v)\n", out["user"], out["account"])
		}
		fmt.Fprintf(w, "Environment  %s", env)
		if _, failed := out["envError"]; failed {
			fmt.Fprint(w, " (couldn't read it)")
		} else if ok, _ := out["envExists"].(bool); signedIn && !ok {
			fmt.Fprint(w, " (not made yet)")
		}
		fmt.Fprintln(w)
		if svcs, ok := out["services"].([]statusService); ok && len(svcs) > 0 {
			var parts []string
			for _, s := range svcs {
				parts = append(parts, s.ID+" ("+s.Kind+")")
			}
			fmt.Fprintf(w, "Services     %s\n", strings.Join(parts, ", "))
		}
		if toks, ok := out["tokens"].([]statusToken); ok {
			fmt.Fprintf(w, "Tokens       %d live\n", len(toks))
		}
		switch {
		case !sf.Exists:
			fmt.Fprintf(w, "%-12s not there\n", file)
		case sf.RealKeys == nil:
			fmt.Fprintf(w, "%-12s %d tokens (real keys: can't tell yet)\n", file, len(sf.Tokens))
		default:
			fmt.Fprintf(w, "%-12s %d real keys, %d tokens\n", file, len(sf.RealKeys), len(sf.Tokens))
		}
		for _, n := range next {
			fmt.Fprintln(w, "Next:", n)
		}
	})
}

// statusEnv fills in the environment, its services and tokens, and the
// file's real keys, and says what to do next.
func (c *ctx) statusEnv(out map[string]any, path, env string, names []string, values map[string]string, sf *statusFile, suggest func(string, ...string) string, envFile string) []string {
	var next []string
	var ls struct {
		Links []link `json:"links"`
	}
	exists := true
	if err := c.call("GET", path+"/links", nil, &ls); err != nil {
		var ce *Error
		if !errors.As(err, &ce) || ce.Code != ExitNotFound {
			out["envError"] = err.Error()
			return append(next, "couldn't read "+env+": "+err.Error()+"; try again")
		}
		exists = false
	}
	out["envExists"] = exists

	// Each service's kind: the catalog's, then the account's own.
	kinds := map[string]string{}
	for _, route := range []string{"/api/catalog", "/api/services"} {
		var list struct {
			Services []service `json:"services"`
		}
		if c.call("GET", route, nil, &list) == nil {
			for _, s := range list.Services {
				if s.Kind != "" {
					kinds[s.ID] = s.Kind
				}
			}
		}
	}
	svcs := []statusService{}
	standIns := 0
	linked := map[string]bool{}
	for _, l := range ls.Links {
		linked[l.Service] = true
		k := kinds[l.Service]
		if k == "" {
			k = "stand-in"
		}
		if k == "stand-in" {
			standIns++
		}
		svcs = append(svcs, statusService{ID: l.Service, Kind: k, Key: l.Key.Name})
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].ID < svcs[j].ID })
	out["services"] = svcs

	toks := []statusToken{}
	if exists {
		var tl struct {
			Tokens []token `json:"tokens"`
		}
		if c.call("GET", path+"/tokens", nil, &tl) == nil {
			for _, t := range tl.Tokens {
				if t.RevokedAt != nil || t.State == "revoked" || t.State == "expired" || t.Kind == "key" {
					continue
				}
				toks = append(toks, statusToken{ID: t.ID, Name: t.Name, Covers: t.covers(), Delivery: t.Delivery, ExpiresAt: t.ExpiresAt})
			}
		}
	}
	out["tokens"] = toks

	// Which variables still hold a real key. A delivered secret or minted
	// credential of a linked service is meant to be on the box as it is.
	// setupHelps: a real key setup would swap for a token (a linked
	// stand-in); the others are keys neither init nor setup takes.
	setupHelps := false
	var untaken []string
	proxyOnly := map[string][]string{} // service -> its variables, for services with no base URL
	if sf.Exists {
		if reads, err := c.readers(); err == nil {
			sf.RealKeys = []string{}
			for _, n := range names {
				r, ok := reads[n]
				if !ok || values[n] == "" || holdsToken(values[n]) {
					continue
				}
				id := r.service.ID
				if r.mintedAlt != nil && linked[r.mintedAlt.service.ID] {
					continue // init linked the short-lived key for it
				}
				if (r.secret || r.minted) && linked[id] {
					continue
				}
				sf.RealKeys = append(sf.RealKeys, n)
				switch {
				case !linked[id] || r.secret || r.minted || r.templated:
					untaken = append(untaken, n)
				case r.service.BaseURL != nil && r.service.BaseURL.Var != "":
					setupHelps = true // setup writes the stand-in and the base URL
				default:
					// No base URL: setup skips it; a token in the file
					// works through the proxy (keystub run).
					proxyOnly[id] = append(proxyOnly[id], n)
				}
			}
		}
	}

	// Whether init has anything left to do: its own plan says, so a
	// variable init leaves alone (a template, AWS with no saved key) never
	// sends the agent round in circles.
	initChanges := !exists
	if exists {
		var buf bytes.Buffer
		sub := *c
		sub.json, sub.Stdout, sub.Stderr = true, &buf, io.Discard
		args := []string{env, "--dry-run"}
		if envFile != "" {
			args = append(args, "--env-file", envFile)
		}
		var plan struct {
			Changes bool `json:"changes"`
		}
		if sub.initEnv(args) == nil && json.Unmarshal(buf.Bytes(), &plan) == nil {
			initChanges = plan.Changes
		}
	}

	switch {
	case initChanges:
		next = append(next, suggest("init", "--dry-run", "--json")+" (the plan; it changes nothing), show the user, and on their yes run it with --yes")
	case len(svcs) == 0:
		next = append(next, "link a saved key: keystub keys list --json, then keystub envs link "+env+" SERVICE KEY --no-token --json")
	case setupHelps, !sf.Exists && standIns > 0:
		next = append(next, suggest("setup", "--dry-run", "--json")+", then ask the user before writing tokens in place of the real keys")
	case len(sf.Tokens) > 0:
		next = append(next, suggest("doctor", "--json")+" (checks each token works)")
	}
	if !initChanges && len(proxyOnly) > 0 {
		var ids, vars []string
		for id, vs := range proxyOnly {
			ids = append(ids, id)
			vars = append(vars, vs...)
		}
		sort.Strings(ids)
		sort.Strings(vars)
		more := []string{}
		for _, id := range ids {
			more = append(more, "--service", id)
		}
		next = append(next, fmt.Sprintf("%s still hold real keys for services with no base URL, which setup leaves alone: ask the user, then keystub tokens create %s --name NAME %s --write-env %s --yes --json, and run the app with keystub run -- COMMAND", strings.Join(vars, ", "), shellQuote(env), strings.Join(more, " "), shellQuote(sf.Path)))
	}
	if !initChanges && len(untaken) > 0 {
		next = append(next, fmt.Sprintf("%s still hold real keys that init and setup leave alone (%s shows why under skipped): tell the user", strings.Join(untaken, ", "), suggest("init", "--dry-run", "--json")))
	}
	for _, t := range toks {
		if t.ExpiresAt == nil && t.Delivery {
			next = append(next, fmt.Sprintf("token %s never expires and has a delivery key: if a sandbox or CI job uses it, ask the user whether to replace it with one that expires", t.Name))
		}
	}
	return next
}
