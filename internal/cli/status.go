package cli

import (
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

const statusUsage = "status [PROJECT/ENV] [--env-file FILE]"

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
	Path     string   `json:"path"`
	Exists   bool     `json:"exists"`
	RealKeys []string `json:"realKeys"` // variables a service reads that still hold a real key; null until signed in (the catalog says which)
	Tokens   []string `json:"tokens"`   // variables that hold a Keystub token
}

// status gathers, in one answer, what an agent needs before it decides
// anything: who is signed in, this folder's environment, its services and
// live tokens, what the env file holds, the skill, and what to do next.
// It changes nothing, and a missing piece is reported, not an error.
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
	out := map[string]any{"server": c.server, "env": env}
	var next []string
	envFlag := ""
	if len(p.args) == 1 || p.flags["env-file"] != "" {
		envFlag = " " + env
		if p.flags["env-file"] != "" {
			envFlag += " --env-file " + shellQuote(file)
		}
	}

	// The env file, by names only: no value leaves this function.
	sf := statusFile{Path: file, RealKeys: []string{}, Tokens: []string{}}
	names, values, ferr := dotenvNames(file)
	sf.Exists = ferr == nil

	var me struct {
		User    map[string]any `json:"user"`
		Account map[string]any `json:"account"`
	}
	signedIn := true
	if err := c.call("GET", "/api/me", nil, &me); err != nil {
		var ce *Error
		if !errors.As(err, &ce) || ce.Code != ExitNoAuth {
			return err
		}
		signedIn = false
	}
	out["signedIn"] = signedIn
	if !signedIn {
		// Which variable is a key needs the catalog; tokens show by their prefix.
		sf.RealKeys = nil
		for _, n := range names {
			if holdsToken(values[n]) {
				sf.Tokens = append(sf.Tokens, n)
			}
		}
		out["file"] = sf
		next = append(next, "keystub login --json (a person approves it in the browser); with no browser, set KEYSTUB_API_KEY and KEYSTUB_SERVER")
	} else {
		if me.User != nil {
			out["user"] = me.User["login"]
		}
		if me.Account != nil {
			out["account"] = me.Account["name"]
		}
		next = c.statusEnv(out, path, env, envFlag, names, values, &sf)
	}
	if ferr == nil {
		sort.Strings(sf.RealKeys)
		sort.Strings(sf.Tokens)
	}

	// The skill, wherever it is installed.
	home := c.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	cwd, _ := os.Getwd()
	copies := skills.Installed(home, cwd)
	if copies == nil {
		copies = []skills.Copy{}
	}
	out["skill"] = copies
	stale := false
	for _, s := range copies {
		stale = stale || !s.Current
	}
	if stale {
		next = append(next, "keystub skill install (an installed copy of the Keystub skill is older than this CLI; start a new agent session after)")
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
		if ok, _ := out["envExists"].(bool); signedIn && !ok {
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
		if sf.Exists {
			if sf.RealKeys == nil {
				fmt.Fprintf(w, "%-12s %d tokens (real keys: sign in to check)\n", file, len(sf.Tokens))
			} else {
				fmt.Fprintf(w, "%-12s %d real keys, %d tokens\n", file, len(sf.RealKeys), len(sf.Tokens))
			}
		}
		for _, n := range next {
			fmt.Fprintln(w, "Next:", n)
		}
	})
}

// statusEnv fills in the environment, its services and tokens, and the
// file's variables, and says what to do next.
func (c *ctx) statusEnv(out map[string]any, path, env, envFlag string, names []string, values map[string]string, sf *statusFile) []string {
	var next []string
	var ls struct {
		Links []link `json:"links"`
	}
	exists := c.call("GET", path+"/links", nil, &ls) == nil
	out["envExists"] = exists

	kinds := map[string]string{}
	var added struct {
		Services []service `json:"services"`
	}
	if c.call("GET", "/api/services", nil, &added) == nil {
		for _, s := range added.Services {
			kinds[s.ID] = s.Kind
		}
	}
	linked := map[string]bool{}
	svcs := []statusService{}
	for _, l := range ls.Links {
		linked[l.Service] = true
		k := kinds[l.Service]
		if k == "" {
			k = "stand-in"
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

	// Which variables still hold a real key, and which a token.
	unlinked := false
	if sf.Exists {
		reads, err := c.readers()
		if err == nil {
			for _, n := range names {
				r, ok := reads[n]
				v := values[n]
				switch {
				case holdsToken(v):
					sf.Tokens = append(sf.Tokens, n)
				case ok && v != "":
					sf.RealKeys = append(sf.RealKeys, n)
					unlinked = unlinked || !linked[r.service.ID]
				}
			}
		}
	}
	out["file"] = sf

	switch {
	case !exists && len(sf.RealKeys) > 0:
		next = append(next, fmt.Sprintf("keystub init%s --dry-run --json, show the user the plan, and on their yes run it with --yes", envFlag))
	case !exists:
		next = append(next, fmt.Sprintf("keystub init%s --dry-run --json (it reads the variables the code uses when there's no .env), or keystub envs add %s --json", envFlag, env))
	case unlinked:
		next = append(next, fmt.Sprintf("keystub init%s --dry-run --json: %s has real keys for services %s doesn't link yet", envFlag, sf.Path, env))
	case len(sf.RealKeys) > 0:
		next = append(next, fmt.Sprintf("keystub setup%s --dry-run --json, then ask the user before writing tokens in place of the real keys", envFlag))
	case len(svcs) == 0:
		next = append(next, fmt.Sprintf("link a saved key: keystub keys list --json, then keystub envs link %s SERVICE KEY --no-token --json", env))
	case sf.Exists && len(sf.Tokens) > 0:
		next = append(next, fmt.Sprintf("keystub doctor%s --json checks the tokens work", envFlag))
	}
	for _, t := range toks {
		if t.ExpiresAt == nil && t.Delivery {
			next = append(next, fmt.Sprintf("token %s never expires and has a delivery key: if a sandbox or CI job uses it, ask the user whether to replace it with one that expires", t.Name))
		}
	}
	return next
}
