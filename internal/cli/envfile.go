package cli

import (
	"fmt"
	"io"
	"strings"
)

// The commands that read and write dotenv files: keys scan, and
// tokens create --write-env.

// scanned is one variable keys scan found: never its value, only whether
// it already holds a proxy token.
type scanned struct {
	Var        string  `json:"var"`
	Service    *string `json:"service"` // the service that reads it, if any
	Added      bool    `json:"added"`   // the account has that service
	ProxyToken bool    `json:"proxyToken"`
}

// scan lists the variables a dotenv file sets, each with the service
// that reads it (the account's own services first, then the catalog).
func (c *ctx) scan(file string) error {
	names, values, err := dotenvNames(file)
	if err != nil {
		return err
	}
	var added, cat struct {
		Services []service `json:"services"`
	}
	if err := c.call("GET", "/api/services", nil, &added); err != nil {
		return err
	}
	if err := c.call("GET", "/api/catalog", nil, &cat); err != nil {
		return err
	}
	reads := map[string]scanned{}
	for i, list := range [][]service{added.Services, cat.Services} {
		for _, s := range list {
			for _, n := range s.varNames() {
				if _, ok := reads[n]; !ok {
					id := s.ID
					reads[n] = scanned{Service: &id, Added: i == 0}
				}
			}
		}
	}
	vars := []scanned{}
	for _, n := range names {
		r := reads[n]
		r.Var = n
		r.ProxyToken = holdsToken(values[n])
		vars = append(vars, r)
	}
	return c.emit(map[string]any{"file": file, "variables": vars}, func(w io.Writer) {
		var rows [][]string
		for _, v := range vars {
			svc, state := "-", "-"
			switch {
			case v.ProxyToken:
				state = "proxy token"
			case v.Service != nil && v.Added:
				state = "real key?"
			case v.Service != nil:
				state = "real key? (add the service: keystub services add " + *v.Service + ")"
			}
			if v.Service != nil {
				svc = *v.Service
			}
			rows = append(rows, []string{v.Var, svc, state})
		}
		table(w, []string{"VARIABLE", "SERVICE", "HOLDS"}, rows)
	})
}

// holdsToken reports whether a value is, or has inside a template, a
// proxy token rather than a real key.
func holdsToken(v string) bool {
	return strings.Contains(v, "sk-stub-") || strings.Contains(v, "skstub")
}

// tokenFile is what tokens create --write-env puts in a file: each
// covered service's key variables, as templates, and its base URL.
type tokenFile struct {
	keys     []string // "OPENAI_API_KEY", or "NAME=template"
	baseURLs []envVar
}

// planTokenFile works out the variables for a token of the environment
// at path: for one service with --service, else for every service the
// environment links. withBase adds each one's base URL on the edge.
func (c *ctx) planTokenFile(path, svc string, withBase bool) (*tokenFile, error) {
	covered := []string{svc}
	if svc == "" {
		var ls struct {
			Links []link `json:"links"`
		}
		if err := c.call("GET", path+"/links", nil, &ls); err != nil {
			return nil, err
		}
		covered = nil
		for _, l := range ls.Links {
			covered = append(covered, l.Service)
		}
	}
	var all struct {
		Services []service `json:"services"`
	}
	if err := c.call("GET", "/api/services", nil, &all); err != nil {
		return nil, err
	}
	var edge string
	if withBase {
		var setup struct {
			EdgeURL string `json:"edgeUrl"`
		}
		if err := c.call("GET", path+"/setup", nil, &setup); err != nil {
			return nil, err
		}
		if edge = strings.TrimSuffix(setup.EdgeURL, "/"); edge == "" {
			return nil, &Error{Code: ExitError, Message: "the server has no edge for base URLs; leave out --base-urls and send requests through keystub run"}
		}
	}
	plan := &tokenFile{}
	for _, id := range covered {
		for _, s := range all.Services {
			if s.ID != id {
				continue
			}
			plan.keys = append(plan.keys, s.EnvVars...)
			if withBase && s.BaseURL != nil && s.BaseURL.Var != "" {
				plan.baseURLs = append(plan.baseURLs, envVar{s.BaseURL.Var, edge + "/s/" + s.ID + s.BaseURL.Path})
			}
		}
	}
	if len(plan.keys) == 0 {
		return nil, usageErr("no key variable to write: the token's services (%s) have none; link a service first, or set its variable by hand", orNone(covered))
	}
	return plan, nil
}

// names are the variables the plan sets in the file.
func (plan tokenFile) names() []string {
	var out []string
	for _, v := range plan.baseURLs {
		out = append(out, v.name)
	}
	for _, k := range plan.keys {
		name, _, _ := strings.Cut(k, "=")
		out = append(out, name)
	}
	return out
}

// confirmWrite asks before a token goes into a dotenv file in place of
// the real keys: --yes, or a "y" typed at the terminal.
func (c *ctx) confirmWrite(file string, plan tokenFile) error {
	return c.confirm(fmt.Sprintf("Write a new token into %s, setting %s (the file is copied to %s first)", file, strings.Join(plan.names(), ", "), c.backupDir()))
}

// writeToken puts a new token into a dotenv file, where the real keys
// were, and prints what it did but never the token. backup is the copy
// of the old file, if there was one.
func (c *ctx) writeToken(file string, plan tokenFile, t token, backup string) error {
	compact := "skstub" + strings.TrimPrefix(t.Secret, "sk-stub-")
	vars := append([]envVar(nil), plan.baseURLs...)
	for _, k := range plan.keys {
		name, tmpl, ok := strings.Cut(k, "=")
		if !ok {
			tmpl = "{key}"
		}
		vars = append(vars, envVar{name, strings.NewReplacer("{key_compact}", compact, "{key}", t.Secret).Replace(tmpl)})
	}
	if err := setDotenv(file, vars); err != nil {
		return &Error{Code: ExitError, Message: fmt.Sprintf("made token %s but couldn't write %s (%v); it isn't shown anywhere, so revoke it: keystub tokens revoke %s --yes", t.ID, file, err, t.ID)}
	}
	var set []string
	for _, v := range vars {
		set = append(set, v.name)
	}
	t.Secret = ""
	out := map[string]any{"token": t, "file": file, "set": set}
	if backup != "" {
		out["backup"] = backup
	}
	return c.emit(out, func(io.Writer) {
		fmt.Fprintf(c.Stderr, "Token %s (%s, id %s) is in %s as %s. It isn't shown anywhere else.\n", t.Name, t.what(), t.ID, file, strings.Join(set, ", "))
		if backup != "" {
			fmt.Fprintf(c.Stderr, "The old file is at %s; put it back with: cp %q %q\n", backup, backup, file)
		}
	})
}
