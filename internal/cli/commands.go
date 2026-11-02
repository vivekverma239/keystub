package cli

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// The API's objects, as far as the CLI reads them (protocol/api.md).

type limits struct {
	DailyRequests int `json:"dailyRequests"`
	PerMinute     int `json:"perMinute"`
}

func (l *limits) String() string {
	if l == nil || (l.DailyRequests == 0 && l.PerMinute == 0) {
		return "none"
	}
	var parts []string
	if l.DailyRequests > 0 {
		parts = append(parts, strconv.Itoa(l.DailyRequests)+"/day")
	}
	if l.PerMinute > 0 {
		parts = append(parts, strconv.Itoa(l.PerMinute)+"/min")
	}
	return strings.Join(parts, ", ")
}

type savedKey struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Service  string    `json:"service"`
	Version  int       `json:"version"`
	SetAt    time.Time `json:"setAt"`
	Limits   *limits   `json:"limits"`
	LinkedIn []string  `json:"linkedIn"`
}

type link struct {
	Env     string `json:"env"`
	Service string `json:"service"`
	Key     struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"key"`
	Version int       `json:"version"`
	SetAt   time.Time `json:"setAt"`
}

type token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Env       string     `json:"env"`
	Kind      string     `json:"kind"`
	Service   *string    `json:"service"`
	Limits    *limits    `json:"limits"`
	ExpiresAt *time.Time `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt"`
	CreatedAt time.Time  `json:"createdAt"`
	State     string     `json:"state,omitempty"`
	Secret    string     `json:"token,omitempty"` // a new token only
}

func (t token) what() string {
	if t.Service != nil {
		return "a service token for " + *t.Service + " in " + t.Env
	}
	return "an environment token for every service " + t.Env + " links"
}

type project struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Limits *limits `json:"limits"`
}

type environment struct {
	ID     string  `json:"id"`
	Limits *limits `json:"limits"`
}

type service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Hosts   []string `json:"hosts"`
	EnvVars []string `json:"envVars"`
	BaseURL *struct {
		Var  string `json:"var"`
		Path string `json:"path"`
	} `json:"baseUrl"`
}

// varNames are the names of a service's key variables, without templates.
func (s service) varNames() []string {
	var out []string
	for _, v := range s.EnvVars {
		name, _, _ := strings.Cut(v, "=")
		out = append(out, name)
	}
	return out
}

func when(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func limitFlags(p parsed) (*limits, error) {
	if !p.has("daily") && !p.has("per-minute") {
		return nil, nil
	}
	var l limits
	for name, dst := range map[string]*int{"daily": &l.DailyRequests, "per-minute": &l.PerMinute} {
		if v, ok := p.flags[name]; ok {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, usageErr("--%s must be a whole number", name)
			}
			*dst = n
		}
	}
	return &l, nil
}

// limitsChange reads a limits command's --daily, --per-minute and --clear:
// the levels given, or nil for --clear.
func limitsChange(p parsed) (*limits, error) {
	l, err := limitFlags(p)
	if err != nil {
		return nil, err
	}
	if (l == nil) == !p.has("clear") {
		return nil, usageErr("give --daily and/or --per-minute, or --clear")
	}
	return l, nil
}

// keepUnset fills the levels a limits command didn't name from the current
// limits, so --daily alone leaves the per-minute limit as it was.
func keepUnset(l, cur *limits, p parsed) *limits {
	if l == nil || cur == nil {
		return l
	}
	out := *l
	if !p.has("daily") {
		out.DailyRequests = cur.DailyRequests
	}
	if !p.has("per-minute") {
		out.PerMinute = cur.PerMinute
	}
	return &out
}

// printNewToken prints a token just made: the value alone on stdout, so
// `$(keystub tokens create …)` captures it, and what it is on stderr.
func (c *ctx) printNewToken(t token) {
	fmt.Fprintln(c.Stdout, t.Secret)
	fmt.Fprintf(c.Stderr, "Token %s (%s, id %s). Copy it now: it isn't shown again.\n", t.Name, t.what(), t.ID)
}

// --- keys ---

const keysUsage = `keys list [--service S]
       keystub keys add SERVICE --name NAME [--from-env VAR [--env-file FILE]] [--daily N] [--per-minute N]   (the value from stdin, $VAR, or VAR in FILE)
       keystub keys scan FILE
       keystub keys show KEY [--service S]
       keystub keys replace KEY [--from-env VAR [--env-file FILE]] [--service S]
       keystub keys rename KEY NEW_NAME [--service S]
       keystub keys limits KEY [--daily N] [--per-minute N] [--clear] [--service S]
       keystub keys delete KEY [--service S] --yes
KEY is a saved key's name or ID. FILE is a dotenv file such as .env;
keys scan lists the variables in it that a service reads, never values.`

func (c *ctx) keys(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub %s", keysUsage)
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "list":
		p, err := parse(args, []string{"service"}, nil)
		if err != nil {
			return err
		}
		if err := p.want(0, 0, "keys list [--service S]"); err != nil {
			return err
		}
		ks, err := c.listKeys()
		if err != nil {
			return err
		}
		if s := p.flags["service"]; s != "" {
			var keep []savedKey
			for _, k := range ks {
				if k.Service == s {
					keep = append(keep, k)
				}
			}
			ks = keep
		}
		if ks == nil {
			ks = []savedKey{}
		}
		return c.emit(map[string]any{"keys": ks}, func(w io.Writer) {
			if len(ks) == 0 {
				fmt.Fprintln(w, "No saved keys. Add one: keystub keys add SERVICE --name NAME < key.txt")
				return
			}
			var rows [][]string
			for _, k := range ks {
				linked := strings.Join(k.LinkedIn, ", ")
				if linked == "" {
					linked = "-"
				}
				rows = append(rows, []string{k.ID, k.Service, k.Name, "v" + strconv.Itoa(k.Version), k.Limits.String(), linked})
			}
			table(w, []string{"ID", "SERVICE", "NAME", "VERSION", "LIMITS", "LINKED IN"}, rows)
		})
	case "add":
		p, err := parse(args, []string{"name", "from-env", "env-file", "daily", "per-minute"}, nil)
		if err != nil {
			return err
		}
		if len(p.args) > 1 {
			return usageErr("a key's value never goes in an argument, where ps and shell history keep it: pipe it on stdin or use --from-env VAR")
		}
		if err := p.want(1, 1, "keys add SERVICE --name NAME [--from-env VAR [--env-file FILE]]"); err != nil {
			return err
		}
		if strings.TrimSpace(p.flags["name"]) == "" {
			return usageErr("--name is required: saved keys are told apart by name, e.g. --name team")
		}
		l, err := limitFlags(p)
		if err != nil {
			return err
		}
		val, err := c.readValue(p, "real key")
		if err != nil {
			return err
		}
		var out struct {
			Key savedKey `json:"key"`
		}
		body := map[string]any{"service": p.args[0], "name": p.flags["name"], "value": strings.TrimSpace(val)}
		if l != nil {
			body["limits"] = l
		}
		if err := c.call("POST", "/api/keys", body, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			fmt.Fprintf(w, "Saved %s key %q (%s). Link it: keystub envs link ENV %s %q\n", out.Key.Service, out.Key.Name, out.Key.ID, out.Key.Service, out.Key.Name)
		})
	case "scan":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "keys scan FILE"); err != nil {
			return err
		}
		return c.scan(p.args[0])
	case "show":
		p, err := parse(args, []string{"service"}, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "keys show KEY [--service S]"); err != nil {
			return err
		}
		k, err := c.findKey(p.args[0], p.flags["service"])
		if err != nil {
			return err
		}
		return c.emit(map[string]any{"key": k}, func(w io.Writer) {
			linked := strings.Join(k.LinkedIn, ", ")
			if linked == "" {
				linked = "nowhere"
			}
			fmt.Fprintf(w, "ID:         %s\nName:       %s\nService:    %s\nVersion:    %d (set %s)\nLimits:     %s\nLinked in:  %s\n",
				k.ID, k.Name, k.Service, k.Version, when(&k.SetAt), k.Limits.String(), linked)
		})
	case "replace":
		p, err := parse(args, []string{"from-env", "env-file", "service"}, nil)
		if err != nil {
			return err
		}
		if len(p.args) > 1 {
			return usageErr("a key's value never goes in an argument, where ps and shell history keep it: pipe it on stdin or use --from-env VAR")
		}
		if err := p.want(1, 1, "keys replace KEY [--from-env VAR [--env-file FILE]]"); err != nil {
			return err
		}
		k, err := c.findKey(p.args[0], p.flags["service"])
		if err != nil {
			return err
		}
		val, err := c.readValue(p, "new value")
		if err != nil {
			return err
		}
		var out struct {
			Key savedKey `json:"key"`
		}
		if err := c.call("PUT", "/api/keys/"+url.PathEscape(k.ID)+"/value", map[string]string{"value": strings.TrimSpace(val)}, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			fmt.Fprintf(w, "Replaced %q: now version %d, used by %s from the next request.\n", out.Key.Name, out.Key.Version, orNone(out.Key.LinkedIn))
		})
	case "rename":
		p, err := parse(args, []string{"service"}, nil)
		if err != nil {
			return err
		}
		if err := p.want(2, 2, "keys rename KEY NEW_NAME"); err != nil {
			return err
		}
		k, err := c.findKey(p.args[0], p.flags["service"])
		if err != nil {
			return err
		}
		var out struct {
			Key savedKey `json:"key"`
		}
		if err := c.call("PATCH", "/api/keys/"+url.PathEscape(k.ID), map[string]string{"name": p.args[1]}, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) { fmt.Fprintf(w, "Renamed %q to %q.\n", k.Name, out.Key.Name) })
	case "limits":
		p, err := parse(args, []string{"daily", "per-minute", "service"}, []string{"clear"})
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "keys limits KEY [--daily N] [--per-minute N] [--clear]"); err != nil {
			return err
		}
		l, err := limitsChange(p)
		if err != nil {
			return err
		}
		k, err := c.findKey(p.args[0], p.flags["service"])
		if err != nil {
			return err
		}
		l = keepUnset(l, k.Limits, p)
		var out struct {
			Key savedKey `json:"key"`
		}
		if err := c.call("PATCH", "/api/keys/"+url.PathEscape(k.ID), map[string]any{"limits": l}, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) { fmt.Fprintf(w, "Limits for %q: %s.\n", out.Key.Name, out.Key.Limits.String()) })
	case "delete":
		p, err := parse(args, []string{"service"}, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "keys delete KEY --yes"); err != nil {
			return err
		}
		k, err := c.findKey(p.args[0], p.flags["service"])
		if err != nil {
			return err
		}
		if err := c.confirm(fmt.Sprintf("Delete saved key %q (%s)", k.Name, k.Service)); err != nil {
			return err
		}
		if err := c.call("DELETE", "/api/keys/"+url.PathEscape(k.ID), nil, nil); err != nil {
			return err
		}
		return c.emit(map[string]any{"ok": true, "deleted": k.ID}, func(w io.Writer) { fmt.Fprintf(w, "Deleted %q.\n", k.Name) })
	}
	return usageErr("usage: keystub %s", keysUsage)
}

func orNone(envs []string) string {
	if len(envs) == 0 {
		return "no environment yet"
	}
	return strings.Join(envs, ", ")
}

func (c *ctx) listKeys() ([]savedKey, error) {
	var out struct {
		Keys []savedKey `json:"keys"`
	}
	err := c.call("GET", "/api/keys", nil, &out)
	return out.Keys, err
}

// findKey resolves a saved key's ID or name; service narrows names that
// several services share.
func (c *ctx) findKey(ref, service string) (savedKey, error) {
	ks, err := c.listKeys()
	if err != nil {
		return savedKey{}, err
	}
	var match []savedKey
	for _, k := range ks {
		if k.ID == ref {
			if service != "" && k.Service != service {
				return savedKey{}, usageErr("saved key %s is for %s, not %s", ref, k.Service, service)
			}
			return k, nil
		}
		if strings.EqualFold(k.Name, ref) && (service == "" || k.Service == service) {
			match = append(match, k)
		}
	}
	switch len(match) {
	case 0:
		where := ""
		if service != "" {
			where = " for " + service
		}
		return savedKey{}, &Error{Code: ExitNotFound, Message: fmt.Sprintf("no saved key%s named or with ID %q", where, ref)}
	case 1:
		return match[0], nil
	}
	var svcs []string
	for _, k := range match {
		svcs = append(svcs, k.Service)
	}
	return savedKey{}, usageErr("several saved keys are named %q (%s): pass --service or the key's ID", ref, strings.Join(svcs, ", "))
}

// --- environments and links ---

const envsUsage = `envs list
       keystub envs add PROJECT/ENV [--daily N] [--per-minute N]
       keystub envs limits PROJECT/ENV [--daily N] [--per-minute N] [--clear]
       keystub envs delete PROJECT/ENV --yes
       keystub envs link PROJECT/ENV SERVICE KEY [--no-token] [--token-name NAME]
       keystub envs unlink PROJECT/ENV SERVICE
       keystub envs links PROJECT/ENV`

func (c *ctx) envs(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub %s", envsUsage)
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "list":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(0, 0, "envs list"); err != nil {
			return err
		}
		var out struct {
			Environments []environment `json:"environments"`
		}
		if err := c.call("GET", "/api/environments", nil, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			var rows [][]string
			for _, e := range out.Environments {
				rows = append(rows, []string{e.ID, e.Limits.String()})
			}
			table(w, []string{"ENVIRONMENT", "LIMITS"}, rows)
		})
	case "limits":
		p, err := parse(args, []string{"daily", "per-minute"}, []string{"clear"})
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "envs limits PROJECT/ENV [--daily N] [--per-minute N] [--clear]"); err != nil {
			return err
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		l, err := limitsChange(p)
		if err != nil {
			return err
		}
		var es struct {
			Environments []environment `json:"environments"`
		}
		if err := c.call("GET", "/api/environments", nil, &es); err != nil {
			return err
		}
		var env *environment
		for i := range es.Environments {
			if es.Environments[i].ID == p.args[0] {
				env = &es.Environments[i]
			}
		}
		if env == nil {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no environment %q", p.args[0])}
		}
		l = keepUnset(l, env.Limits, p)
		if err := c.call("PATCH", path, map[string]any{"limits": l}, nil); err != nil {
			return err
		}
		out := struct {
			Environment environment `json:"environment"`
		}{environment{ID: env.ID, Limits: zeroIfNil(l)}}
		return c.emit(out, func(w io.Writer) { fmt.Fprintf(w, "Limits for %s: %s.\n", env.ID, l.String()) })
	case "add":
		p, err := parse(args, []string{"daily", "per-minute"}, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "envs add PROJECT/ENV"); err != nil {
			return err
		}
		if _, err := envPath(p.args[0]); err != nil {
			return err
		}
		l, err := limitFlags(p)
		if err != nil {
			return err
		}
		project, name, _ := strings.Cut(p.args[0], "/")
		var ps struct {
			Projects []struct {
				ID string `json:"id"`
			} `json:"projects"`
		}
		if err := c.call("GET", "/api/projects", nil, &ps); err != nil {
			return err
		}
		have := false
		for _, x := range ps.Projects {
			have = have || x.ID == project
		}
		if !have { // a new project: make it first
			if err := c.call("POST", "/api/projects", map[string]any{"name": project}, nil); err != nil {
				return err
			}
		}
		body := map[string]any{"project": project, "name": name}
		if l != nil {
			body["limits"] = l
		}
		var out struct {
			Environment environment `json:"environment"`
		}
		if err := c.call("POST", "/api/environments", body, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			fmt.Fprintf(w, "Made %s. Link a key: keystub envs link %s SERVICE KEY\n", out.Environment.ID, out.Environment.ID)
		})
	case "delete":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "envs delete PROJECT/ENV --yes"); err != nil {
			return err
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		if err := c.confirm("Delete " + p.args[0] + ", revoking its tokens"); err != nil {
			return err
		}
		// Deleted at once; what hosted still has to tell the edge is told by
		// re-syncing the deleted environment.
		if err := c.untilDone("DELETE", path, "POST", path+"/resync"); err != nil {
			return err
		}
		return c.emit(map[string]any{"ok": true}, func(w io.Writer) { fmt.Fprintf(w, "Deleted %s; its tokens are revoked.\n", p.args[0]) })
	case "link":
		p, err := parse(args, []string{"token-name"}, []string{"no-token"})
		if err != nil {
			return err
		}
		if err := p.want(3, 3, "envs link PROJECT/ENV SERVICE KEY [--no-token] [--token-name NAME]"); err != nil {
			return err
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		svc := p.args[1]
		k, err := c.findKey(p.args[2], svc)
		if err != nil {
			return err
		}
		body := map[string]any{"key": k.ID, "serviceToken": !p.has("no-token")}
		if n := p.flags["token-name"]; n != "" {
			body["tokenName"] = n
		}
		var out struct {
			Link  link   `json:"link"`
			Token *token `json:"token"`
		}
		if err := c.call("PUT", path+"/links/"+url.PathEscape(svc), body, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			fmt.Fprintf(c.Stderr, "%s now uses %q for %s (link version %d).\n", out.Link.Env, out.Link.Key.Name, out.Link.Service, out.Link.Version)
			if out.Token != nil {
				c.printNewToken(*out.Token)
			}
		})
	case "unlink":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(2, 2, "envs unlink PROJECT/ENV SERVICE"); err != nil {
			return err
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		if err := c.call("DELETE", path+"/links/"+url.PathEscape(p.args[1]), nil, nil); err != nil {
			return err
		}
		return c.emit(map[string]any{"ok": true}, func(w io.Writer) {
			fmt.Fprintf(w, "Unlinked %s from %s: its tokens are refused for %s until it is linked again.\n", p.args[1], p.args[0], p.args[1])
		})
	case "links":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "envs links PROJECT/ENV"); err != nil {
			return err
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		var out struct {
			Links []link `json:"links"`
		}
		if err := c.call("GET", path+"/links", nil, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			if len(out.Links) == 0 {
				fmt.Fprintf(w, "%s links no keys. Link one: keystub envs link %s SERVICE KEY\n", p.args[0], p.args[0])
				return
			}
			var rows [][]string
			for _, l := range out.Links {
				rows = append(rows, []string{l.Service, l.Key.Name, l.Key.ID, "v" + strconv.Itoa(l.Version), when(&l.SetAt)})
			}
			table(w, []string{"SERVICE", "KEY", "KEY ID", "LINK", "SET"}, rows)
		})
	}
	return usageErr("usage: keystub %s", envsUsage)
}

// --- projects ---

const projectsUsage = `projects list
       keystub projects limits PROJECT [--daily N] [--per-minute N] [--clear]`

func (c *ctx) projects(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub %s", projectsUsage)
	}
	sub, args := args[0], args[1:]
	var out struct {
		Projects []project `json:"projects"`
	}
	switch sub {
	case "list":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(0, 0, "projects list"); err != nil {
			return err
		}
		if err := c.call("GET", "/api/projects", nil, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			var rows [][]string
			for _, x := range out.Projects {
				rows = append(rows, []string{x.ID, x.Limits.String()})
			}
			table(w, []string{"PROJECT", "LIMITS"}, rows)
		})
	case "limits":
		p, err := parse(args, []string{"daily", "per-minute"}, []string{"clear"})
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "projects limits PROJECT [--daily N] [--per-minute N] [--clear]"); err != nil {
			return err
		}
		l, err := limitsChange(p)
		if err != nil {
			return err
		}
		if err := c.call("GET", "/api/projects", nil, &out); err != nil {
			return err
		}
		var pr *project
		for i := range out.Projects {
			if out.Projects[i].ID == p.args[0] {
				pr = &out.Projects[i]
			}
		}
		if pr == nil {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("no project %q", p.args[0])}
		}
		l = keepUnset(l, pr.Limits, p)
		if err := c.call("PATCH", "/api/projects/"+url.PathEscape(pr.ID), map[string]any{"limits": l}, nil); err != nil {
			return err
		}
		pr.Limits = zeroIfNil(l)
		res := struct {
			Project project `json:"project"`
		}{*pr}
		return c.emit(res, func(w io.Writer) { fmt.Fprintf(w, "Limits for project %s: %s.\n", pr.ID, l.String()) })
	}
	return usageErr("usage: keystub %s", projectsUsage)
}

// zeroIfNil is the limits a level has after a change: nil (cleared) reads
// as zero at both levels, as the API sends it.
func zeroIfNil(l *limits) *limits {
	if l == nil {
		return &limits{}
	}
	return l
}

// --- tokens ---

const tokensUsage = `tokens create PROJECT/ENV --name NAME [--ttl 2h] [--service S] [--daily N] [--per-minute N]
                       [--write-env FILE [--base-urls]]
       keystub tokens list PROJECT/ENV
       keystub tokens revoke TOKEN_ID --yes`

func (c *ctx) tokens(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub %s", tokensUsage)
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "create":
		p, err := parse(args, []string{"name", "ttl", "service", "daily", "per-minute", "write-env"}, []string{"base-urls"})
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "tokens create PROJECT/ENV --name NAME"); err != nil {
			return err
		}
		if strings.TrimSpace(p.flags["name"]) == "" {
			return usageErr("--name is required, e.g. --name sandbox-1")
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		l, err := limitFlags(p)
		if err != nil {
			return err
		}
		file := p.flags["write-env"]
		if p.has("write-env") && strings.TrimSpace(file) == "" {
			return usageErr("--write-env needs a file, e.g. --write-env .env")
		}
		if p.has("base-urls") && !p.has("write-env") {
			return usageErr("--base-urls goes with --write-env FILE")
		}
		var plan *tokenFile
		if p.has("write-env") {
			// Everything the file needs is read, and the file checked,
			// before the token is made, so a failure here leaves no token
			// nobody has seen.
			if err := checkWritable(file); err != nil {
				return err
			}
			if plan, err = c.planTokenFile(path, p.flags["service"], p.has("base-urls")); err != nil {
				return err
			}
		}
		body := map[string]any{"name": p.flags["name"]}
		if v := p.flags["ttl"]; v != "" {
			body["ttl"] = v
		}
		if v, ok := p.flags["service"]; ok {
			body["service"] = v
		}
		if l != nil {
			body["limits"] = l
		}
		var out struct {
			Token token `json:"token"`
		}
		if err := c.call("POST", path+"/tokens", body, &out); err != nil {
			return err
		}
		if plan != nil {
			return c.writeToken(file, *plan, out.Token)
		}
		return c.emit(out.Token, func(io.Writer) { c.printNewToken(out.Token) })
	case "list":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "tokens list PROJECT/ENV"); err != nil {
			return err
		}
		path, err := envPath(p.args[0])
		if err != nil {
			return err
		}
		var out struct {
			Tokens []token `json:"tokens"`
		}
		if err := c.call("GET", path+"/tokens", nil, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			var rows [][]string
			for _, t := range out.Tokens {
				svc := "all linked"
				if t.Service != nil {
					svc = *t.Service
				}
				rows = append(rows, []string{t.ID, t.Name, t.Kind, svc, t.Limits.String(), when(t.ExpiresAt), t.State})
			}
			table(w, []string{"ID", "NAME", "KIND", "SERVICES", "LIMITS", "EXPIRES", "STATE"}, rows)
		})
	case "revoke":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "tokens revoke TOKEN_ID --yes"); err != nil {
			return err
		}
		if err := c.confirm("Revoke token " + p.args[0]); err != nil {
			return err
		}
		if err := c.call("POST", "/api/tokens/"+url.PathEscape(p.args[0])+"/revoke", nil, nil); err != nil {
			return err
		}
		return c.emit(map[string]any{"ok": true}, func(w io.Writer) { fmt.Fprintf(w, "Revoked %s.\n", p.args[0]) })
	}
	return usageErr("usage: keystub %s", tokensUsage)
}

// --- services ---

const servicesUsage = `services list
       keystub services add CATALOG_ID
       keystub services add NAME --hosts HOST,… [--header H] [--format "Bearer {key}"] [--env-vars VAR,…]
       keystub services remove SERVICE_ID --yes`

func splitComma(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (c *ctx) services(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub %s", servicesUsage)
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "list":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(0, 0, "services list"); err != nil {
			return err
		}
		var out struct {
			Services []service `json:"services"`
		}
		if err := c.call("GET", "/api/services", nil, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			var rows [][]string
			for _, s := range out.Services {
				rows = append(rows, []string{s.ID, s.Name, strings.Join(s.Hosts, ", "), strings.Join(s.EnvVars, ", ")})
			}
			table(w, []string{"ID", "NAME", "HOSTS", "ENV VARS"}, rows)
		})
	case "add":
		p, err := parse(args, []string{"hosts", "header", "format", "env-vars"}, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "services add CATALOG_ID | NAME --hosts HOST,…"); err != nil {
			return err
		}
		body := map[string]any{"catalog": p.args[0]}
		if p.has("hosts") {
			body = map[string]any{"name": p.args[0], "hosts": splitComma(p.flags["hosts"]), "header": p.flags["header"],
				"format": p.flags["format"], "envVars": splitComma(p.flags["env-vars"])}
		}
		var out struct {
			Service service `json:"service"`
		}
		if err := c.call("POST", "/api/services", body, &out); err != nil {
			return err
		}
		return c.emit(out, func(w io.Writer) {
			fmt.Fprintf(w, "Added %s (%s). Save its key: keystub keys add %s --name NAME < key.txt\n", out.Service.Name, out.Service.ID, out.Service.ID)
		})
	case "remove":
		p, err := parse(args, nil, nil)
		if err != nil {
			return err
		}
		if err := p.want(1, 1, "services remove SERVICE_ID --yes"); err != nil {
			return err
		}
		if err := c.confirm("Remove " + p.args[0] + ", its links and its saved keys"); err != nil {
			return err
		}
		path := "/api/services/" + url.PathEscape(p.args[0])
		if err := c.untilDone("DELETE", path, "DELETE", path); err != nil {
			return err
		}
		return c.emit(map[string]any{"ok": true}, func(w io.Writer) { fmt.Fprintf(w, "Removed %s.\n", p.args[0]) })
	}
	return usageErr("usage: keystub %s", servicesUsage)
}

// --- usage, setup, CA ---

func (c *ctx) usage(args []string) error {
	p, err := parse(args, []string{"by", "range"}, nil)
	if err != nil {
		return err
	}
	if err := p.want(0, 1, "usage [PROJECT/ENV] [--by service,token,key] [--range 24h|7d|30d]"); err != nil {
		return err
	}
	q := url.Values{}
	if len(p.args) == 1 {
		if _, err := envPath(p.args[0]); err != nil {
			return err
		}
		q.Set("env", p.args[0])
	}
	by := p.flags["by"]
	if by == "" {
		by = "service"
	}
	q.Set("by", by)
	if r := p.flags["range"]; r != "" {
		q.Set("range", r)
	}
	var out struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := c.call("GET", "/api/usage?"+q.Encode(), nil, &out); err != nil {
		return err
	}
	return c.emit(out, func(w io.Writer) {
		if len(out.Rows) == 0 {
			fmt.Fprintln(w, "No requests in that range.")
			return
		}
		dims := splitComma(by)
		head := make([]string, 0, len(dims)+4)
		for _, d := range dims {
			head = append(head, strings.ToUpper(d))
		}
		head = append(head, "REQUESTS", "OK", "REFUSED", "COST USD")
		field := map[string]string{"token": "token", "key": "key", "env": "env", "service": "service", "model": "model", "operation": "operation", "project": "project", "hour": "hour"}
		var rows [][]string
		for _, r := range out.Rows {
			var row []string
			for _, d := range dims {
				row = append(row, fmt.Sprint(orDash(r[field[d]])))
			}
			row = append(row, num(r["requests"]), num(r["ok"]), num(r["refused"]), fmt.Sprintf("%.4f", toFloat(r["costUsd"])))
			rows = append(rows, row)
		}
		table(w, head, rows)
	})
}

func orDash(v any) any {
	if v == nil || v == "" {
		return "-"
	}
	return v
}

func toFloat(v any) float64 {
	f, _ := v.(float64)
	return f
}

func num(v any) string { return strconv.FormatInt(int64(toFloat(v)), 10) }

func (c *ctx) setup(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if err := p.want(1, 1, "setup PROJECT/ENV"); err != nil {
		return err
	}
	path, err := envPath(p.args[0])
	if err != nil {
		return err
	}
	var out struct {
		EdgeURL          string   `json:"edgeUrl"`
		GatewayURL       *string  `json:"gatewayUrl"`
		EnvLines         []string `json:"envLines"`
		RemoteProxyLines []string `json:"remoteProxyLines"`
	}
	if err := c.call("GET", path+"/setup", nil, &out); err != nil {
		return err
	}
	return c.emit(out, func(w io.Writer) {
		fmt.Fprintf(w, "# Quick start for %s: SDKs call the edge at %s directly.\n# Replace <token> with a token: keystub tokens create %s --name NAME\n", p.args[0], out.EdgeURL, p.args[0])
		for _, l := range out.EnvLines {
			fmt.Fprintln(w, l)
		}
		if len(out.RemoteProxyLines) > 0 {
			fmt.Fprintln(w, "\n# Or send everything through the remote proxy:")
			for _, l := range out.RemoteProxyLines {
				fmt.Fprintln(w, l)
			}
		}
	})
}

func (c *ctx) ca(args []string) error {
	p, err := parse(args, []string{"o", "output"}, nil)
	if err != nil {
		return err
	}
	if err := p.want(0, 0, "ca [-o FILE]"); err != nil {
		return err
	}
	tok, err := c.credential()
	if err != nil {
		return err
	}
	resp, err := c.do("GET", "/api/ca.pem", tok, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return answerError(resp.StatusCode, b)
	}
	out := p.flags["o"]
	if out == "" {
		out = p.flags["output"]
	}
	if out == "" {
		if c.json {
			return c.emit(map[string]string{"pem": string(b)}, nil)
		}
		_, err := c.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	return c.emit(map[string]string{"path": out}, func(w io.Writer) { fmt.Fprintf(w, "Wrote the CA certificate to %s.\n", out) })
}
