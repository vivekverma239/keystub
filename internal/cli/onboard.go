package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// keystub init and keystub doctor: a project's setup in one step, and a
// check that it works. Both are written for a coding agent to run for a
// person: init shows its plan (--dry-run) before it changes anything, and
// rewrites the dotenv file only when asked, after a copy is kept.

// initStep is one service init sets up: the variable its key is read
// from, and what is still to do.
type initStep struct {
	Service    string `json:"service"`
	Var        string `json:"var"`
	AddService bool   `json:"addService"` // the account doesn't have the service yet
	SaveKey    bool   `json:"saveKey"`    // no saved key to use yet: save the file's
	Key        string `json:"key"`        // the saved key's name it links
	Shared     bool   `json:"shared"`     // Key is one the account had already, not --key-name
	Link       bool   `json:"link"`       // the environment doesn't link the service yet
	LinkedTo   string `json:"linkedTo,omitempty"`
}

type initPlan struct {
	File      string     `json:"file"`
	Env       string     `json:"env"`
	KeyName   string     `json:"keyName"`
	MakeEnv   bool       `json:"makeEnv"`
	Steps     []initStep `json:"steps"`
	Skipped   []skipped  `json:"skipped"`
	WriteEnv  bool       `json:"writeEnv"`
	BaseURLs  bool       `json:"baseUrls"`
	WriteVars []string   `json:"writeVars,omitempty"` // what --write-env sets in the file
	Changes   bool       `json:"changes"`
	DryRun    bool       `json:"dryRun"`
	Backup    string     `json:"backup,omitempty"`
	TokenID   string     `json:"tokenId,omitempty"`
	FileSet   []string   `json:"fileSet,omitempty"`
	NextSteps []string   `json:"nextSteps"`
}

// skipped is a variable init leaves alone, and why.
type skipped struct {
	Var    string `json:"var"`
	Reason string `json:"reason"`
}

const initUsage = "init [PROJECT/ENV] [--env-file FILE] [--key-name NAME] [--write-env [--base-urls]] [--dry-run]"

var slugUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

// defaultEnv is the environment init and doctor use when none is named:
// the folder the dotenv file is in, as a project, and dev.
func defaultEnv(file string) string {
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	name := strings.Trim(slugUnsafe.ReplaceAllString(strings.ToLower(filepath.Base(filepath.Dir(abs))), "-"), "-")
	if name == "" {
		name = "app"
	}
	return name + "/dev"
}

// readers maps each key variable to the service that reads it: the
// account's own services first, then the catalog. A variable whose key
// sits inside a template (NAME=Bearer {key}) isn't one init can save
// from, so it maps with templated set.
type reader struct {
	service   service
	added     bool
	templated bool
}

func (c *ctx) readers() (map[string]reader, error) {
	var added, cat struct {
		Services []service `json:"services"`
	}
	if err := c.call("GET", "/api/services", nil, &added); err != nil {
		return nil, err
	}
	if err := c.call("GET", "/api/catalog", nil, &cat); err != nil {
		return nil, err
	}
	out := map[string]reader{}
	for i, list := range [][]service{added.Services, cat.Services} {
		for _, s := range list {
			for _, v := range s.EnvVars {
				name, tmpl, hasTmpl := strings.Cut(v, "=")
				if _, ok := out[name]; !ok {
					out[name] = reader{service: s, added: i == 0, templated: hasTmpl && tmpl != "{key}"}
				}
			}
		}
	}
	return out, nil
}

func (c *ctx) initEnv(args []string) error {
	p, err := parse(args, []string{"env-file", "key-name"}, []string{"write-env", "base-urls", "dry-run"})
	if err != nil {
		return err
	}
	if err := p.want(0, 1, initUsage); err != nil {
		return err
	}
	file := p.flags["env-file"]
	if file == "" {
		file = ".env"
	}
	named := p.flags["key-name"] != ""
	plan := initPlan{File: file, KeyName: p.flags["key-name"], WriteEnv: p.has("write-env"), BaseURLs: p.has("base-urls"), DryRun: p.has("dry-run"), Steps: []initStep{}, Skipped: []skipped{}}
	if plan.BaseURLs && !plan.WriteEnv {
		return usageErr("--base-urls goes with --write-env")
	}
	if plan.KeyName == "" {
		plan.KeyName = "personal"
	}
	plan.Env = defaultEnv(file)
	if len(p.args) == 1 {
		plan.Env = p.args[0]
	}
	path, err := envPath(plan.Env)
	if err != nil {
		return err
	}
	names, values, err := dotenvNames(file)
	if err != nil {
		return err
	}
	if plan.WriteEnv {
		if err := checkWritable(file); err != nil {
			return err
		}
	}
	reads, err := c.readers()
	if err != nil {
		return err
	}
	keys, err := c.listKeys()
	if err != nil {
		return err
	}
	var es struct {
		Environments []environment `json:"environments"`
	}
	if err := c.call("GET", "/api/environments", nil, &es); err != nil {
		return err
	}
	plan.MakeEnv = true
	for _, e := range es.Environments {
		if e.ID == plan.Env {
			plan.MakeEnv = false
		}
	}
	linked := map[string]string{}
	if !plan.MakeEnv {
		var ls struct {
			Links []link `json:"links"`
		}
		if err := c.call("GET", path+"/links", nil, &ls); err != nil {
			return err
		}
		for _, l := range ls.Links {
			linked[l.Service] = l.Key.Name
		}
	}

	// One step per service, from the first of its variables the file sets
	// to a real key.
	seen := map[string]bool{}
	for _, n := range names {
		r, ok := reads[n]
		switch {
		case !ok:
			continue // not a key variable Keystub knows
		case holdsToken(values[n]):
			plan.Skipped = append(plan.Skipped, skipped{n, "already a Keystub token"})
			continue
		case strings.TrimSpace(values[n]) == "":
			plan.Skipped = append(plan.Skipped, skipped{n, "empty"})
			continue
		case r.templated:
			plan.Skipped = append(plan.Skipped, skipped{n, "the key is inside a template; save it with keystub keys add " + r.service.ID})
			continue
		case seen[r.service.ID]:
			plan.Skipped = append(plan.Skipped, skipped{n, "another variable already gives the " + r.service.ID + " key"})
			continue
		}
		// A value dotenv loaders read differently from the file (a stray #
		// or $, odd quotes) isn't saved: the person fixes the line first.
		if _, err := dotenvValue(file, n); err != nil {
			plan.Skipped = append(plan.Skipped, skipped{n, err.Error()})
			continue
		}
		seen[r.service.ID] = true
		st := initStep{Service: r.service.ID, Var: n, AddService: !r.added, SaveKey: true, Link: true, Key: plan.KeyName}
		if k := pickKey(keys, st.Service, plan.KeyName, named); k != nil {
			st.SaveKey, st.Key, st.Shared = false, k.Name, !strings.EqualFold(k.Name, plan.KeyName)
		}
		if to, ok := linked[st.Service]; ok {
			st.Link, st.LinkedTo = false, to
		}
		plan.Steps = append(plan.Steps, st)
	}
	for _, st := range plan.Steps {
		plan.Changes = plan.Changes || st.AddService || st.SaveKey || st.Link
	}
	if plan.WriteEnv && len(plan.Steps) > 0 {
		// What the token file will set: the key variables of every service
		// the environment links once this is done, and with --base-urls
		// their base URLs, as the account's own copy of each service has
		// them (the catalog's only for a service being added).
		byID := map[string]service{}
		for _, r := range reads {
			if _, ok := byID[r.service.ID]; !ok || r.added {
				byID[r.service.ID] = r.service
			}
		}
		covered := map[string]bool{}
		for _, st := range plan.Steps {
			covered[st.Service] = true
		}
		for id := range linked {
			covered[id] = true
		}
		var ids []string
		for id := range covered {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			s := byID[id]
			if plan.BaseURLs && s.BaseURL != nil && s.BaseURL.Var != "" {
				plan.WriteVars = append(plan.WriteVars, s.BaseURL.Var)
			}
			plan.WriteVars = append(plan.WriteVars, s.varNames()...)
		}
	}
	plan.Changes = plan.Changes || plan.MakeEnv || (plan.WriteEnv && len(plan.Steps) > 0)
	if len(plan.Steps) == 0 && len(linked) == 0 {
		if len(plan.Skipped) > 0 {
			var why []string
			for _, sk := range plan.Skipped {
				why = append(why, sk.Var+": "+sk.Reason)
			}
			return &Error{Code: ExitError, Message: fmt.Sprintf("%s has no key init can save: %s", file, strings.Join(why, "; ")), Extra: map[string]any{"skipped": plan.Skipped}}
		}
		return &Error{Code: ExitNotFound, Message: fmt.Sprintf("%s sets no key Keystub knows: see keystub keys scan %s, or add a service with keystub services add", file, file)}
	}

	if plan.DryRun || !plan.Changes {
		plan.NextSteps = c.initNext(plan)
		return c.emit(plan, func(w io.Writer) { c.printPlan(w, plan) })
	}
	if !c.json {
		c.printPlan(c.Stderr, plan)
	}
	if err := c.confirm("Set up " + plan.Env + " as planned"); err != nil {
		return err
	}

	for _, st := range plan.Steps {
		if st.AddService {
			if err := c.call("POST", "/api/services", map[string]any{"catalog": st.Service}, nil); err != nil {
				return fmt.Errorf("adding %s: %w", st.Service, err)
			}
		}
		if st.SaveKey {
			v, err := dotenvValue(file, st.Var)
			if err != nil {
				return err
			}
			body := map[string]any{"service": st.Service, "name": plan.KeyName, "value": strings.TrimSpace(v)}
			if err := c.call("POST", "/api/keys", body, nil); err != nil {
				return fmt.Errorf("saving the %s key: %w", st.Service, err)
			}
		}
	}
	if plan.MakeEnv {
		if err := c.makeEnv(plan.Env); err != nil {
			return err
		}
	}
	for _, st := range plan.Steps {
		if !st.Link {
			continue
		}
		k, err := c.findKey(st.Key, st.Service)
		if err != nil {
			return err
		}
		if err := c.call("PUT", path+"/links/"+st.Service, map[string]any{"key": k.ID, "serviceToken": false}, nil); err != nil {
			return fmt.Errorf("linking %s: %w", st.Service, err)
		}
	}
	if plan.WriteEnv {
		if err := c.initWrite(&plan, path); err != nil {
			return err
		}
	}
	plan.NextSteps = c.initNext(plan)
	return c.emit(plan, func(w io.Writer) {
		fmt.Fprintf(w, "Done: %s is set up.\n", plan.Env)
		if plan.FileSet != nil {
			fmt.Fprintf(w, "%s now holds a Keystub token in %s (token %s).\n", plan.File, strings.Join(plan.FileSet, ", "), plan.TokenID)
			if plan.Backup != "" {
				fmt.Fprintf(w, "The old file is at %s; put it back with: cp %q %q\n", plan.Backup, plan.Backup, plan.File)
			}
		}
		for _, s := range plan.NextSteps {
			fmt.Fprintln(w, "Next:", s)
		}
	})
}

// pickKey is the saved key init uses for a service instead of saving
// the file's: the one named name; else, when no name was given, the
// account's own for the service (a teammate's, say), the one linked in
// the most environments, so a team shares one key rather than each
// person saving a copy. nil means save the file's.
func pickKey(keys []savedKey, service, name string, named bool) *savedKey {
	var best *savedKey
	for i := range keys {
		k := &keys[i]
		if k.Service != service {
			continue
		}
		if strings.EqualFold(k.Name, name) {
			return k
		}
		if !named && (best == nil || len(k.LinkedIn) > len(best.LinkedIn) || (len(k.LinkedIn) == len(best.LinkedIn) && k.Name < best.Name)) {
			best = k
		}
	}
	return best
}

// makeEnv makes an environment, and its project first if it's new.
func (c *ctx) makeEnv(env string) error {
	proj, name, _ := strings.Cut(env, "/")
	var ps struct {
		Projects []project `json:"projects"`
	}
	if err := c.call("GET", "/api/projects", nil, &ps); err != nil {
		return err
	}
	have := false
	for _, x := range ps.Projects {
		have = have || x.ID == proj
	}
	if !have {
		if err := c.call("POST", "/api/projects", map[string]any{"name": proj}, nil); err != nil {
			return err
		}
	}
	return c.call("POST", "/api/environments", map[string]any{"project": proj, "name": name}, nil)
}

// initWrite makes an environment token and puts it in the dotenv file,
// with base URLs on the edge with --base-urls, after keeping a copy of
// the file.
func (c *ctx) initWrite(plan *initPlan, path string) error {
	tf, err := c.planTokenFile(path, "", plan.BaseURLs)
	if err != nil {
		return err
	}
	if plan.Backup, err = c.backupDotenv(plan.File); err != nil {
		return err
	}
	name := c.Hostname
	if name == "" {
		name = "init"
	}
	var out struct {
		Token token `json:"token"`
	}
	if err := c.call("POST", path+"/tokens", map[string]any{"name": name}, &out); err != nil {
		return err
	}
	quiet := *c
	quiet.json, quiet.Stdout, quiet.Stderr = true, io.Discard, io.Discard
	if err := quiet.writeToken(plan.File, *tf, out.Token, plan.Backup); err != nil {
		return err
	}
	plan.TokenID, plan.FileSet = out.Token.ID, tf.names()
	return nil
}

func (c *ctx) initNext(plan initPlan) []string {
	var next []string
	base := "keystub init " + shellQuote(plan.Env) + " --env-file " + shellQuote(plan.File)
	if !strings.EqualFold(plan.KeyName, "personal") {
		base += " --key-name " + shellQuote(plan.KeyName)
	}
	if plan.DryRun && plan.Changes {
		flags := ""
		if plan.WriteEnv {
			flags = " --write-env"
		}
		if plan.BaseURLs {
			flags += " --base-urls"
		}
		next = append(next, base+flags+" --yes   (after the person agrees to the plan)")
		return next
	}
	if plan.FileSet == nil && len(plan.Steps) > 0 {
		next = append(next, fmt.Sprintf("%s --write-env --base-urls --dry-run   (shows which variables a token would replace in %s; only with the person's yes, run it again with --yes in place of --dry-run, which copies the file to %s first)", base, plan.File, c.backupDir()))
	}
	next = append(next, "keystub doctor "+shellQuote(plan.Env)+" --env-file "+shellQuote(plan.File))
	return next
}

func (c *ctx) printPlan(w io.Writer, plan initPlan) {
	fmt.Fprintf(w, "Keystub setup for %s, from %s:\n", plan.Env, plan.File)
	if plan.MakeEnv {
		fmt.Fprintf(w, "  - make the environment %s\n", plan.Env)
	}
	for _, st := range plan.Steps {
		var do []string
		if st.AddService {
			do = append(do, "add the service")
		}
		switch {
		case st.SaveKey:
			do = append(do, fmt.Sprintf("save its key from %s as %q", st.Var, plan.KeyName))
		case st.Shared:
			do = append(do, fmt.Sprintf("use the account's saved key %q, not the one in %s (--key-name NAME saves the file's)", st.Key, st.Var))
		default:
			do = append(do, fmt.Sprintf("use the saved key %q", st.Key))
		}
		if st.Link {
			do = append(do, "link it")
		} else {
			do = []string{fmt.Sprintf("already linked to %q, left as is", st.LinkedTo)}
		}
		fmt.Fprintf(w, "  - %s: %s\n", st.Service, strings.Join(do, ", "))
	}
	for _, s := range plan.Skipped {
		fmt.Fprintf(w, "  - %s left alone: %s\n", s.Var, s.Reason)
	}
	if plan.WriteEnv && len(plan.Steps) > 0 {
		fmt.Fprintf(w, "  - put a new token in %s, setting %s (the file is copied to %s first)\n", plan.File, strings.Join(plan.WriteVars, ", "), c.backupDir())
	} else {
		fmt.Fprintf(w, "  - %s isn't changed\n", plan.File)
	}
	if !plan.Changes {
		fmt.Fprintln(w, "Nothing to do: it's set up already.")
	}
	if plan.DryRun {
		for _, s := range c.initNext(plan) {
			fmt.Fprintln(w, "Next:", s)
		}
	}
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// shellQuote quotes a word for a suggested command line, when it needs it.
func shellQuote(v string) string {
	if shellSafe.MatchString(v) {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// --- doctor ---

// check is one thing doctor looked at.
type check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok, warn or fail
	Detail string `json:"detail"`
}

const doctorUsage = "doctor [PROJECT/ENV] [--env-file FILE]"

func (c *ctx) doctor(args []string) error {
	p, err := parse(args, []string{"env-file"}, nil)
	if err != nil {
		return err
	}
	if err := p.want(0, 1, doctorUsage); err != nil {
		return err
	}
	file := p.flags["env-file"]
	if file == "" {
		file = ".env"
	}
	env := defaultEnv(file)
	if len(p.args) == 1 {
		env = p.args[0]
	}
	path, err := envPath(env)
	if err != nil {
		return err
	}
	var checks []check
	add := func(name, status, format string, a ...any) {
		checks = append(checks, check{name, status, fmt.Sprintf(format, a...)})
	}
	// report prints the checks: with --json one value on stdout, the
	// result, or on a failure the error with the checks in it.
	report := func() error {
		failed := false
		for _, ch := range checks {
			failed = failed || ch.Status == "fail"
		}
		if failed && c.json {
			return &Error{Code: ExitError, Message: "some checks failed", Extra: map[string]any{"env": env, "file": file, "ok": false, "checks": checks}}
		}
		err := c.emit(map[string]any{"env": env, "file": file, "ok": !failed, "checks": checks}, func(w io.Writer) {
			for _, ch := range checks {
				mark := map[string]string{"ok": "ok  ", "warn": "warn", "fail": "FAIL"}[ch.Status]
				fmt.Fprintf(w, "%s  %-22s %s\n", mark, ch.Name, ch.Detail)
			}
		})
		if err == nil && failed {
			return &Error{Code: ExitError, Message: "some checks failed"}
		}
		return err
	}

	var me map[string]any
	if err := c.call("GET", "/api/me", nil, &me); err != nil {
		add("sign-in", "fail", "%s: %v", c.server, err)
		return report()
	}
	add("sign-in", "ok", "%s", c.server)

	var ls struct {
		Links []link `json:"links"`
	}
	if err := c.call("GET", path+"/links", nil, &ls); err != nil {
		add("environment", "fail", "%s: %v (set it up: keystub init %s --env-file %s)", env, err, env, file)
		return report()
	}
	linked := map[string]bool{}
	var svcs []string
	for _, l := range ls.Links {
		linked[l.Service] = true
		svcs = append(svcs, l.Service)
	}
	sort.Strings(svcs)
	if len(svcs) == 0 {
		add("environment", "fail", "%s links no keys (keystub init %s --env-file %s)", env, env, file)
	} else {
		add("environment", "ok", "%s links %s", env, strings.Join(svcs, ", "))
	}

	names, values, err := dotenvNames(file)
	if err != nil {
		add("env file", "fail", "%v", err)
		return report()
	}
	reads, err := c.readers()
	if err != nil {
		return err
	}
	var setup struct {
		EdgeURL string `json:"edgeUrl"`
	}
	_ = c.call("GET", path+"/setup", nil, &setup)
	edge := strings.TrimSuffix(setup.EdgeURL, "/")
	probed := map[string]bool{}
	for _, n := range names {
		r, ok := reads[n]
		if !ok {
			continue
		}
		id := r.service.ID
		v := values[n]
		switch {
		case !holdsToken(v):
			if linked[id] {
				add(n, "warn", "still the real %s key; keystub init %s --env-file %s --write-env swaps it for a token (it asks first)", id, env, file)
			} else {
				add(n, "warn", "a real %s key, and %s doesn't link %s", id, env, id)
			}
		case !linked[id]:
			add(n, "fail", "a Keystub token, but %s doesn't link %s: keystub envs link %s %s KEY", env, id, env, id)
		case edge == "" || probed[id]:
			add(n, "ok", "a Keystub token")
		default:
			probed[id] = true
			status, detail := c.probe(edge, id, tokenIn(v))
			add(n, status, "%s", detail)
		}
	}
	// Each linked service's base URL variable, where the file sets it.
	baseOf := map[string]service{}
	for _, r := range reads {
		if b := r.service.BaseURL; b != nil && b.Var != "" && linked[r.service.ID] {
			baseOf[b.Var] = r.service
		}
	}
	for _, n := range names {
		s, ok := baseOf[n]
		if !ok || edge == "" {
			continue
		}
		want := edge + "/s/" + s.ID + s.BaseURL.Path
		if strings.TrimSuffix(values[n], "/") == strings.TrimSuffix(want, "/") {
			add(n, "ok", "points at Keystub")
		} else {
			add(n, "warn", "is %s, not Keystub's %s", values[n], want)
		}
	}
	return report()
}

var tokenPattern = regexp.MustCompile(`(sk-stub-|skstub)[A-Za-z0-9_-]+`)

// tokenIn is the token inside a value, which may be a template.
func tokenIn(v string) string { return tokenPattern.FindString(v) }

// probe sends one request with the token through the edge to the
// service, and says whether Keystub took it. A Keystub error is a
// failure; any answer from the service means the swap worked, though a
// 401 or 403 there means the saved key itself was turned down.
func (c *ctx) probe(edge, svc, tok string) (status, detail string) {
	req, err := http.NewRequest("GET", edge+"/s/"+svc+"/", nil)
	if err != nil {
		return "fail", err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.Client.Do(req)
	if err != nil {
		return "fail", "couldn't reach the edge: " + unwrapURLError(err).Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var ke struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &ke) == nil && ke.Error.Type == "keystub" {
		return "fail", fmt.Sprintf("Keystub refused the token (HTTP %d): %s", resp.StatusCode, ke.Error.Message)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "warn", fmt.Sprintf("the token works, but %s turned the saved key down (HTTP %d): check it, or replace it with keystub keys replace", svc, resp.StatusCode)
	}
	return "ok", fmt.Sprintf("the token works: %s answered through Keystub (HTTP %d)", svc, resp.StatusCode)
}
