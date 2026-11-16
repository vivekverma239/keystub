package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vivekverma239/keystub/skills"
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
	// Secret is a value handed to the box as it is (a database URL, a
	// deploy key), saved for this environment alone, never shared.
	Secret bool `json:"secret,omitempty"`
	// Custom is a secret no service reads yet: init makes one for it.
	Custom bool `json:"custom,omitempty"`
}

type initPlan struct {
	File      string     `json:"file"`
	Source    string     `json:"source"` // file, example (names only) or code (names found in the code)
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
	secret    bool // a delivered secret's variable (Postgres's DATABASE_URL)
	minted    bool // a minted service's variable (AWS's AWS_ACCESS_KEY_ID): never saved from the file
	// mintedAlt is a minted service that reads the same variable as this
	// stand-in (Fly.io's FLY_API_TOKEN): init links it instead when the
	// account has a key saved for it.
	mintedAlt *reader
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
			if s.Kind == "secret" || s.Kind == "minted" {
				for _, name := range s.Variables {
					// A minted service's plain settings (AWS_REGION, a project)
					// say nothing about a key: only its credential names count.
					if s.Kind == "minted" && !looksSecret(name, "") {
						continue
					}
					r := reader{service: s, added: i == 0, secret: s.Kind == "secret", minted: s.Kind == "minted"}
					if have, ok := out[name]; !ok {
						out[name] = r
					} else if r.minted && !have.secret && !have.minted && have.mintedAlt == nil {
						have.mintedAlt = &r
						out[name] = have
					}
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
	src := envSource{Kind: "file"}
	if file == "" {
		if src, err = findEnvSource("."); err != nil {
			return err
		}
		file = src.File
		if file == "" {
			file = ".env"
		}
	} else if src.Names, src.Values, err = dotenvNames(file); err != nil {
		return err
	}
	if src.Kind != "file" && p.has("write-env") {
		return usageErr("there's no .env to write a token into (init read %s): run keystub setup after init, which writes one", map[string]string{"example": src.File, "code": "the code"}[src.Kind])
	}
	named := p.flags["key-name"] != ""
	plan := initPlan{File: file, Source: src.Kind, KeyName: p.flags["key-name"], WriteEnv: p.has("write-env"), BaseURLs: p.has("base-urls"), DryRun: p.has("dry-run"), Steps: []initStep{}, Skipped: []skipped{}}
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
	names, values := src.Names, src.Values
	if plan.WriteEnv {
		if err := checkWritable(file); err != nil {
			return err
		}
	}
	reads, err := c.readers()
	if err != nil {
		return err
	}
	// A server that can hold secrets has a delivered secret in its
	// catalog (Postgres); a self-hosted one doesn't yet.
	canSecrets := false
	for _, r := range reads {
		canSecrets = canSecrets || r.secret
	}
	secretKey := strings.ReplaceAll(plan.Env, "/", "-")
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
		if ok && r.mintedAlt != nil && pickKey(keys, r.mintedAlt.service.ID, plan.KeyName, false) != nil {
			r = *r.mintedAlt // a short-lived key saved for it: better than a stand-in
		}
		if ok && r.secret && n == "DATABASE_URL" && values[n] != "" && !isPostgresURL(values[n]) {
			ok = false // a MySQL or SQLite URL: kept as a secret of its own
		}
		if !ok && looksSecret(n, values[n]) {
			if !canSecrets {
				if strings.TrimSpace(values[n]) != "" {
					plan.Skipped = append(plan.Skipped, skipped{n, "a secret this server can't hold yet: it stays in the file"})
				}
				continue
			}
			id := localSlug(n)
			r, ok = reader{service: service{ID: id, Name: n, Kind: "secret", Variables: []string{n}}, secret: true}, true
			for _, x := range reads {
				if x.added && x.service.ID == id {
					r = x // made by an init of another project: the service, not its value
				}
			}
		}
		switch {
		case !ok:
			if src.Kind == "code" {
				plan.Skipped = append(plan.Skipped, skipped{n, "read in " + src.FoundIn[n] + "; not a key or secret Keystub knows"})
			}
			continue // not a key variable Keystub knows
		case holdsToken(values[n]):
			plan.Skipped = append(plan.Skipped, skipped{n, "already a Keystub token"})
			continue
		case seen[r.service.ID]:
			plan.Skipped = append(plan.Skipped, skipped{n, "another variable already gives the " + r.service.ID + " key"})
			continue
		}
		st := initStep{Service: r.service.ID, Var: n, AddService: !r.added, SaveKey: true, Link: true, Key: plan.KeyName, Secret: r.secret}
		if r.secret {
			// A secret is this environment's own: another project's database
			// URL is never the one to use.
			st.Key = secretKey
			st.Custom = !r.added && r.service.Kind == "secret" && len(r.service.Hosts) == 0 && !inCatalog(reads, r.service.ID)
		}
		if k := pickKey(keys, st.Service, st.Key, named || r.secret); k != nil {
			// A saved key to link: the file's value isn't read, so it may be
			// empty (a copied .env.example) or anything else.
			st.SaveKey, st.Key, st.Shared = false, k.Name, !r.secret && !strings.EqualFold(k.Name, plan.KeyName)
		} else {
			reason := ""
			switch {
			case r.minted:
				// A file's long-lived key is what minting keeps off the box:
				// it is saved in Keystub with what it may assume, not copied.
				reason = "minted by Keystub from a saved " + r.service.Name + " key: add one in the dashboard (Keys, Add key), then run init again"
			case strings.TrimSpace(values[n]) == "" && src.Kind == "code":
				reason = "read in " + src.FoundIn[n] + " but there's no value: save it with keystub keys add " + st.Service
			case strings.TrimSpace(values[n]) == "" && src.Kind == "example":
				reason = "only in " + src.File + ", with no value: save it with keystub keys add " + st.Service
			case strings.TrimSpace(values[n]) == "":
				reason = "empty"
			}
			switch {
			case reason != "":
			case r.templated:
				reason = "the key is inside a template; save it with keystub keys add " + r.service.ID
			default:
				if _, err := dotenvValue(file, n); err != nil {
					// A value dotenv loaders read differently from the file (a
					// stray # or $, odd quotes) isn't saved: the person fixes
					// the line first.
					reason = err.Error()
				}
			}
			if reason != "" {
				plan.Skipped = append(plan.Skipped, skipped{n, reason})
				continue
			}
		}
		seen[r.service.ID] = true
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

	for i := range plan.Steps {
		st := &plan.Steps[i]
		switch {
		case st.Custom:
			var out struct {
				Service service `json:"service"`
			}
			if err := c.call("POST", "/api/services", map[string]any{"kind": "secret", "name": st.Var, "variable": st.Var}, &out); err != nil {
				return fmt.Errorf("adding the secret %s: %w", st.Var, err)
			}
			st.Service = out.Service.ID
		case st.AddService:
			if err := c.call("POST", "/api/services", map[string]any{"catalog": st.Service}, nil); err != nil {
				return fmt.Errorf("adding %s: %w", st.Service, err)
			}
		}
		if st.SaveKey {
			v, err := dotenvValue(file, st.Var)
			if err != nil {
				return err
			}
			body := map[string]any{"service": st.Service, "name": st.Key, "value": strings.TrimSpace(v)}
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
	if err := writeProjectFile(filepath.Dir(plan.File), plan.Env); err != nil {
		return err
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
	tf, err := c.planTokenFile(path, nil, plan.BaseURLs)
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
		next = append(next, fmt.Sprintf("keystub setup %s --env-file %s --dry-run   (shows what setup writes into %s: stand-ins for the keys and the secrets; only with the person's yes, run it again without --dry-run, adding --yes when it replaces real keys; the file is copied to %s first)", shellQuote(plan.Env), shellQuote(setupFile(plan)), setupFile(plan), c.backupDir()))
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
		if st.AddService && !st.Custom {
			do = append(do, "add the service")
		}
		switch {
		case st.SaveKey && st.Secret:
			do = append(do, fmt.Sprintf("save %s as a secret of %s alone, handed to the box as it is", st.Var, plan.Env))
		case st.SaveKey:
			do = append(do, fmt.Sprintf("save its key from %s as %q", st.Var, plan.KeyName))
		case st.Shared:
			do = append(do, fmt.Sprintf("use the account's saved key %q (to save %s's value instead: --key-name NAME)", st.Key, st.Var))
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

	// An installed skill older than this CLI teaches the agent stale commands.
	home := c.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	cwd, _ := os.Getwd()
	for _, s := range skills.Installed(home, cwd) {
		if !s.Current {
			add("agent skill", "warn", "%s is older than this CLI: keystub skill install, then start a new agent session", s.Path)
		}
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

// setupFile is the dotenv file setup writes after init: the file init read,
// unless that was an example or the code, when it's .env beside it.
func setupFile(plan initPlan) string {
	if plan.Source == "file" {
		return plan.File
	}
	return filepath.Join(filepath.Dir(plan.File), ".env")
}
