package cli

// keystub connect: finds where this code deploys to (fly.toml, a wrangler
// config, a convex/ folder) and saves, for each, a key Keystub mints a
// short-lived deploy sign-in from for every session, made from the logins
// already on this machine where it can be:
//
//   - Fly.io: `fly tokens create deploy -a APP`, with the fly CLI's login;
//   - Convex: the Convex CLI's login (~/.convex/config.json), which can make
//     deploy keys for the deployment;
//   - Cloudflare: no CLI login can make tokens, so it opens the page for an
//     account token, says what to tick, and checks the pasted token is one
//     (a personal token from My Profile can't make tokens there).
//
// init asks the same at its end.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const connectUsage = "connect [PROJECT/ENV] [--dir DIR] [--only fly,convex,cloudflare] [--dry-run]"

// deployTarget is somewhere this code deploys to that Keystub can mint a
// short-lived deploy sign-in for.
type deployTarget struct {
	Service string `json:"service"` // fly-minted, convex, cloudflare-minted
	Name    string `json:"name"`    // Fly.io, Convex, Cloudflare
	Kind    string `json:"kind"`    // fly, convex, cloudflare (for --only)
	// Target is the Fly.io app, the Convex deployment or the Worker; empty
	// when the code doesn't say (a Convex deployment that's only named in
	// the dashboard).
	Target  string   `json:"target,omitempty"`
	Account string   `json:"account,omitempty"` // a Cloudflare account ID the config names
	File    string   `json:"file"`
	Others  []string `json:"others,omitempty"` // more of the same kind: an environment links one each
	Linked  bool     `json:"linked"`
	Done    string   `json:"done,omitempty"` // what connect did
	Skipped string   `json:"skipped,omitempty"`
	env     string   // the environment it is being connected for
}

var (
	flyApp        = regexp.MustCompile(`(?m)^\s*app\s*=\s*["']([^"']+)["']`)
	tomlName      = regexp.MustCompile(`(?m)^name\s*=\s*["']([^"']+)["']`)
	tomlAccount   = regexp.MustCompile(`(?m)^account_id\s*=\s*["']([0-9a-fA-F]{32})["']`)
	jsonName      = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
	jsonAccount   = regexp.MustCompile(`"account_id"\s*:\s*"([0-9a-fA-F]{32})"`)
	convexProd    = regexp.MustCompile(`(?m)^\s*(?:export\s+)?CONVEX_(?:DEPLOYMENT|DEPLOY_KEY)\s*=\s*["']?prod:([a-z0-9-]+)`)
	convexName    = regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9]+$`)
	cfAccountID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	wranglerOAuth = regexp.MustCompile(`(?m)^oauth_token\s*=\s*"([^"]+)"`)
)

// skipDirs are never searched for deploy configs.
var deploySkipDirs = map[string]bool{"node_modules": true, ".git": true, "dist": true, "build": true, "vendor": true, ".next": true, ".venv": true, "venv": true, ".wrangler": true, "_generated": true}

// detectDeploys looks up to three folders deep under dir.
func detectDeploys(dir string) []deployTarget {
	var found []deployTarget
	root := filepath.Clean(dir)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(filepath.Separator)) + 1
		}
		if d.IsDir() {
			if path != root && (deploySkipDirs[d.Name()] || depth > 3) {
				return filepath.SkipDir
			}
			if d.Name() == "convex" && path != root && isConvexDir(path) {
				found = append(found, deployTarget{Service: "convex", Name: "Convex", Kind: "convex", Target: convexDeployment(filepath.Dir(path)), File: rel})
			}
			return nil
		}
		read := func() string {
			b, err := os.ReadFile(path)
			if err != nil || len(b) > 1<<20 {
				return ""
			}
			return string(b)
		}
		switch d.Name() {
		case "fly.toml":
			if m := flyApp.FindStringSubmatch(read()); m != nil {
				found = append(found, deployTarget{Service: "fly-minted", Name: "Fly.io", Kind: "fly", Target: m[1], File: rel})
			}
		case "wrangler.toml":
			s := read()
			// Top-level keys only: [env.*] tables have their own name.
			if i := strings.Index(s, "\n["); i >= 0 {
				s = s[:i]
			}
			if m := tomlName.FindStringSubmatch(s); m != nil {
				t := deployTarget{Service: "cloudflare-minted", Name: "Cloudflare", Kind: "cloudflare", Target: m[1], File: rel}
				if a := tomlAccount.FindStringSubmatch(s); a != nil {
					t.Account = strings.ToLower(a[1])
				}
				found = append(found, t)
			}
		case "wrangler.json", "wrangler.jsonc":
			s := read()
			if m := jsonName.FindStringSubmatch(s); m != nil {
				t := deployTarget{Service: "cloudflare-minted", Name: "Cloudflare", Kind: "cloudflare", Target: m[1], File: rel}
				if a := jsonAccount.FindStringSubmatch(s); a != nil {
					t.Account = strings.ToLower(a[1])
				}
				found = append(found, t)
			}
		}
		return nil
	})
	// One of each: an environment links one key per service. The rest are
	// named so the person can pick another with --only and a later run.
	var out []deployTarget
	at := map[string]int{}
	for _, t := range found {
		if i, ok := at[t.Service]; ok {
			if t.Target != "" && t.Target != out[i].Target {
				out[i].Others = append(out[i].Others, t.Target)
			}
			continue
		}
		at[t.Service] = len(out)
		out = append(out, t)
	}
	return out
}

// isConvexDir is a convex/ folder of Convex functions.
func isConvexDir(path string) bool {
	for _, n := range []string{"schema.ts", "schema.js", "_generated", "tsconfig.json"} {
		if _, err := os.Stat(filepath.Join(path, n)); err == nil {
			return true
		}
	}
	return false
}

// convexDeployment is the production deployment an env file beside the
// Convex project names (CONVEX_DEPLOYMENT=prod:NAME, or a production deploy
// key's prefix: only the part before | is read), or "".
func convexDeployment(dir string) string {
	files, _ := filepath.Glob(filepath.Join(dir, ".env*"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		if m := convexProd.FindStringSubmatch(string(b)); m != nil {
			return m[1]
		}
	}
	return ""
}

// Where connect reaches outside Keystub; tests replace them.
var (
	lookFly = func() (string, error) {
		if p, err := exec.LookPath("fly"); err == nil {
			return p, nil
		}
		return exec.LookPath("flyctl")
	}
	runFly = func(path string, args ...string) ([]byte, error) {
		cmd := exec.Command(path, args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			if s := strings.TrimSpace(stderr.String()); s != "" {
				return nil, errors.New(lastLine(s))
			}
			return nil, err
		}
		return out, nil
	}
	convexAPI     = "https://api.convex.dev/v1"
	cloudflareAPI = "https://api.cloudflare.com/client/v4"
)

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (c *ctx) connect(args []string) error {
	p, err := parse(args, []string{"dir", "only"}, []string{"dry-run"})
	if err != nil {
		return err
	}
	if err := p.want(0, 1, connectUsage); err != nil {
		return err
	}
	dir := p.flags["dir"]
	if dir == "" {
		dir = "."
	}
	env := ""
	if len(p.args) == 1 {
		env = p.args[0]
	} else if pf := readProjectFile(dir); pf != "" {
		env = pf
	} else {
		return usageErr("name the environment: keystub %s (or run keystub init first, which remembers it here)", connectUsage)
	}
	only := map[string]bool{}
	for _, k := range strings.Split(p.flags["only"], ",") {
		if k = strings.TrimSpace(k); k != "" {
			if k != "fly" && k != "convex" && k != "cloudflare" {
				return usageErr("--only takes fly, convex and cloudflare")
			}
			only[k] = true
		}
	}
	targets := detectDeploys(dir)
	if len(only) > 0 {
		var keep []deployTarget
		for _, t := range targets {
			if only[t.Kind] {
				keep = append(keep, t)
			}
		}
		targets = keep
	}
	if len(targets) == 0 {
		return &Error{Code: ExitNotFound, Message: fmt.Sprintf("found no fly.toml, wrangler config or convex/ folder under %s", dir)}
	}
	return c.connectTargets(env, targets, p.has("dry-run"))
}

// connectTargets links what isn't linked yet, asking first for each.
func (c *ctx) connectTargets(env string, targets []deployTarget, dryRun bool) error {
	path, err := envPath(env)
	if err != nil {
		return err
	}
	var ls struct {
		Links []link `json:"links"`
	}
	exists := true
	if err := c.call("GET", path+"/links", nil, &ls); err != nil {
		var e *Error
		if !errors.As(err, &e) || e.Code != ExitNotFound {
			return err
		}
		exists = false
	}
	for i := range targets {
		for _, l := range ls.Links {
			if l.Service == targets[i].Service {
				targets[i].Linked = true
			}
		}
	}
	out := struct {
		Env     string         `json:"env"`
		Targets []deployTarget `json:"targets"`
		DryRun  bool           `json:"dryRun,omitempty"`
	}{env, targets, dryRun}
	if dryRun {
		return c.emit(out, func(w io.Writer) { c.printTargets(w, env, targets) })
	}
	if !c.json {
		c.printTargets(c.Stderr, env, targets)
	}
	keyName := strings.ReplaceAll(env, "/", "-")
	var added map[string]bool // services the account has, once read
	var keys []savedKey
	// prepare makes what a link needs, once, before any token is made.
	prepare := func(t *deployTarget) (*savedKey, error) {
		if !exists {
			if err := c.makeEnv(env); err != nil {
				return nil, err
			}
			exists = true
		}
		if added == nil {
			var ss struct {
				Services []service `json:"services"`
			}
			if err := c.call("GET", "/api/services", nil, &ss); err != nil {
				return nil, err
			}
			added = map[string]bool{}
			for _, s := range ss.Services {
				added[s.ID] = true
			}
			if keys, err = c.listKeys(); err != nil {
				return nil, err
			}
		}
		if !added[t.Service] {
			if err := c.call("POST", "/api/services", map[string]any{"catalog": t.Service}, nil); err != nil {
				return nil, fmt.Errorf("adding %s: %w", t.Name, err)
			}
			added[t.Service] = true
		}
		// A key of this name already there is replaced, unless another
		// environment uses it too: replacing it would change that one.
		for i, k := range keys {
			if k.Service == t.Service && strings.EqualFold(k.Name, keyName) {
				for _, e := range k.LinkedIn {
					if e != env {
						return nil, fmt.Errorf("the saved %s key %q is also used by %s: rename it (keystub keys rename %s NEW_NAME) and run again", t.Name, k.Name, e, k.ID)
					}
				}
				return &keys[i], nil
			}
		}
		return nil, nil
	}
	for i := range targets {
		t := &targets[i]
		if t.Linked {
			continue
		}
		q := fmt.Sprintf("Let sessions in %s deploy to %s", env, t.Name)
		if t.Target != "" {
			q += " (" + t.Target + ")"
		}
		if !c.ask(q) {
			t.Skipped = "not now"
			if !c.StdinTerminal {
				t.Skipped = "nothing can ask here (stdin isn't a terminal): run keystub connect at a terminal, or pass --yes"
			}
			continue
		}
		t.env = env
		have, err := prepare(t)
		if err != nil {
			t.Skipped = err.Error()
			continue
		}
		value, err := c.deployCredential(t)
		if err != nil {
			t.Skipped = err.Error()
			continue
		}
		var saved struct {
			Key savedKey `json:"key"`
		}
		if have != nil {
			err = c.call("PUT", "/api/keys/"+url.PathEscape(have.ID)+"/value", map[string]string{"value": value}, &saved)
			saved.Key.ID = have.ID
		} else {
			err = c.call("POST", "/api/keys", map[string]any{"service": t.Service, "name": keyName, "value": value}, &saved)
		}
		if err != nil {
			t.Skipped = fmt.Sprintf("saving the key: %v", err)
			continue
		}
		if err := c.call("PUT", path+"/links/"+url.PathEscape(t.Service), map[string]any{"key": saved.Key.ID, "serviceToken": false}, nil); err != nil {
			t.Skipped = fmt.Sprintf("the key is saved as %q but linking it failed: %v", keyName, err)
			continue
		}
		t.Linked = true
		t.Done = "linked: each session gets a short-lived " + strings.Join(deliveredAs[t.Service], " and ")
	}
	return c.emit(out, func(w io.Writer) {
		for _, t := range targets {
			switch {
			case t.Done != "":
				fmt.Fprintf(w, "%s %s\n", t.Name, t.Done)
			case t.Skipped != "" && t.Skipped != "not now":
				fmt.Fprintf(w, "%s not linked: %s\n", t.Name, t.Skipped)
			}
		}
	})
}

// deliveredAs is what a session gets for each.
var deliveredAs = map[string][]string{
	"fly-minted":        {"FLY_API_TOKEN"},
	"convex":            {"CONVEX_DEPLOY_KEY"},
	"cloudflare-minted": {"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"},
}

func (c *ctx) printTargets(w io.Writer, env string, targets []deployTarget) {
	fmt.Fprintf(w, "This code deploys to:\n")
	for _, t := range targets {
		what := t.Target
		if what == "" {
			what = "deployment not named in the code"
		}
		state := "not linked in " + env
		if t.Linked {
			state = "already linked in " + env
		}
		fmt.Fprintf(w, "  %-10s %s (%s): %s\n", t.Name, what, t.File, state)
		if len(t.Others) > 0 {
			fmt.Fprintf(w, "             also %s: an environment links one; this one is first\n", strings.Join(t.Others, ", "))
		}
	}
}

// ask is a yes/no question: --yes says yes, and nothing is asked when no
// one can answer (stdin isn't a terminal).
func (c *ctx) ask(q string) bool {
	if c.yes {
		return true
	}
	if !c.StdinTerminal {
		return false
	}
	fmt.Fprintf(c.Stderr, "%s? [y/N] ", q)
	line, _ := readLine(c.Stdin)
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

// askLine asks for a line of plain text (never a secret), or "" when no
// one can answer.
func (c *ctx) askLine(q string) string {
	if !c.StdinTerminal {
		return ""
	}
	fmt.Fprintf(c.Stderr, "%s: ", q)
	line, _ := readLine(c.Stdin)
	return strings.TrimSpace(line)
}

// deployCredential is the value saved for t: JSON with the token and what
// it is for, as the server takes it. The value never reaches stdout.
func (c *ctx) deployCredential(t *deployTarget) (string, error) {
	switch t.Kind {
	case "fly":
		return c.flyCredential(t)
	case "convex":
		return c.convexCredential(t)
	case "cloudflare":
		return c.cloudflareCredential(t)
	}
	return "", fmt.Errorf("unknown kind %s", t.Kind)
}

func (c *ctx) flyCredential(t *deployTarget) (string, error) {
	fly, err := lookFly()
	if err != nil {
		return "", errors.New("the fly CLI isn't installed (https://fly.io/docs/flyctl/install/)")
	}
	out, err := runFly(fly, "tokens", "create", "deploy", "-a", t.Target, "-n", "Keystub "+t.env, "-x", "8760h")
	if err != nil {
		return "", fmt.Errorf("fly tokens create deploy -a %s failed: %v (signed in? fly auth login)", t.Target, err)
	}
	tok := ""
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "FlyV1 ") {
			tok = l
		}
	}
	if tok == "" {
		return "", errors.New("fly made no token")
	}
	b, _ := json.Marshal(map[string]string{"token": tok, "app": t.Target})
	return string(b), nil
}

func (c *ctx) convexCredential(t *deployTarget) (string, error) {
	home := c.Getenv("HOME")
	b, err := os.ReadFile(filepath.Join(home, ".convex", "config.json"))
	var cfg struct {
		AccessToken string `json:"accessToken"`
	}
	if err != nil || json.Unmarshal(b, &cfg) != nil || cfg.AccessToken == "" {
		return "", errors.New("the Convex CLI isn't signed in here: run npx convex login, then again")
	}
	if t.Target == "" {
		t.Target = c.askLine("The production deployment to deploy (like happy-animal-123, from the Convex dashboard)")
	}
	if !convexName.MatchString(t.Target) {
		return "", errors.New("name the production deployment (like happy-animal-123): CONVEX_DEPLOYMENT=prod:NAME in an env file beside convex/, or run connect in a terminal")
	}
	req, _ := http.NewRequest("GET", convexAPI+"/deployments/"+url.PathEscape(t.Target)+"/list_deploy_keys", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("couldn't reach Convex: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("your Convex login can't make deploy keys for %s (status %d)", t.Target, resp.StatusCode)
	}
	fmt.Fprintf(c.Stderr, "Saving your Convex CLI login: Keystub makes an hour's deploy key for %s from it each session. It can reach your other Convex projects too: to stop that, delete the key in Keystub.\n", t.Target)
	v, _ := json.Marshal(map[string]string{"token": cfg.AccessToken, "deployment": t.Target})
	return string(v), nil
}

// cfAPI calls Cloudflare's API with token, into out.
func (c *ctx) cfAPI(token, path string, out any) error {
	req, _ := http.NewRequest("GET", cloudflareAPI+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil || !env.Success {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// cloudflareAccount is the account ID: the wrangler config's, else the one
// account wrangler's login sees, else asked.
func (c *ctx) cloudflareAccount(t *deployTarget) string {
	if t.Account != "" {
		return t.Account
	}
	home := c.Getenv("HOME")
	for _, f := range []string{
		filepath.Join(home, "Library", "Preferences", ".wrangler", "config", "default.toml"),
		filepath.Join(home, ".config", ".wrangler", "config", "default.toml"),
		filepath.Join(home, ".wrangler", "config", "default.toml"),
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		m := wranglerOAuth.FindStringSubmatch(string(b))
		if m == nil {
			continue
		}
		var accounts []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if c.cfAPI(m[1], "/accounts", &accounts) == nil && len(accounts) == 1 {
			return accounts[0].ID
		}
		break
	}
	return strings.ToLower(c.askLine("Your Cloudflare account ID (32 characters: the dashboard's URL after dash.cloudflare.com/)"))
}

func (c *ctx) cloudflareCredential(t *deployTarget) (string, error) {
	if !c.StdinTerminal || c.ReadSecret == nil {
		return "", errors.New("Cloudflare needs a token pasted: run keystub connect in a terminal")
	}
	acct := c.cloudflareAccount(t)
	if !cfAccountID.MatchString(acct) {
		return "", errors.New("that isn't a Cloudflare account ID")
	}
	page := "https://dash.cloudflare.com/" + acct + "/api-tokens/create"
	fmt.Fprintf(c.Stderr, `Cloudflare: make an account token (not one under My Profile, which can't make tokens for sessions).
  Page: %s
  1. Pick the "Edit Cloudflare Workers" template.
  2. In its account policy, also tick Account API Tokens: Edit (Keystub needs it to make each session's token; sessions never get it).
  3. If the Worker has a custom domain, add DNS: Edit and Zone: Read to the zone policy.
  4. Review token, Create Token, copy it.
`, page)
	if c.OpenURL != nil {
		_ = c.OpenURL(page)
	}
	tok, err := c.ReadSecret("Paste the Cloudflare token, then press Enter: ")
	if err != nil {
		return "", err
	}
	tok = strings.TrimSpace(tok)
	if err := c.cfAPI(tok, "/accounts/"+acct+"/tokens/verify", nil); err != nil {
		return "", errors.New("Cloudflare doesn't take that as an account token for this account: make it under Manage account, Account API tokens")
	}
	v, _ := json.Marshal(map[string]string{"token": tok, "accountId": acct})
	return string(v), nil
}

// offerConnect ends init: when this code deploys somewhere env doesn't
// link yet, it asks to connect it (at a terminal), or says how (else).
// Nothing here fails init, which is done.
func (c *ctx) offerConnect(env, dir string) {
	targets := detectDeploys(dir)
	if len(targets) == 0 {
		return
	}
	// --yes answers init's question, not these: connecting makes tokens.
	if c.json || !c.StdinTerminal || c.yes {
		var names []string
		for _, t := range targets {
			names = append(names, t.Name)
		}
		fmt.Fprintf(c.Stderr, "keystub: this code deploys to %s: to let sessions deploy, run keystub connect %s\n", strings.Join(names, ", "), env)
		return
	}
	fmt.Fprintln(c.Stderr)
	if err := c.connectTargets(env, targets, false); err != nil {
		fmt.Fprintf(c.Stderr, "keystub: connect: %v\n", err)
	}
}
