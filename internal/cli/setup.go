package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/internal/proxy"
)

// keystub setup: everything a project's environment gives a box, written
// where the box's tools read it. One command on a laptop (signed in with
// keystub login) and in a sandbox (given an access: KEYSTUB_TOKEN,
// KEYSTUB_DELIVERY_KEY and KEYSTUB_EDGE).
//
// What it writes, by protection:
//   - Never on the box: a base URL on the edge and a stand-in key, for
//     every linked service with a base URL. The real key stays in Keystub.
//   - Short-lived on the box: a credential minted for this box (Google
//     Cloud: a 1-hour token in a file). Running setup again refreshes it.
//   - On the box: a saved secret (a database URL, a deploy key), as it is.
//
// The variables go into the dotenv file (.env by default), keeping every
// other line, after a copy of the old file is kept. In a sandbox, setup
// also sets up the CLIs that don't read a dotenv file: gcloud gets the
// token file and project in its own configuration, and every variable is
// exported from ~/.keystub/env.sh, which the shell's profile sources.

const setupUsage = "setup [PROJECT/ENV] [--env-file FILE] [--ttl 7d] [--cli | --no-cli] [--dry-run] [--print]"

// accessFile is a laptop's access to one environment from one folder:
// the token setup made for it, kept so setup can run again without making
// another. Mode 600, under the CLI's own folder.
type accessFile struct {
	Server      string     `json:"server"`
	Env         string     `json:"env"`
	Edge        string     `json:"edge"`
	TokenID     string     `json:"tokenId"`
	Token       string     `json:"token"`
	DeliveryKey string     `json:"deliveryKey,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// access is what setup asks the edge with.
type access struct {
	env, edge, token, deliveryKey string
	tokenID, tokenName            string
	expiresAt                     *time.Time
	sandbox                       bool // from KEYSTUB_TOKEN, not made by setup
	made                          bool // setup made the token just now
}

// setVar is one variable setup writes, and why.
type setVar struct {
	Name       string `json:"name"`
	Service    string `json:"service"`
	Protection string `json:"protection"` // never-on-box, short-lived or on-box
	value      string
	secret     bool
	current    bool // the file already holds this value
}

// setupResult is what setup reports. Never a value.
type setupResult struct {
	Env       string        `json:"env"`
	File      string        `json:"file"`
	Token     setupToken    `json:"token"`
	Set       []setVar      `json:"set"`
	Files     []string      `json:"files,omitempty"`
	Skipped   []skipped     `json:"skipped"`
	Failed    []skipped     `json:"failed,omitempty"`
	Expires   []setupExpiry `json:"expires,omitempty"`
	CLIs      []string      `json:"clis,omitempty"`
	Backup    string        `json:"backup,omitempty"`
	DryRun    bool          `json:"dryRun"`
	NextSteps []string      `json:"nextSteps,omitempty"`
}

type setupToken struct {
	ID        string     `json:"id,omitempty"`
	Name      string     `json:"name,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Made      bool       `json:"made"`
}

// setupExpiry is a short-lived credential: when it stops working.
type setupExpiry struct {
	Service      string    `json:"service"`
	ExpiresAt    time.Time `json:"expiresAt"`
	RefreshAfter time.Time `json:"refreshAfter"`
}

// bundle is the body of the edge's POST /provision.
type bundle struct {
	Variables []struct {
		Name    string `json:"name"`
		Service string `json:"service"`
		Value   string `json:"value"`
		File    string `json:"file"`
		Secret  bool   `json:"secret"`
	} `json:"variables"`
	Files []struct {
		Path    string `json:"path"`
		Service string `json:"service"`
		Content string `json:"content"`
	} `json:"files"`
	Items []struct {
		Service      string     `json:"service"`
		Name         string     `json:"name"`
		Kind         string     `json:"kind"`
		Protection   string     `json:"protection"`
		Variables    []string   `json:"variables"`
		ExpiresAt    *time.Time `json:"expiresAt"`
		RefreshAfter *time.Time `json:"refreshAfter"`
		Error        string     `json:"error"`
	} `json:"items"`
}

const (
	neverOnBox = "never-on-box"
	shortLived = "short-lived"
	onBox      = "on-box"
)

var protectionWords = map[string]string{neverOnBox: "Never on the box", shortLived: "Short-lived on the box", onBox: "On the box"}

func (c *ctx) setup(args []string) error {
	p, err := parse(args, []string{"env-file", "ttl"}, []string{"cli", "no-cli", "dry-run", "print"})
	if err != nil {
		return err
	}
	if err := p.want(0, 1, setupUsage); err != nil {
		return err
	}
	if p.has("print") {
		if len(p.args) != 1 {
			return usageErr("usage: keystub setup PROJECT/ENV --print")
		}
		return c.printQuickStart(p.args[0])
	}
	if p.has("cli") && p.has("no-cli") {
		return usageErr("--cli and --no-cli can't go together")
	}
	file := p.flags["env-file"]
	if file == "" {
		file = ".env"
	}
	if !p.has("dry-run") {
		if err := checkWritable(file); err != nil {
			return err
		}
	}
	named := ""
	if len(p.args) == 1 {
		named = p.args[0]
	}
	res := setupResult{File: file, DryRun: p.has("dry-run"), Set: []setVar{}, Skipped: []skipped{}}

	var a *access
	if tok := strings.TrimSpace(c.Getenv("KEYSTUB_TOKEN")); tok != "" {
		a, err = c.sandboxAccess(tok, named)
	} else {
		a, err = c.laptopAccess(named, file, p.flags["ttl"], res.DryRun)
	}
	if err != nil {
		return err
	}
	res.Env = a.env
	if a.tokenID != "" || a.tokenName != "" {
		res.Token = setupToken{ID: a.tokenID, Name: a.tokenName, ExpiresAt: a.expiresAt, Made: a.made}
	}
	clis := a.sandbox
	if p.has("cli") {
		clis = true
	}
	if p.has("no-cli") {
		clis = false
	}

	if res.DryRun && a.token == "" {
		// A laptop with no token yet: name what the environment links,
		// without making a token to ask the edge with.
		if err := c.plannedVars(a.env, &res); err != nil {
			return err
		}
		res.NextSteps = []string{"keystub setup " + shellQuote(a.env) + " --env-file " + shellQuote(file) + "   (makes a token for this folder and writes " + file + ")"}
		return c.emit(res, func(w io.Writer) { c.printSetup(w, res) })
	}

	cat, err := c.edgeCatalog(a.edge, a.token)
	if err != nil {
		return err
	}
	if a.tokenName == "" {
		res.Token = setupToken{ID: cat.Token.ID, Name: cat.Token.Name, ExpiresAt: cat.Token.ExpiresAt, Made: a.made}
	}
	if res.Env == "" {
		res.Env = cat.Token.Env
	}
	if named != "" && cat.Token.Env != "" && cat.Token.Env != named {
		return usageErr("KEYSTUB_TOKEN is for %s, not %s", cat.Token.Env, named)
	}
	vars := standIns(cat, a, &res)

	files := map[string]string{} // absolute path → content
	if a.deliveryKey == "" {
		why := "this server made no delivery key, so only stand-ins are set"
		if a.sandbox {
			why = "no delivery key: set KEYSTUB_DELIVERY_KEY to get them"
		}
		res.Skipped = append(res.Skipped, skipped{"(secrets and minted credentials)", why})
	} else if res.DryRun {
		res.NextSteps = append(res.NextSteps, "secrets and minted credentials are fetched when setup runs without --dry-run")
	} else {
		b, err := c.provision(a)
		if err != nil {
			return err
		}
		more, err := c.delivered(b, res.Env, files, &res)
		if err != nil {
			return err
		}
		vars = append(vars, more...)
	}
	if err := noClash(vars); err != nil {
		return err
	}

	// Which variables already hold what setup would write.
	values := map[string]string{}
	if _, err := os.Stat(file); err == nil {
		if _, values, err = dotenvNames(file); err != nil {
			return err
		}
	}
	var overwrite []string
	for i := range vars {
		cur, ok := values[vars[i].Name]
		vars[i].current = ok && cur == vars[i].value
		if ok && !vars[i].current && strings.TrimSpace(cur) != "" && !fromKeystub(cur, a.edge) {
			overwrite = append(overwrite, vars[i].Name)
		}
	}
	res.Set = vars
	sort.Slice(res.Set, func(i, j int) bool { return res.Set[i].Name < res.Set[j].Name })
	if clis {
		res.CLIs = c.cliPlan(vars)
	}

	if res.DryRun {
		return c.emit(res, func(w io.Writer) { c.printSetup(w, res) })
	}
	if len(overwrite) > 0 {
		// The file holds real values setup would replace: say so first. A
		// copy is kept either way.
		if err := c.confirm(fmt.Sprintf("Replace %s in %s with what Keystub gives (the file is copied to %s first)", strings.Join(overwrite, ", "), file, c.backupDir())); err != nil {
			return err
		}
	}
	for path, content := range files {
		if err := writePrivate(path, content); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	changed := false
	for _, v := range vars {
		changed = changed || !v.current
	}
	if changed {
		if res.Backup, err = c.backupDotenv(file); err != nil {
			return err
		}
		ev := make([]envVar, 0, len(vars))
		for _, v := range res.Set {
			ev = append(ev, envVar{v.Name, v.value})
		}
		if err := setDotenv(file, ev); err != nil {
			return fmt.Errorf("writing %s: %w", file, err)
		}
	}
	if !a.sandbox {
		if err := writeProjectFile(filepath.Dir(file), a.env); err != nil {
			return err
		}
	}
	if clis {
		if res.CLIs, err = c.setUpCLIs(vars); err != nil {
			return err
		}
	}
	if len(res.Expires) > 0 {
		res.NextSteps = append(res.NextSteps, "keystub setup again before "+res.Expires[0].ExpiresAt.Local().Format("15:04")+" to refresh the short-lived credentials")
	}
	return c.emit(res, func(w io.Writer) { c.printSetup(w, res) })
}

// --- access ---

// sandboxAccess is the access a sandbox was given in its environment.
func (c *ctx) sandboxAccess(tok, named string) (*access, error) {
	edge := strings.TrimSuffix(strings.TrimSpace(c.Getenv("KEYSTUB_EDGE")), "/")
	if edge == "" {
		return nil, usageErr("KEYSTUB_TOKEN is set but KEYSTUB_EDGE isn't: set it to the edge URL shown with the token (keystub tokens create … --delivery)")
	}
	if !strings.HasPrefix(edge, "https://") && !strings.HasPrefix(edge, "http://127.0.0.1") && !strings.HasPrefix(edge, "http://localhost") {
		return nil, usageErr("KEYSTUB_EDGE must be an https:// URL")
	}
	return &access{env: named, edge: edge, token: tok, deliveryKey: strings.TrimSpace(c.Getenv("KEYSTUB_DELIVERY_KEY")), sandbox: true}, nil
}

// laptopAccess is this folder's token for the environment, made with the
// person's sign-in the first time and kept for the next run. A dry run
// makes nothing: it returns the access with no token when there's none.
func (c *ctx) laptopAccess(named, file, ttl string, dryRun bool) (*access, error) {
	env := named
	if env == "" {
		env = readProjectFile(filepath.Dir(file))
	}
	if env == "" {
		env = defaultEnv(file)
	}
	path, err := envPath(env)
	if err != nil {
		return nil, err
	}
	folder, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		return nil, err
	}
	store := c.accessPath(env, folder)
	var saved accessFile
	if b, err := os.ReadFile(store); err == nil && json.Unmarshal(b, &saved) == nil &&
		sameServer(saved.Server, c.server) && saved.Env == env && saved.Token != "" &&
		(saved.ExpiresAt == nil || time.Until(*saved.ExpiresAt) > time.Hour) {
		return &access{env: env, edge: saved.Edge, token: saved.Token, deliveryKey: saved.DeliveryKey, tokenID: saved.TokenID, expiresAt: saved.ExpiresAt}, nil
	}
	if _, err := c.credential(); err != nil {
		return nil, err
	}
	var es struct {
		Environments []environment `json:"environments"`
	}
	if err := c.call("GET", "/api/environments", nil, &es); err != nil {
		return nil, err
	}
	found := false
	for _, e := range es.Environments {
		found = found || e.ID == env
	}
	if !found {
		return nil, &Error{Code: ExitNotFound, Message: fmt.Sprintf("there's no environment %s yet: run keystub init first, which makes it from this folder", env)}
	}
	if dryRun {
		return &access{env: env}, nil
	}
	var st struct {
		EdgeURL string `json:"edgeUrl"`
	}
	if err := c.call("GET", path+"/setup", nil, &st); err != nil {
		return nil, err
	}
	edge := strings.TrimSuffix(st.EdgeURL, "/")
	if edge == "" {
		return nil, &Error{Code: ExitError, Message: "the server has no edge to set up against"}
	}
	if ttl == "" {
		ttl = "7d"
	}
	name := c.Hostname
	if name == "" {
		name = "setup"
	}
	name += "/" + filepath.Base(folder)
	var out struct {
		Token struct {
			token
			DeliveryKey string `json:"deliveryKey"`
		} `json:"token"`
	}
	if err := c.call("POST", path+"/tokens", map[string]any{"name": name, "ttl": ttl, "delivery": true}, &out); err != nil {
		return nil, err
	}
	t := out.Token
	saved = accessFile{Server: c.server, Env: env, Edge: edge, TokenID: t.ID, Token: t.Secret, DeliveryKey: t.DeliveryKey, ExpiresAt: t.ExpiresAt}
	b, _ := json.MarshalIndent(saved, "", "  ")
	if err := writePrivate(store, string(b)+"\n"); err != nil {
		return nil, &Error{Code: ExitError, Message: fmt.Sprintf("made token %s but couldn't keep it (%v); revoke it: keystub tokens revoke %s --yes", t.ID, err, t.ID)}
	}
	return &access{env: env, edge: edge, token: t.Secret, deliveryKey: t.DeliveryKey, tokenID: t.ID, tokenName: t.Name, expiresAt: t.ExpiresAt, made: true}, nil
}

// accessPath is where a folder's access to env is kept.
func (c *ctx) accessPath(env, folder string) string {
	sum := sha256.Sum256([]byte(c.server + "\n" + env + "\n" + folder))
	return filepath.Join(c.Home, "access", hex.EncodeToString(sum[:8])+".json")
}

// --- what goes on the box ---

// edgeCatalog asks the edge which services the token may use.
func (c *ctx) edgeCatalog(edge, token string) (proxy.CatalogResponse, error) {
	var out proxy.CatalogResponse
	req, err := http.NewRequest("GET", edge+"/catalog", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set(proxy.TokenHeader, token)
	resp, err := c.Client.Do(req)
	if err != nil {
		return out, fmt.Errorf("can't reach the edge at %s: %v", edge, unwrapURLError(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return out, &Error{Code: ExitNoAuth, Message: "the edge refused the token: it expired or was revoked. Ask for a new access, or on a laptop run keystub setup again after deleting " + filepath.Join(c.Home, "access")}
	}
	if resp.StatusCode != http.StatusOK {
		return out, answerError(resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("the edge's catalog isn't valid: %w", err)
	}
	return out, nil
}

// standIns are the base URLs and stand-in keys for the services the token
// may use. A service with no base URL is reached only through the proxy
// (keystub run), so its stand-in in a dotenv file would go nowhere.
func standIns(cat proxy.CatalogResponse, a *access, res *setupResult) []setVar {
	compact := "skstub" + strings.TrimPrefix(a.token, "sk-stub-")
	keyed := strings.NewReplacer("{key_compact}", compact, "{key}", a.token)
	var out []setVar
	for _, s := range cat.Services {
		if s.BaseURL.Var == "" {
			for _, v := range s.EnvVars {
				name, _, _ := strings.Cut(v, "=")
				res.Skipped = append(res.Skipped, skipped{name, s.Name + " has no base URL: reach it through keystub run"})
			}
			continue
		}
		out = append(out, setVar{Name: s.BaseURL.Var, Service: s.ID, Protection: neverOnBox, value: a.edge + "/s/" + s.ID + s.BaseURL.Path})
		for _, v := range s.EnvVars {
			name, tmpl, ok := strings.Cut(v, "=")
			if !ok {
				tmpl = "{key}"
			}
			out = append(out, setVar{Name: name, Service: s.ID, Protection: neverOnBox, value: keyed.Replace(tmpl), secret: true})
		}
	}
	return out
}

// provision asks the edge for the environment's secrets and minted
// credentials. A server with no /provision (a self-hosted one) delivers
// nothing.
func (c *ctx) provision(a *access) (bundle, error) {
	var b bundle
	req, err := http.NewRequest("POST", a.edge+"/provision", bytes.NewReader(nil))
	if err != nil {
		return b, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Keystub-Delivery-Key", a.deliveryKey)
	resp, err := c.Client.Do(req)
	if err != nil {
		return b, fmt.Errorf("can't reach the edge at %s: %v", a.edge, unwrapURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return b, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return b, &Error{Code: ExitNoAuth, Message: "the edge refused the token: it expired or was revoked"}
	case resp.StatusCode == http.StatusForbidden:
		return b, &Error{Code: ExitNoAuth, Message: "the edge refused the delivery key: KEYSTUB_DELIVERY_KEY isn't the one made with this token"}
	case resp.StatusCode != http.StatusOK:
		return b, answerError(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return b, fmt.Errorf("the edge's delivery isn't valid: %w", err)
	}
	return b, nil
}

// delivered turns a bundle into variables, and its files into files to
// write under the CLI's folder (mode 600), never the project's.
func (c *ctx) delivered(b bundle, env string, files map[string]string, res *setupResult) ([]setVar, error) {
	dir := filepath.Join(c.Home, "files", slugUnsafe.ReplaceAllString(strings.ToLower(env), "-"))
	protection := map[string]string{}
	for _, it := range b.Items {
		if it.Error != "" {
			res.Failed = append(res.Failed, skipped{it.Name, it.Error})
			continue
		}
		protection[it.Service] = it.Protection
		if it.ExpiresAt != nil {
			e := setupExpiry{Service: it.Service, ExpiresAt: *it.ExpiresAt}
			if it.RefreshAfter != nil {
				e.RefreshAfter = *it.RefreshAfter
			}
			res.Expires = append(res.Expires, e)
		}
	}
	paths := map[string]string{}
	for _, f := range b.Files {
		clean := filepath.Clean(filepath.FromSlash(f.Path))
		if f.Path == "" || filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "..") {
			return nil, fmt.Errorf("the edge sent a file with a bad path %q", f.Path)
		}
		abs := filepath.Join(dir, clean)
		files[abs] = f.Content
		paths[f.Path] = abs
		res.Files = append(res.Files, abs)
	}
	var out []setVar
	for _, v := range b.Variables {
		value := v.Value
		if v.File != "" {
			abs, ok := paths[v.File]
			if !ok {
				return nil, fmt.Errorf("the edge's %s names a file it didn't send", v.Name)
			}
			value = abs
		}
		prot := protection[v.Service]
		if prot == "" {
			prot = onBox
		}
		out = append(out, setVar{Name: v.Name, Service: v.Service, Protection: prot, value: value, secret: v.Secret})
	}
	return out, nil
}

// noClash refuses two services setting one variable.
func noClash(vars []setVar) error {
	by := map[string]string{}
	for _, v := range vars {
		if other, ok := by[v.Name]; ok && other != v.Service {
			return &Error{Code: ExitConflict, Message: fmt.Sprintf("%s is set by both %s and %s: unlink one from the environment", v.Name, other, v.Service)}
		}
		by[v.Name] = v.Service
	}
	return nil
}

// fromKeystub reports whether a value is one setup wrote: a stand-in, an
// edge URL or a file under the CLI's folder. Replacing it needs no yes.
func fromKeystub(v, edge string) bool {
	return holdsToken(v) || (edge != "" && strings.HasPrefix(v, edge+"/")) || strings.Contains(v, string(filepath.Separator)+".keystub"+string(filepath.Separator))
}

// plannedVars names what the environment links, for a dry run with no
// token yet.
func (c *ctx) plannedVars(env string, res *setupResult) error {
	path, err := envPath(env)
	if err != nil {
		return err
	}
	var ls struct {
		Links []link `json:"links"`
	}
	if err := c.call("GET", path+"/links", nil, &ls); err != nil {
		return err
	}
	var all, cat struct {
		Services []service `json:"services"`
	}
	if err := c.call("GET", "/api/services", nil, &all); err != nil {
		return err
	}
	if err := c.call("GET", "/api/catalog", nil, &cat); err != nil {
		return err
	}
	byID := map[string]service{}
	for _, list := range [][]service{cat.Services, all.Services} {
		for _, s := range list {
			byID[s.ID] = s
		}
	}
	for _, l := range ls.Links {
		s, ok := byID[l.Service]
		if !ok {
			continue
		}
		switch {
		case s.Kind == "minted":
			for _, v := range s.Variables {
				res.Set = append(res.Set, setVar{Name: v, Service: s.ID, Protection: shortLived})
			}
		case s.Kind == "secret":
			for _, v := range s.Variables {
				res.Set = append(res.Set, setVar{Name: v, Service: s.ID, Protection: onBox})
			}
		case s.BaseURL == nil || s.BaseURL.Var == "":
			for _, n := range s.varNames() {
				res.Skipped = append(res.Skipped, skipped{n, s.Name + " has no base URL: reach it through keystub run"})
			}
		default:
			res.Set = append(res.Set, setVar{Name: s.BaseURL.Var, Service: s.ID, Protection: neverOnBox})
			for _, n := range s.varNames() {
				res.Set = append(res.Set, setVar{Name: n, Service: s.ID, Protection: neverOnBox})
			}
		}
	}
	sort.Slice(res.Set, func(i, j int) bool { return res.Set[i].Name < res.Set[j].Name })
	return nil
}

// --- CLIs ---

// cliPlan names the CLIs setup would set up for these variables.
func (c *ctx) cliPlan(vars []setVar) []string {
	out := []string{"shell (~/.keystub/env.sh, sourced from ~/.profile and ~/.bashrc)"}
	if gcloudVars(vars) != nil {
		out = append(out, "gcloud (configuration keystub)")
	}
	return out
}

// gcloudVars is the token file and project Google Cloud's delivery sets,
// or nil.
func gcloudVars(vars []setVar) map[string]string {
	g := map[string]string{}
	for _, v := range vars {
		if v.Name == "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE" || v.Name == "CLOUDSDK_CORE_PROJECT" {
			g[v.Name] = v.value
		}
	}
	if g["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] == "" {
		return nil
	}
	return g
}

const profileLine = `[ -f "$HOME/.keystub/env.sh" ] && . "$HOME/.keystub/env.sh"   # keystub setup`

// setUpCLIs exports every variable from ~/.keystub/env.sh for shells and
// the CLIs that don't read a dotenv file, and points gcloud at the token
// file. It reports what it set up.
func (c *ctx) setUpCLIs(vars []setVar) ([]string, error) {
	var b strings.Builder
	b.WriteString("# Written by keystub setup. Run it again to refresh.\n")
	sorted := append([]setVar(nil), vars...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, v := range sorted {
		b.WriteString("export " + v.Name + "=" + shSingle(v.value) + "\n")
	}
	if err := writePrivate(filepath.Join(c.Home, "env.sh"), b.String()); err != nil {
		return nil, err
	}
	done := []string{"shell (" + filepath.Join(c.Home, "env.sh") + ")"}
	if home := c.Getenv("HOME"); home != "" && filepath.Clean(c.Home) == filepath.Join(home, ".keystub") {
		for _, rc := range []string{".profile", ".bashrc"} {
			if err := appendOnce(filepath.Join(home, rc), profileLine); err != nil {
				return nil, err
			}
		}
		done[0] = "shell (~/.keystub/env.sh, sourced from ~/.profile and ~/.bashrc)"
	}
	if g := gcloudVars(vars); g != nil {
		if gc, err := lookGcloud(); err == nil {
			cmds := [][]string{
				{"config", "configurations", "create", "keystub", "--no-activate"},
				{"config", "configurations", "activate", "keystub"},
				{"config", "set", "auth/access_token_file", g["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"], "--configuration", "keystub"},
			}
			if pr := g["CLOUDSDK_CORE_PROJECT"]; pr != "" {
				cmds = append(cmds, []string{"config", "set", "core/project", pr, "--configuration", "keystub"})
			}
			for i, a := range cmds {
				out, err := runGcloud(gc, a...)
				if err != nil && i != 0 { // the configuration may exist already
					return nil, fmt.Errorf("gcloud %s: %s", strings.Join(a, " "), strings.TrimSpace(string(out)))
				}
			}
			done = append(done, "gcloud (configuration keystub, active)")
		} else {
			done = append(done, "gcloud isn't installed: the token file is in CLOUDSDK_AUTH_ACCESS_TOKEN_FILE for when it is")
		}
	}
	return done, nil
}

// shSingle quotes a value for a POSIX shell.
func shSingle(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

// appendOnce adds line to the file unless it's there already.
func appendOnce(path, line string) error {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if strings.Contains(string(b), line) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	prefix := ""
	if len(b) > 0 && !bytes.HasSuffix(b, []byte("\n")) {
		prefix = "\n"
	}
	_, err = f.WriteString(prefix + line + "\n")
	return err
}

// writePrivate writes a file only its owner can read, in a folder only its
// owner can open, swapping it in whole.
func writePrivate(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(content)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// --- output ---

func (c *ctx) printSetup(w io.Writer, res setupResult) {
	verb := "Set up"
	if res.DryRun {
		verb = "Would set up"
	}
	fmt.Fprintf(w, "%s %s in %s", verb, res.Env, res.File)
	if res.Token.Name != "" {
		fmt.Fprintf(w, " (token %s, expires %s)", res.Token.Name, when(res.Token.ExpiresAt))
	}
	fmt.Fprintln(w, ":")
	for _, prot := range []string{neverOnBox, shortLived, onBox} {
		var names []string
		for _, v := range res.Set {
			if v.Protection == prot {
				names = append(names, v.Name)
			}
		}
		if len(names) > 0 {
			fmt.Fprintf(w, "  %-23s %s\n", protectionWords[prot], strings.Join(names, ", "))
		}
	}
	if len(res.Set) == 0 {
		fmt.Fprintln(w, "  nothing: the environment links no service with a base URL, secret or credential")
	}
	for _, e := range res.Expires {
		fmt.Fprintf(w, "  %s expires at %s\n", e.Service, e.ExpiresAt.Local().Format("15:04"))
	}
	for _, f := range res.Failed {
		fmt.Fprintf(w, "Failed: %s: %s\n", f.Var, f.Reason)
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(w, "Skipped: %s: %s\n", s.Var, s.Reason)
	}
	for _, s := range res.CLIs {
		fmt.Fprintln(w, "Set up:", s)
	}
	if res.Backup != "" {
		fmt.Fprintf(w, "The old file is at %s; put it back with: cp %q %q\n", res.Backup, res.Backup, res.File)
	}
	for _, s := range res.NextSteps {
		fmt.Fprintln(w, "Next:", s)
	}
}

// printQuickStart is setup --print: the quick-start lines for an
// environment, with <token> for a token, to copy by hand.
func (c *ctx) printQuickStart(env string) error {
	path, err := envPath(env)
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
		fmt.Fprintf(w, "# Quick start for %s: SDKs call the edge at %s directly.\n# Replace <token> with a token: keystub tokens create %s --name NAME\n", env, out.EdgeURL, env)
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

// createAccess is tokens create --delivery: a token and its delivery key,
// printed as the three variables a sandbox runs keystub setup with.
func (c *ctx) createAccess(path string, body map[string]any) error {
	var st struct {
		EdgeURL string `json:"edgeUrl"`
	}
	if err := c.call("GET", path+"/setup", nil, &st); err != nil {
		return err
	}
	edge := strings.TrimSuffix(st.EdgeURL, "/")
	if edge == "" {
		return &Error{Code: ExitError, Message: "the server has no edge for a sandbox to set up against"}
	}
	body["delivery"] = true
	var out struct {
		Token struct {
			token
			DeliveryKey string `json:"deliveryKey"`
		} `json:"token"`
	}
	if err := c.call("POST", path+"/tokens", body, &out); err != nil {
		return err
	}
	t := out.Token
	if t.DeliveryKey == "" {
		fmt.Fprintln(c.Stderr, "keystub: warning: this server made no delivery key, so the sandbox gets stand-ins only")
	}
	if c.json {
		return c.emit(map[string]any{"token": t.token, "deliveryKey": t.DeliveryKey, "edge": edge}, nil)
	}
	fmt.Fprintln(c.Stdout, "KEYSTUB_TOKEN="+t.Secret)
	if t.DeliveryKey != "" {
		fmt.Fprintln(c.Stdout, "KEYSTUB_DELIVERY_KEY="+t.DeliveryKey)
	}
	fmt.Fprintln(c.Stdout, "KEYSTUB_EDGE="+edge)
	fmt.Fprintf(c.Stderr, "Access %s for %s (id %s, expires %s). Put these three in the sandbox's environment, then run keystub setup there. They aren't shown again.\n", t.Name, t.Env, t.ID, when(t.ExpiresAt))
	return nil
}

// lookGcloud and runGcloud are gcloud on this machine; tests replace them,
// so a test never changes the machine's own gcloud configuration.
var (
	lookGcloud = func() (string, error) { return exec.LookPath("gcloud") }
	runGcloud  = func(path string, args ...string) ([]byte, error) { return exec.Command(path, args...).CombinedOutput() }
)
