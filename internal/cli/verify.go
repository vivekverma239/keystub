package cli

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// keystub verify: does what keystub setup delivered work, here, for what
// this code does? It reads the variables a program here would get (the
// env file, then ~/.keystub/env.sh, then the environment) and, for each
// credential, makes one read-only call with it:
//
//   - a stand-in: a request through the edge, as doctor does;
//   - Google Cloud: the token works, and the service account holds the
//     permissions this code's deploy needs (Cloud Run, App Engine,
//     Firebase), with the command that grants what's missing;
//   - Fly.io, Cloudflare, Convex, AWS: the credential is accepted for
//     the app, account or deployment it names;
//   - a database URL: its host answers.
//
// It also says which CLIs the code's deploys need and whether they're
// here. With --deploy it rehearses a deploy where that can be done without
// touching the app: a throwaway Cloud Run service and a throwaway Worker,
// each deleted right after.

const verifyUsage = "verify [PROJECT/ENV] [--env-file FILE] [--dir DIR] [--deploy] [--region REGION]"

var (
	googleAPI    = "https://cloudresourcemanager.googleapis.com/v1"
	googleRunAPI = "https://run.googleapis.com/v2"
	googleIAM    = "https://iam.googleapis.com/v1"
	googleToken  = "https://oauth2.googleapis.com/tokeninfo"
	flyAPI       = "https://api.machines.dev/v1"
	convexCloud  = "https://%s.convex.cloud"
	lookTool     = exec.LookPath
	// rehearsalWait is how long a rehearsal waits for a deploy to finish.
	rehearsalWait = 4 * time.Minute
	pollEvery     = 3 * time.Second
)

// helloImage is Google's public sample: a rehearsal deploys it, never the
// app.
const helloImage = "us-docker.pkg.dev/cloudrun/container/hello"

type verifyResult struct {
	Env    string   `json:"env,omitempty"`
	File   string   `json:"file"`
	OK     bool     `json:"ok"`
	Checks []check  `json:"checks"`
	Fixes  []string `json:"fixes,omitempty"` // commands that fix a failed or warned check
}

func (c *ctx) verify(args []string) error {
	p, err := parse(args, []string{"env-file", "dir", "region"}, []string{"deploy"})
	if err != nil {
		return err
	}
	if err := p.want(0, 1, verifyUsage); err != nil {
		return err
	}
	file := p.flags["env-file"]
	if file == "" {
		file = ".env"
	}
	dir := p.flags["dir"]
	if dir == "" {
		dir = filepath.Dir(file)
	}
	res := verifyResult{File: file, Checks: []check{}}
	if len(p.args) == 1 {
		res.Env = p.args[0]
	} else if e := readProjectFile(filepath.Dir(file)); e != "" {
		res.Env = e
	}
	v := &verifier{c: c, res: &res, vars: c.verifyVars(file), managed: c.managedVars(file), dir: dir, deploy: p.has("deploy"), region: p.flags["region"]}
	v.run()

	return c.reportChecks(res.Env, file, res.Checks, res.Fixes)
}

// verifyVars is what a program here would read: the env file first, then
// what keystub setup exported to ~/.keystub/env.sh, then the environment.
func (c *ctx) verifyVars(file string) map[string]string {
	out := map[string]string{}
	if _, values, err := dotenvNames(file); err == nil {
		for k, v := range values {
			out[k] = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(c.Home, "env.sh")); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			name, val, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
			if !ok || !strings.HasPrefix(line, "export ") {
				continue
			}
			if _, set := out[name]; !set {
				out[name] = unSingle(val)
			}
		}
	}
	for _, n := range verifyNames {
		if _, set := out[n]; !set {
			if v := c.Getenv(n); v != "" {
				out[n] = v
			}
		}
	}
	return out
}

// verifyNames are the variables verify reads from the environment when
// neither file sets them.
var verifyNames = []string{
	"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT",
	"FLY_API_TOKEN", "FLY_APP", "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID",
	"CONVEX_DEPLOY_KEY", "AWS_SHARED_CREDENTIALS_FILE", "AWS_PROFILE", "AWS_REGION",
	"RAILWAY_TOKEN", "DATABASE_URL", "KEYSTUB_TOKEN", "KEYSTUB_EDGE",
}

// unSingle undoes shSingle.
func unSingle(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return strings.ReplaceAll(v[1:len(v)-1], `'\''`, "'")
	}
	return v
}

type verifier struct {
	c       *ctx
	res     *verifyResult
	vars    map[string]string
	managed map[string]bool // variables keystub setup wrote to the file
	dir     string
	deploy  bool
	region  string
}

func (v *verifier) add(name, status, format string, a ...any) {
	v.res.Checks = append(v.res.Checks, check{name, status, fmt.Sprintf(format, a...)})
}

func (v *verifier) fix(cmd string) {
	for _, f := range v.res.Fixes {
		if f == cmd {
			return
		}
	}
	v.res.Fixes = append(v.res.Fixes, cmd)
}

func (v *verifier) run() {
	deploys := detectDeploys(v.dir)
	gcp := detectGoogle(v.dir)
	if v.region == "" {
		v.region = gcp.region
	}
	if v.region == "" {
		v.region = "us-central1"
	}
	found := v.standIns()
	found = v.google(gcp) || found
	found = v.fly() || found
	found = v.cloudflare() || found
	found = v.convex() || found
	found = v.aws() || found
	found = v.database() || found
	if !found {
		v.add("credentials", "fail", "nothing from Keystub here: run keystub setup first (it writes %s)", v.res.File)
		v.fix("keystub setup" + v.envArg())
	}
	v.tools(deploys, gcp)
	if v.deploy {
		v.rehearse()
	}
}

func (v *verifier) envArg() string {
	if v.res.Env == "" {
		return ""
	}
	return " " + shellQuote(v.res.Env)
}

// --- stand-ins ---

var edgeService = regexp.MustCompile(`^(https?://[^/]+)/s/([a-z0-9][a-z0-9-]*)`)

// standIns probes each service setup pointed at the edge, with the token
// in the variables. Only Keystub's edge gets the token: a URL setup wrote,
// or one on KEYSTUB_EDGE's host, never any URL that merely has /s/ in it.
func (v *verifier) standIns() bool {
	edgeHost := ""
	if u, err := url.Parse(v.vars["KEYSTUB_EDGE"]); err == nil {
		edgeHost = u.Host
	}
	tok := ""
	names := make([]string, 0, len(v.vars))
	for n := range v.vars {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if t := tokenIn(v.vars[n]); t != "" && n != "KEYSTUB_TOKEN" {
			tok = t
			break
		}
	}
	seen := map[string]bool{}
	any := false
	for _, n := range names {
		m := edgeService.FindStringSubmatch(v.vars[n])
		if m == nil || seen[m[2]] {
			continue
		}
		if u, err := url.Parse(m[1]); err != nil || (!v.managed[n] && (edgeHost == "" || u.Host != edgeHost)) {
			continue
		}
		seen[m[2]] = true
		any = true
		if tok == "" {
			v.add(m[2], "fail", "%s points at Keystub, but no variable holds a token: run keystub setup again", n)
			continue
		}
		status, detail := v.c.probe(m[1], m[2], tok)
		v.add(m[2], status, "%s", detail)
	}
	return any
}

// --- Google Cloud ---

// googleTargets is what this code deploys to on Google Cloud.
type googleTargets struct {
	run, appEngine, firebase, build bool
	region                          string
	files                           []string
}

var (
	runDeploy   = regexp.MustCompile(`gcloud\s+(?:beta\s+)?run\s+(?:deploy|services\s+replace|jobs\s+deploy)`)
	buildSubmit = regexp.MustCompile(`gcloud\s+builds\s+submit`)
	regionFlag  = regexp.MustCompile(`--region[= ]+([a-z]+-[a-z]+\d)`)
)

// detectGoogle looks, as deeply as connect does, for a Cloud Run deploy in
// scripts, Makefiles, CI workflows and Cloud Build files, an app.yaml, and
// a firebase.json.
func detectGoogle(dir string) googleTargets {
	var g googleTargets
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
			if path != root && ((deploySkipDirs[d.Name()] && d.Name() != ".github") || depth > 4) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		ext := filepath.Ext(name)
		switch {
		case name == "app.yaml" && depth <= 2:
			g.appEngine = true
			g.files = append(g.files, rel)
			return nil
		case name == "firebase.json" && depth <= 2:
			g.firebase = true
			g.files = append(g.files, rel)
			return nil
		case name == "cloudbuild.yaml" || name == "cloudbuild.yml":
			g.build = true
		case name == "package.json" || name == "Makefile" || ext == ".sh" || ext == ".yml" || ext == ".yaml" || ext == ".toml":
		default:
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil || len(b) > 1<<20 {
			return nil
		}
		s := string(b)
		if loc := runDeploy.FindStringIndex(s); loc != nil {
			g.run = true
			g.files = append(g.files, rel)
			line := s[loc[0]:]
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = line[:i]
			}
			if m := regionFlag.FindStringSubmatch(line); m != nil && g.region == "" {
				g.region = m[1]
			}
		}
		if buildSubmit.MatchString(s) {
			g.build = true
		}
		return nil
	})
	return g
}

// googlePerms are the permissions each kind of deploy needs, and the role
// that grants them.
var googlePerms = []struct {
	perm, role string
	need       func(googleTargets) bool
}{
	{"resourcemanager.projects.get", "roles/browser", func(googleTargets) bool { return true }},
	{"run.services.list", "roles/run.developer", func(g googleTargets) bool { return g.run }},
	{"run.services.create", "roles/run.developer", func(g googleTargets) bool { return g.run }},
	{"run.services.update", "roles/run.developer", func(g googleTargets) bool { return g.run }},
	{"iam.serviceAccounts.actAs", "roles/iam.serviceAccountUser", func(g googleTargets) bool { return g.run || g.appEngine }},
	{"artifactregistry.repositories.uploadArtifacts", "roles/artifactregistry.writer", func(g googleTargets) bool { return g.run || g.build }},
	{"cloudbuild.builds.create", "roles/cloudbuild.builds.editor", func(g googleTargets) bool { return g.build }},
	{"appengine.versions.create", "roles/appengine.deployer", func(g googleTargets) bool { return g.appEngine }},
	{"firebasehosting.sites.update", "roles/firebasehosting.admin", func(g googleTargets) bool { return g.firebase }},
}

func (v *verifier) googleToken() (string, error) {
	f := v.vars["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"]
	b, err := os.ReadFile(f)
	if err != nil {
		return "", fmt.Errorf("its token file can't be read (%s): run keystub setup again", f)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("its token file is empty (%s): run keystub setup again", f)
	}
	return t, nil
}

func (v *verifier) google(g googleTargets) bool {
	if v.vars["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] == "" {
		if g.run || g.appEngine || g.firebase {
			v.add("google cloud", "warn", "this code deploys to Google Cloud (%s), and nothing here signs in to it: link a Google Cloud key to the environment, then keystub setup", strings.Join(g.files, ", "))
		}
		return false
	}
	project := v.vars["CLOUDSDK_CORE_PROJECT"]
	if project == "" {
		project = v.vars["GOOGLE_CLOUD_PROJECT"]
	}
	tok, err := v.googleToken()
	if err != nil {
		v.add("google cloud", "fail", "%v", err)
		return true
	}
	// Who the token is (a POST, so it isn't in a URL).
	var info struct {
		Email     string `json:"email"`
		Azp       string `json:"azp"`
		ExpiresIn string `json:"expires_in"`
		Error     string `json:"error_description"`
	}
	code, err := v.c.verifyCall("POST", googleToken, "application/x-www-form-urlencoded", strings.NewReader(url.Values{"access_token": {tok}}.Encode()), nil, &info)
	switch {
	case err != nil:
		v.add("google cloud", "fail", "Google couldn't be reached: %v", err)
		return true
	case code != 200:
		v.add("google cloud", "fail", "Google turned the token down (expired?): run keystub setup again to refresh it")
		v.fix("keystub setup" + v.envArg())
		return true
	}
	if info.Email == "" && info.Azp != "" {
		// A service account's token names it by its unique ID only.
		var sa struct {
			Email string `json:"email"`
		}
		if code, err := v.c.verifyCall("GET", googleIAM+"/projects/-/serviceAccounts/"+url.PathEscape(info.Azp), "", nil, bearer(tok), &sa); err == nil && code == 200 {
			info.Email = sa.Email
		}
	}
	who := info.Email
	if who == "" {
		who = "the service account"
	}
	if project == "" {
		v.add("google cloud", "warn", "the token works (%s), but no project is set: set the Google Cloud key's project in Keystub", who)
		return true
	}
	var want []string
	roleOf := map[string]string{}
	for _, gp := range googlePerms {
		if gp.need(g) {
			want = append(want, gp.perm)
			roleOf[gp.perm] = gp.role
		}
	}
	var got struct {
		Permissions []string `json:"permissions"`
	}
	body, _ := json.Marshal(map[string]any{"permissions": want})
	code, err = v.c.verifyCall("POST", googleAPI+"/projects/"+url.PathEscape(project)+":testIamPermissions", "application/json", bytes.NewReader(body), bearer(tok), &got)
	if err != nil || code != 200 {
		v.add("google cloud", "fail", "the token works (%s), but %s can't be checked (HTTP %d%s): the project may not exist, or the account has no role in it", who, project, code, errSuffix(err))
		return true
	}
	has := map[string]bool{}
	for _, p := range got.Permissions {
		has[p] = true
	}
	var missing []string
	roles := map[string]bool{}
	for _, p := range want {
		if !has[p] {
			missing = append(missing, p)
			roles[roleOf[p]] = true
		}
	}
	what := "reads the project"
	var kinds []string
	if g.run {
		kinds = append(kinds, "Cloud Run")
	}
	if g.appEngine {
		kinds = append(kinds, "App Engine")
	}
	if g.firebase {
		kinds = append(kinds, "Firebase Hosting")
	}
	if len(kinds) > 0 {
		what = "can deploy to " + strings.Join(kinds, ", ")
	}
	if len(missing) == 0 {
		v.add("google cloud", "ok", "%s %s in %s", who, what, project)
		return true
	}
	need := "deploy here"
	if len(kinds) == 0 {
		need = "read the project"
	}
	v.add("google cloud", "fail", "%s lacks %s in %s, which it needs to %s", who, strings.Join(missing, ", "), project, need)
	member := "serviceAccount:" + info.Email
	if info.Email == "" {
		member = "serviceAccount:SERVICE_ACCOUNT_EMAIL"
	}
	rs := make([]string, 0, len(roles))
	for r := range roles {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	for _, r := range rs {
		v.fix(fmt.Sprintf("gcloud projects add-iam-policy-binding %s --member=%s --role=%s --condition=None", project, member, r))
	}
	return true
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return ": " + err.Error()
}

func bearer(t string) map[string]string { return map[string]string{"Authorization": "Bearer " + t} }

// verifyCall sends one request and decodes a JSON answer into out (when
// it's JSON). It returns the status; err only when there was no answer.
func (c *ctx) verifyCall(method, u, ctype string, body io.Reader, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return 0, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	req.Header.Set("User-Agent", "keystub-cli")
	resp, err := c.Client.Do(req)
	if err != nil {
		return 0, unwrapURLError(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if out != nil {
		_ = json.Unmarshal(b, out)
	}
	return resp.StatusCode, nil
}

// --- Fly.io, Cloudflare, Convex ---

func flyAuth(t string) map[string]string {
	if strings.HasPrefix(t, "FlyV1 ") {
		return map[string]string{"Authorization": t}
	}
	return bearer(t)
}

func (v *verifier) fly() bool {
	t, app := v.vars["FLY_API_TOKEN"], v.vars["FLY_APP"]
	if t == "" {
		return false
	}
	if app == "" {
		v.add("fly.io", "warn", "FLY_API_TOKEN is set, but FLY_APP isn't: the token's app can't be checked")
		return true
	}
	var out struct {
		Name  string `json:"name"`
		Error string `json:"error"`
	}
	code, err := v.c.verifyCall("GET", flyAPI+"/apps/"+url.PathEscape(app), "", nil, flyAuth(t), &out)
	switch {
	case err != nil:
		v.add("fly.io", "fail", "Fly.io couldn't be reached: %v", err)
	case code == 200:
		v.add("fly.io", "ok", "the token reaches the app %s", app)
	case code == 401 || code == 403:
		v.add("fly.io", "fail", "Fly.io turned the token down for %s (HTTP %d): it expired (run keystub setup again) or isn't for this app", app, code)
	case code == 404:
		v.add("fly.io", "fail", "Fly.io has no app %s, or the token can't see it", app)
	default:
		v.add("fly.io", "warn", "Fly.io answered HTTP %d for %s", code, app)
	}
	return true
}

func (v *verifier) cloudflare() bool {
	t, acct := v.vars["CLOUDFLARE_API_TOKEN"], v.vars["CLOUDFLARE_ACCOUNT_ID"]
	if t == "" {
		return false
	}
	var out struct {
		Success bool `json:"success"`
		Result  struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	u := cloudflareAPI + "/user/tokens/verify"
	if acct != "" {
		u = cloudflareAPI + "/accounts/" + url.PathEscape(acct) + "/tokens/verify"
	}
	code, err := v.c.verifyCall("GET", u, "", nil, bearer(t), &out)
	switch {
	case err != nil:
		v.add("cloudflare", "fail", "Cloudflare couldn't be reached: %v", err)
	case code == 200 && out.Success && out.Result.Status == "active":
		where := "the account"
		if acct != "" {
			where = "account " + acct
		}
		v.add("cloudflare", "ok", "the token is active for %s", where)
	default:
		v.add("cloudflare", "fail", "Cloudflare turned the token down (HTTP %d): it expired (run keystub setup again) or was revoked", code)
	}
	return true
}

func (v *verifier) convex() bool {
	k := v.vars["CONVEX_DEPLOY_KEY"]
	if k == "" {
		return false
	}
	pre, _, ok := strings.Cut(k, "|")
	kind, name, ok2 := strings.Cut(pre, ":")
	if !ok || !ok2 || name == "" {
		v.add("convex", "fail", "CONVEX_DEPLOY_KEY isn't a deploy key (DEPLOYMENT|KEY)")
		return true
	}
	code, err := v.c.verifyCall("GET", fmt.Sprintf(convexCloud, name)+"/api/check_admin_key", "", nil, map[string]string{"Authorization": "Convex " + k}, nil)
	switch {
	case err != nil:
		v.add("convex", "fail", "the deployment %s couldn't be reached: %v", name, err)
	case code == 200:
		v.add("convex", "ok", "the deploy key works for the %s deployment %s", kind, name)
	case code == 401 || code == 403:
		v.add("convex", "fail", "%s turned the deploy key down (HTTP %d): it expired (run keystub setup again) or was deleted", name, code)
	default:
		v.add("convex", "warn", "%s answered HTTP %d", name, code)
	}
	return true
}

// --- AWS, databases ---

func (v *verifier) aws() bool {
	f := v.vars["AWS_SHARED_CREDENTIALS_FILE"]
	if f == "" {
		return false
	}
	if _, err := os.Stat(f); err != nil {
		v.add("aws", "fail", "its credentials file is missing (%s): run keystub setup again", f)
		return true
	}
	if _, err := lookTool("aws"); err != nil {
		v.add("aws", "warn", "the credentials file is there, but the aws CLI isn't installed, so it isn't checked")
		return true
	}
	env := append(os.Environ(), "AWS_SHARED_CREDENTIALS_FILE="+f, "AWS_PROFILE=default", "AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=")
	if r := v.vars["AWS_REGION"]; r != "" {
		env = append(env, "AWS_REGION="+r)
	}
	var out bytes.Buffer
	if err := v.c.Exec(nil, &out, &out, env, "aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text"); err != nil {
		v.add("aws", "fail", "AWS turned the credentials down: %s (run keystub setup again)", lastLine(out.String()))
		return true
	}
	v.add("aws", "ok", "signed in as %s", strings.TrimSpace(out.String()))
	return true
}

func (v *verifier) database() bool {
	raw := v.vars["DATABASE_URL"]
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		v.add("database", "warn", "DATABASE_URL isn't a URL with a host")
		return true
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"postgres": "5432", "postgresql": "5432", "mysql": "3306", "redis": "6379", "rediss": "6379", "mongodb": "27017"}[u.Scheme]
	}
	if port == "" {
		v.add("database", "ok", "DATABASE_URL is set (%s)", u.Scheme)
		return true
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 5*time.Second)
	if err != nil {
		v.add("database", "fail", "%s's host %s doesn't answer on port %s from here: %v", u.Scheme, u.Hostname(), port, err)
		return true
	}
	conn.Close()
	v.add("database", "ok", "%s's host %s answers on port %s", u.Scheme, u.Hostname(), port)
	return true
}

// --- tools ---

// toolInstall is how to install each CLI a deploy needs.
var toolInstall = map[string]string{
	"gcloud":   "keystub tools install gcloud",
	"fly":      "keystub tools install fly",
	"wrangler": "keystub tools install wrangler",
	"aws":      "keystub tools install aws",
	"npx":      "install Node.js (https://nodejs.org)",
}

func (v *verifier) tools(deploys []deployTarget, g googleTargets) {
	need := map[string]string{} // tool → why
	if v.vars["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] != "" || g.run || g.appEngine || g.build {
		need["gcloud"] = "Google Cloud"
	}
	if v.vars["AWS_SHARED_CREDENTIALS_FILE"] != "" {
		need["aws"] = "AWS"
	}
	for _, d := range deploys {
		switch d.Kind {
		case "fly":
			need["fly"] = "Fly.io deploys (" + d.File + ")"
		case "cloudflare":
			need["wrangler"] = "Cloudflare deploys (" + d.File + ")"
		case "convex":
			need["npx"] = "Convex deploys (" + d.File + ")"
		}
	}
	names := make([]string, 0, len(need))
	for n := range need {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if toolHere(n, v.c.homeDir()) {
			v.add(n, "ok", "installed, for %s", need[n])
			continue
		}
		v.add(n, "warn", "not installed, and %s need it", need[n])
		v.fix(toolInstall[n])
	}
}

// toolHere is whether a CLI is on the PATH, or where keystub tools and
// the vendors' installers put it under home (fly as fly or flyctl).
func toolHere(n, home string) bool {
	alts := map[string][]string{"fly": {"fly", "flyctl"}}[n]
	if alts == nil {
		alts = []string{n}
	}
	for _, a := range alts {
		if _, err := lookTool(a); err == nil {
			return true
		}
		if home == "" {
			continue
		}
		for _, d := range []string{filepath.Join(home, ".local", "bin"), filepath.Join(home, ".fly", "bin")} {
			if fi, err := os.Stat(filepath.Join(d, a)); err == nil && !fi.IsDir() {
				return true
			}
		}
	}
	return false
}

// homeDir is HOME, else this user's home.
func (c *ctx) homeDir() string {
	if h := c.Getenv("HOME"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// --- rehearsal ---

func randomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (v *verifier) rehearse() {
	ran := false
	if v.vars["CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"] != "" {
		ran = true
		v.rehearseRun()
	}
	if v.vars["CLOUDFLARE_API_TOKEN"] != "" && v.vars["CLOUDFLARE_ACCOUNT_ID"] != "" {
		ran = true
		v.rehearseWorker()
	}
	if v.vars["FLY_API_TOKEN"] != "" {
		ran = true
		v.add("deploy fly.io", "warn", "not rehearsed: the token reaches only %s, and a rehearsal would deploy to it; deploy to a staging app to test a deploy", v.vars["FLY_APP"])
	}
	if v.vars["CONVEX_DEPLOY_KEY"] != "" {
		ran = true
		v.add("deploy convex", "warn", "not rehearsed: the key reaches only its own deployment; link a dev or preview deployment to test a deploy")
	}
	if !ran {
		v.add("deploy", "warn", "nothing here deploys: no Google Cloud, Cloudflare, Fly.io or Convex credentials")
	}
}

// rehearseRun deploys Google's sample image as a throwaway Cloud Run
// service, waits until it's ready, and deletes it.
func (v *verifier) rehearseRun() {
	project := v.vars["CLOUDSDK_CORE_PROJECT"]
	if project == "" {
		project = v.vars["GOOGLE_CLOUD_PROJECT"]
	}
	tok, err := v.googleToken()
	if err != nil || project == "" {
		v.add("deploy cloud run", "fail", "no token or project to deploy with")
		return
	}
	name := "keystub-verify-" + randomSuffix()
	base := googleRunAPI + "/projects/" + url.PathEscape(project) + "/locations/" + url.PathEscape(v.region) + "/services"
	body, _ := json.Marshal(map[string]any{"template": map[string]any{"containers": []map[string]any{{"image": helloImage}}}})
	var op struct {
		Name  string `json:"name"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	code, err := v.c.verifyCall("POST", base+"?serviceId="+name, "application/json", bytes.NewReader(body), bearer(tok), &op)
	if err != nil || code != 200 {
		v.add("deploy cloud run", "fail", "couldn't create a service in %s/%s (HTTP %d): %s", project, v.region, code, firstNonEmpty(op.Error.Message, errSuffix(err)))
		return
	}
	defer func() {
		var del struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		code, err := v.c.verifyCall("DELETE", base+"/"+name, "", nil, bearer(tok), &del)
		if err != nil || code != 200 {
			v.add("deploy cloud run", "warn", "the throwaway service %s wasn't deleted (HTTP %d %s): delete it with gcloud run services delete %s --region %s --project %s", name, code, del.Error.Message, name, v.region, project)
		}
	}()
	deadline := time.Now().Add(rehearsalWait)
	for {
		var svc struct {
			URI      string `json:"uri"`
			Terminal struct {
				State   string `json:"state"`
				Message string `json:"message"`
			} `json:"terminalCondition"`
			Reconciling bool `json:"reconciling"`
		}
		code, err := v.c.verifyCall("GET", base+"/"+name, "", nil, bearer(tok), &svc)
		if err == nil && code == 200 && !svc.Reconciling {
			switch svc.Terminal.State {
			case "CONDITION_SUCCEEDED":
				v.add("deploy cloud run", "ok", "deployed a throwaway service to %s/%s (%s) and deleted it", project, v.region, svc.URI)
				return
			case "CONDITION_FAILED":
				v.add("deploy cloud run", "fail", "the throwaway service didn't deploy: %s", svc.Terminal.Message)
				return
			}
		}
		if time.Now().After(deadline) {
			v.add("deploy cloud run", "warn", "the throwaway service wasn't ready after %s", rehearsalWait)
			return
		}
		v.c.Sleep(pollEvery)
	}
}

// rehearseWorker uploads a one-line Worker under a throwaway name and
// deletes it.
func (v *verifier) rehearseWorker() {
	t, acct := v.vars["CLOUDFLARE_API_TOKEN"], v.vars["CLOUDFLARE_ACCOUNT_ID"]
	name := "keystub-verify-" + randomSuffix()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	meta, _ := json.Marshal(map[string]any{"main_module": "worker.js", "compatibility_date": "2025-01-01"})
	_ = mw.WriteField("metadata", string(meta))
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="worker.js"; filename="worker.js"`)
	h.Set("Content-Type", "application/javascript+module")
	pw, _ := mw.CreatePart(h)
	_, _ = pw.Write([]byte(`export default { fetch() { return new Response("keystub verify") } }`))
	_ = mw.Close()
	base := cloudflareAPI + "/accounts/" + url.PathEscape(acct) + "/workers/scripts/" + name
	var out struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	code, err := v.c.verifyCall("PUT", base, mw.FormDataContentType(), &buf, bearer(t), &out)
	if err != nil || code != 200 || !out.Success {
		why := errSuffix(err)
		if len(out.Errors) > 0 {
			why = out.Errors[0].Message
		}
		v.add("deploy cloudflare", "fail", "couldn't upload a Worker to account %s (HTTP %d): %s", acct, code, why)
		return
	}
	code, err = v.c.verifyCall("DELETE", base, "", nil, bearer(t), nil)
	if err != nil || code != 200 {
		v.add("deploy cloudflare", "warn", "uploaded a throwaway Worker, but it wasn't deleted (HTTP %d): delete %s in the dashboard", code, name)
		return
	}
	v.add("deploy cloudflare", "ok", "uploaded a throwaway Worker to account %s and deleted it", acct)
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
