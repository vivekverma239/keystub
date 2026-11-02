// Package cli is the `keystub` commands that drive a server's JSON API
// (protocol/api.md): login, keys, envs, tokens, services, usage, setup
// and ca. One CLI drives the hosted service and a self-hosted server.
//
// It is written for people and their coding agents alike: every command
// takes --json, nothing prompts when stdin isn't a terminal, exit codes
// are stable, secret values are read only from stdin or an environment
// variable and never printed back, and a new token is printed once.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Exit codes. They are part of the CLI's contract: scripts and agents
// branch on them.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2 // a bad command line, or a delete without --yes when nothing can ask
	ExitNoAuth      = 3 // not signed in, or the server refused the credentials
	ExitNotFound    = 4
	ExitConflict    = 5
	DefaultServer   = "https://app.keystub.app"
	credentialsFile = "cli.json"
)

// Commands are the top-level commands this package runs.
var Commands = []string{"login", "logout", "whoami", "keys", "projects", "envs", "tokens", "services", "usage", "setup", "ca"}

// Env is everything a command touches outside itself, so tests can run
// it in-process.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Home           string // $KEYSTUB_HOME, ~/.keystub by default
	StdinTerminal  bool   // a person may be typing: prompts are allowed
	Client         *http.Client
	Hostname       string
	Sleep          func(time.Duration)
	// ReadSecret reads a value typed at the terminal without echoing it.
	ReadSecret func(prompt string) (string, error)
}

// Error is a failure with its exit code.
type Error struct {
	Code    int
	Message string
	Extra   map[string]any // more fields for the JSON error, e.g. linkedIn
}

func (e *Error) Error() string { return e.Message }

func usageErr(format string, a ...any) error {
	return &Error{Code: ExitUsage, Message: fmt.Sprintf(format, a...)}
}

// Main runs one command and returns its exit code.
func Main(e Env, cmd string, args []string) int {
	if e.Client == nil {
		e.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if e.Sleep == nil {
		e.Sleep = time.Sleep
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	g, rest, err := globals(args)
	c := &ctx{Env: e, json: g.json, yes: g.yes}
	if err == nil {
		c.server, err = c.resolveServer(g.server)
	}
	if err == nil {
		err = c.dispatch(cmd, rest)
	}
	if err == nil {
		return ExitOK
	}
	var ce *Error
	if !errors.As(err, &ce) {
		ce = &Error{Code: ExitError, Message: err.Error()}
	}
	if c.json {
		body := map[string]any{"type": "keystub", "message": ce.Message, "exitCode": ce.Code}
		for k, v := range ce.Extra {
			body[k] = v
		}
		_ = json.NewEncoder(e.Stdout).Encode(map[string]any{"error": body})
	} else {
		fmt.Fprintln(e.Stderr, "keystub:", ce.Message)
	}
	return ce.Code
}

type ctx struct {
	Env
	json, yes    bool
	server       string // no trailing slash
	serverFrom   string // flag, env, login, local or default
	localChecked bool   // checkLocal passed
}

func (c *ctx) dispatch(cmd string, args []string) error {
	switch cmd {
	case "login":
		return c.login(args)
	case "logout":
		return c.logout(args)
	case "whoami":
		return c.whoami(args)
	case "keys":
		return c.keys(args)
	case "envs":
		return c.envs(args)
	case "projects":
		return c.projects(args)
	case "tokens":
		return c.tokens(args)
	case "services":
		return c.services(args)
	case "usage":
		return c.usage(args)
	case "setup":
		return c.setup(args)
	case "ca":
		return c.ca(args)
	}
	return usageErr("unknown command %q", cmd)
}

// --- arguments ---

type globalFlags struct {
	server    string
	json, yes bool
}

// globals takes the flags every command shares out of args, wherever
// they are.
func globals(args []string) (globalFlags, []string, error) {
	var g globalFlags
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return g, append(rest, args[i:]...), nil
		case a == "--json":
			g.json = true
		case a == "--yes" || a == "-y":
			g.yes = true
		case a == "--server":
			if i+1 >= len(args) {
				return g, nil, usageErr("--server needs a URL")
			}
			i++
			g.server = args[i]
		case strings.HasPrefix(a, "--server="):
			g.server = strings.TrimPrefix(a, "--server=")
		default:
			rest = append(rest, a)
		}
	}
	return g, rest, nil
}

// parsed is a command's flags and positional arguments.
type parsed struct {
	flags map[string]string
	set   map[string]bool
	args  []string
}

func (p parsed) has(name string) bool { return p.set[name] }

// parse reads a command's own flags. valued lists the flags that take a
// value; switches those that don't. Anything else starting with - is a
// usage error.
func parse(args []string, valued, switches []string) (parsed, error) {
	p := parsed{flags: map[string]string{}, set: map[string]bool{}}
	isValued := map[string]bool{}
	for _, v := range valued {
		isValued[v] = true
	}
	isSwitch := map[string]bool{}
	for _, v := range switches {
		isSwitch[v] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			p.args = append(p.args, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			p.args = append(p.args, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case name == "value":
			return p, usageErr("a key's value never goes in an argument, where ps and shell history keep it: pipe it on stdin or use --from-env VAR")
		case isValued[name]:
			if !hasVal {
				if i+1 >= len(args) {
					return p, usageErr("--%s needs a value", name)
				}
				i++
				val = args[i]
			}
			p.flags[name], p.set[name] = val, true
		case isSwitch[name] && !hasVal:
			p.set[name] = true
		default:
			return p, usageErr("unknown flag %s", a)
		}
	}
	return p, nil
}

// want checks the number of positional arguments.
func (p parsed) want(min, max int, usage string) error {
	if len(p.args) < min || len(p.args) > max {
		return usageErr("usage: keystub %s", usage)
	}
	return nil
}

// --- server and credentials ---

// resolveServer picks the server: --server, else $KEYSTUB_SERVER, else
// the one `keystub login` signed in to, else a `keystub serve` running on
// this box, else the hosted service.
func (c *ctx) resolveServer(flag string) (string, error) {
	s, from := flag, "flag"
	if s == "" {
		s, from = c.Getenv("KEYSTUB_SERVER"), "env"
	}
	if s == "" {
		if cr, err := c.loadCredentials(); err == nil && cr.Server != "" {
			s, from = cr.Server, "login"
		}
	}
	local := c.localServer()
	if s == "" {
		s, from = local, "local"
	}
	if s == "" {
		s, from = DefaultServer, "default"
	}
	c.serverFrom = from
	u, err := url.Parse(strings.TrimSuffix(s, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", usageErr("%q isn't a server URL like https://app.keystub.app", s)
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) && !(local != "" && sameServer(local, s) && ownAddress(u.Hostname())) {
		return "", usageErr("%s: use https; plain http is only for a server on this machine", s)
	}
	u.Path, u.RawQuery, u.Fragment = strings.TrimSuffix(u.Path, "/"), "", ""
	return u.String(), nil
}

// ownAddress reports whether h is an IP address of this machine, so a
// connection to it never leaves the machine.
func ownAddress(h string) bool {
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// localServer is the dashboard of a `keystub serve` on this machine, from
// the serve.json it writes while it runs; "" if none.
func (c *ctx) localServer() string {
	b, err := os.ReadFile(filepath.Join(c.Home, "serve.json"))
	if err != nil {
		return ""
	}
	var si struct {
		DashboardAddr string `json:"dashboardAddr"`
	}
	if json.Unmarshal(b, &si) != nil || si.DashboardAddr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(si.DashboardAddr)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
		if ip != nil && ip.To4() == nil {
			host = "::1"
		}
	}
	return "http://" + net.JoinHostPort(host, port)
}

// credential finds what to send as the bearer token: $KEYSTUB_API_KEY,
// else what `keystub login` saved for this server, else, for the
// `keystub serve` on this machine, its admin API key. The admin key is
// never sent anywhere else.
func (c *ctx) credential() (string, error) {
	if k := strings.TrimSpace(c.Getenv("KEYSTUB_API_KEY")); k != "" {
		// The key is for one server; never guess which. Only --server or
		// $KEYSTUB_SERVER names it: not the default, serve.json or the
		// server `keystub login` saved, which may be another.
		if c.serverFrom != "flag" && c.serverFrom != "env" {
			return "", usageErr("KEYSTUB_API_KEY is set but no server is named for it: set KEYSTUB_SERVER (or pass --server) to the server it is for")
		}
		return k, nil
	}
	if cr, err := c.loadCredentials(); err == nil && cr.Token != "" && sameServer(cr.Server, c.server) {
		return cr.Token, nil
	}
	if local := c.localServer(); local != "" && sameServer(local, c.server) {
		if b, err := os.ReadFile(filepath.Join(c.Home, "admin.token")); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				if err := c.checkLocal(); err != nil {
					return "", err
				}
				return t, nil
			}
		}
	}
	return "", &Error{Code: ExitNoAuth, Message: "not signed in to " + c.server + ": run `keystub login`, or set KEYSTUB_API_KEY"}
}

// checkLocal makes sure the server serve.json names is a running Keystub
// before it gets the admin key: serve.json outlives the server, and
// something else may listen on its port now. Keystub answers /api/me
// without a key with 401 and its own error shape.
func (c *ctx) checkLocal() error {
	if c.localChecked {
		return nil
	}
	stale := &Error{Code: ExitNoAuth, Message: c.server + " doesn't answer as Keystub; is keystub serve running? (its serve.json may be left from an earlier run)"}
	resp, err := c.do("GET", "/api/me", "", nil)
	if err != nil {
		return stale
	}
	defer resp.Body.Close()
	var e struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusUnauthorized || json.Unmarshal(b, &e) != nil || e.Error.Type != "keystub" {
		return stale
	}
	c.localChecked = true
	return nil
}

func sameServer(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/"))
}

// --- HTTP ---

// call sends a request to the API and decodes a JSON answer into out (if
// not nil). An error answer becomes an *Error with the matching exit code.
func (c *ctx) call(method, path string, body, out any) error {
	tok, err := c.credential()
	if err != nil {
		return err
	}
	return c.send(method, path, tok, body, out)
}

func (c *ctx) send(method, path, token string, body, out any) error {
	resp, err := c.do(method, path, token, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeAnswer(resp, out)
}

func (c *ctx) do(method, path, token string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.server+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't reach %s: %v", c.server, unwrapURLError(err))
	}
	return resp, nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func decodeAnswer(resp *http.Response, out any) error {
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return answerError(resp.StatusCode, b)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("the server's answer isn't the JSON expected (%s)", resp.Status)
	}
	return nil
}

func answerError(status int, b []byte) error {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	msg := http.StatusText(status)
	var extra map[string]any
	if json.Unmarshal(b, &e) == nil && len(e.Error) > 0 {
		var full map[string]any
		var s string
		if json.Unmarshal(e.Error, &full) == nil {
			if m, ok := full["message"].(string); ok && m != "" {
				msg = m
			}
			for k, v := range full {
				if k != "message" && k != "type" {
					if extra == nil {
						extra = map[string]any{}
					}
					extra[k] = v
				}
			}
		} else if json.Unmarshal(e.Error, &s) == nil && s != "" {
			msg = s
		}
	}
	code := ExitError
	switch status {
	case http.StatusUnauthorized:
		code = ExitNoAuth
	case http.StatusNotFound:
		code = ExitNotFound
	case http.StatusConflict:
		code = ExitConflict
	}
	return &Error{Code: code, Message: msg, Extra: extra}
}

// --- output ---

// emit prints v as JSON under --json, else runs human.
func (c *ctx) emit(v any, human func(w io.Writer)) error {
	if c.json {
		enc := json.NewEncoder(c.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	human(c.Stdout)
	return nil
}

// table prints rows with columns padded to line up.
func table(w io.Writer, header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			widths[i] = max(widths[i], len(cell))
		}
	}
	line := func(cells []string) {
		var b strings.Builder
		for i, cell := range cells {
			if i == len(cells)-1 {
				b.WriteString(cell)
			} else {
				b.WriteString(cell + strings.Repeat(" ", widths[i]-len(cell)+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
	line(header)
	for _, r := range rows {
		line(r)
	}
}

// confirm allows a delete: --yes, or a "y" typed at the terminal.
func (c *ctx) confirm(what string) error {
	if c.yes {
		return nil
	}
	if !c.StdinTerminal {
		return usageErr("%s: pass --yes to confirm (nothing can ask, since stdin isn't a terminal)", what)
	}
	fmt.Fprintf(c.Stderr, "%s? [y/N] ", what)
	line, _ := readLine(c.Stdin)
	if a := strings.ToLower(strings.TrimSpace(line)); a == "y" || a == "yes" {
		return nil
	}
	return &Error{Code: ExitError, Message: "not confirmed"}
}

func readLine(r io.Reader) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return string(b), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			return string(b), err
		}
	}
}

// readValue reads a secret value: from $VAR with --from-env (or VAR in
// a dotenv file, with --env-file too), else from stdin (piped), else
// typed at the terminal without echo.
func (c *ctx) readValue(p parsed, what string) (string, error) {
	if file, ok := p.flags["env-file"]; ok {
		v, ok := p.flags["from-env"]
		if !ok {
			return "", usageErr("--env-file FILE goes with --from-env VAR: the variable to read from FILE")
		}
		return dotenvValue(file, v)
	}
	if v, ok := p.flags["from-env"]; ok {
		val := c.Getenv(v)
		if strings.TrimSpace(val) == "" {
			return "", usageErr("$%s is empty or not set", v)
		}
		return val, nil
	}
	if c.StdinTerminal {
		if c.ReadSecret == nil {
			return "", usageErr("pipe the %s on stdin, or use --from-env VAR", what)
		}
		v, err := c.ReadSecret("Paste the " + what + ", then press Enter: ")
		if err != nil {
			return "", fmt.Errorf("couldn't read the %s: %v", what, err)
		}
		return v, nil
	}
	b, err := io.ReadAll(io.LimitReader(c.Stdin, 1<<20))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", usageErr("no %s on stdin: pipe it in, or use --from-env VAR", what)
	}
	return string(b), nil
}

// maxRounds bounds how often untilDone asks again; hosted tells the edge
// at most 40 changes a request, so this covers 2,000.
const maxRounds = 50

// untilDone sends method to path, then nextMethod to next while the
// server says some of the work remains: hosted deletes an
// environment or a service over several requests, answering how many
// changes it has still to tell the edge. Self-hosted finishes in one and
// says nothing, which reads as 0.
func (c *ctx) untilDone(method, path, nextMethod, next string) error {
	var out struct {
		Remaining int `json:"remaining"`
	}
	if err := c.call(method, path, nil, &out); err != nil {
		return err
	}
	for i := 1; out.Remaining > 0; i++ {
		if i == maxRounds {
			return fmt.Errorf("%d changes are still to reach the edge; try again later with %s %s", out.Remaining, nextMethod, next)
		}
		out.Remaining = 0
		if err := c.call(nextMethod, next, nil, &out); err != nil {
			return err
		}
	}
	return nil
}

// envPath is the API path of an environment: "<project>/<env>", whose
// two parts are slugs, so the slash goes as is.
func envPath(env string) (string, error) {
	p, e, ok := strings.Cut(env, "/")
	if !ok || p == "" || e == "" || strings.Contains(e, "/") {
		return "", usageErr("%q isn't an environment like my-app/dev", env)
	}
	return "/api/environments/" + url.PathEscape(p) + "/" + url.PathEscape(e), nil
}
