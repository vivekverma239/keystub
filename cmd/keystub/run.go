package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/vivekverma239/keystub/internal/legacy"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/vivekverma239/keystub/internal/agent"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/dashboard"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/runenv"
)

// runOpts are the flags `run` and `env` share.
type runOpts struct {
	envID, name string
	direct      bool
	token       string // a proxy token to use as it is, instead of one from the admin API
	remote      string // an edge URL: forward to it with no local server
}

func (o *runOpts) flags(fs *flag.FlagSet) {
	fs.StringVar(&o.envID, "env", "", "environment, e.g. my-app/prod (default: $KEYSTUB_ENV, else default/dev)")
	fs.StringVar(&o.name, "name", "", "token name (default: the git worktree's folder)")
	fs.BoolVar(&o.direct, "direct", false, "quick start: base URLs pointing at the edge, no proxy or CA")
	fs.StringVar(&o.token, "token", "", "use this proxy token instead of asking the local server for one; prefer $KEYSTUB_TOKEN, since a flag shows in ps")
	fs.StringVar(&o.remote, "remote", "", "an edge URL, e.g. https://keystub.example.com: forward to it, with no keys or server on this box")
}

func (o runOpts) check() error {
	if o.token == "" {
		if o.remote != "" {
			return errors.New("--remote needs a proxy token: pass --token or set $KEYSTUB_TOKEN")
		}
		return nil
	}
	if o.envID != "" || o.name != "" {
		return errors.New("--env and --name pick a token on your own server; with --token, the token decides")
	}
	if !strings.HasPrefix(core.Normalize(o.token), core.TokenPrefix) {
		return errors.New("--token must be a proxy token (sk-stub-… or skstub…)")
	}
	return nil
}

// issued is a token and the services it may use, from the admin API or
// from an edge's catalog.
type issued struct {
	token, name, env string
	services         []svcVars
}

// svcVars is what `run` needs to know about a service.
type svcVars struct {
	ID, Name string
	EnvVars  []string
	BaseURL  core.BaseURL
}

func fromCatalog(token string, c proxy.CatalogResponse) issued {
	is := issued{token: token, name: c.Token.Name, env: c.Token.Env}
	for _, s := range c.Services {
		is.services = append(is.services, svcVars{ID: s.ID, Name: s.Name, EnvVars: s.EnvVars, BaseURL: s.BaseURL})
	}
	return is
}

// where says how a command reaches Keystub: a proxy and an edge.
type where struct {
	proxyAddr  string // "" for quick start
	edgeURL    string
	caPath     string
	bundlePath string
}

// build turns a token and its services into the command's environment.
func build(is issued, w where, direct bool) (map[string]string, error) {
	var envVars, baseURLs, needProxy []string
	for _, s := range is.services {
		if direct && s.BaseURL.Var == "" {
			needProxy = append(needProxy, s.Name)
			continue
		}
		envVars = append(envVars, s.EnvVars...)
		if s.BaseURL.Var != "" {
			baseURLs = append(baseURLs, s.BaseURL.Var+"=/s/"+s.ID+s.BaseURL.Path)
		}
	}
	if direct {
		if w.edgeURL == "" {
			return nil, errors.New("this Keystub server has no edge; restart it with this version of keystub serve")
		}
		if len(needProxy) > 0 {
			fmt.Fprintf(os.Stderr, "keystub: %s can't be used without the proxy; use keystub run for them\n", strings.Join(needProxy, ", "))
		}
		return runenv.Vars(runenv.Config{
			Token: is.token, KeyName: is.name, EnvID: is.env, EnvVars: envVars,
			Direct: true, EdgeURL: w.edgeURL, BaseURLs: baseURLs,
		}, os.Getenv), nil
	}
	bundle := w.bundlePath
	if bundle != "" {
		if _, err := os.Stat(bundle); err != nil {
			bundle = ""
		}
	}
	if bundle == "" {
		fmt.Fprintln(os.Stderr, "keystub: warning: no CA bundle, so Python and curl won't trust the proxy")
	}
	return runenv.Vars(runenv.Config{
		ProxyAddr: w.proxyAddr, Token: is.token, KeyName: is.name, EnvID: is.env,
		CAPath: w.caPath, BundlePath: bundle, EnvVars: envVars,
	}, os.Getenv), nil
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// onThisBox turns a listen address into one to dial from this box: a
// server on every interface (0.0.0.0:8789, [::]:8789, :8789) is reached
// on loopback, so its plain-HTTP edge isn't taken for one off the box.
func onThisBox(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if ip != nil && ip.To4() == nil {
			return net.JoinHostPort("::1", port)
		}
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

// local finds what's running on this box. With a token, a running agent
// (`keystub agent`) comes first, else a server (`keystub serve`); without
// one, only a server can hand out tokens. An agent whose proxy no longer
// answers (it crashed and left agent.json) is skipped.
func local(dir string, withToken bool) (where, *serveInfo, *agentInfo, error) {
	ai, agentUp := runningAgent(dir)
	if withToken && agentUp {
		return where{proxyAddr: ai.ProxyAddr, edgeURL: ai.Remote, caPath: ai.CAPath, bundlePath: ai.BundlePath}, nil, ai, nil
	}
	var si serveInfo
	if err := readJSON(filepath.Join(dir, "serve.json"), &si); err != nil {
		if agentUp {
			return where{}, nil, nil, errors.New("this box runs an agent with no keys or admin access: pass --token or set $KEYSTUB_TOKEN")
		}
		return where{}, nil, nil, errors.New("Keystub isn't running. Start it with `keystub serve`, or `keystub agent --remote URL`, or pass --remote")
	}
	w := where{proxyAddr: onThisBox(si.ProxyAddr), caPath: filepath.Join(dir, "ca.pem"), bundlePath: filepath.Join(dir, "ca-bundle.pem")}
	if si.EdgeAddr != "" {
		w.edgeURL = "http://" + onThisBox(si.EdgeAddr)
	}
	return w, &si, nil, nil
}

// runningAgent reads agent.json and reports whether that agent still runs:
// its process is alive and its proxy accepts connections. Both, since a
// `keystub serve` may have taken the port of an agent that died.
func runningAgent(dir string) (*agentInfo, bool) {
	var ai agentInfo
	if readJSON(filepath.Join(dir, "agent.json"), &ai) != nil || ai.PID <= 0 {
		return nil, false
	}
	if !processAlive(ai.PID) {
		return nil, false
	}
	return &ai, listening(ai.ProxyAddr)
}

// listening reports whether something accepts connections at addr.
func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// onlyDecrypted drops services the running agent doesn't decrypt: their
// hosts are tunnelled, so a stub token in their variables would reach the
// service as is. That happens when the agent's token is scoped to fewer
// services than the command's.
func onlyDecrypted(is issued, ai *agentInfo) issued {
	if ai == nil || ai.Services == nil {
		return is
	}
	var keep []svcVars
	var dropped []string
	for _, s := range is.services {
		if slices.Contains(ai.Services, s.ID) {
			keep = append(keep, s)
		} else {
			dropped = append(dropped, s.Name)
		}
	}
	if len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "keystub: warning: the running agent doesn't decrypt %s, so its variables aren't set: the agent's token can't use it, or its hosts aren't in Keystub's catalog and weren't allowed with --allow-host\n", strings.Join(dropped, ", "))
	}
	is.services = keep
	return is
}

func parseRemote(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSuffix(s, "/"))
	if err != nil {
		return nil, fmt.Errorf("%q isn't an edge URL like https://keystub.example.com", s)
	}
	if err := agent.CheckRemote(u); err != nil {
		return nil, err
	}
	return u, nil
}

// parse reads the flags, taking the token from $KEYSTUB_TOKEN when none is
// given. It isn't the flag's default, which usage output would print.
func (o *runOpts) parse(fs *flag.FlagSet, args []string) {
	_ = fs.Parse(args)
	if o.token == "" {
		o.token = legacy.Getenv("KEYSTUB_TOKEN")
	}
}

// catalogFrom asks an edge which services token may use.
func catalogFrom(edgeURL, token string) (issued, error) {
	if edgeURL == "" {
		return issued{}, errors.New("this Keystub server has no edge to ask about the token; restart it with this version of keystub serve")
	}
	u, err := parseRemote(edgeURL)
	if err != nil {
		return issued{}, err
	}
	c, err := agent.FetchCatalog(context.Background(), proxy.EdgeTransport(), u, token)
	if err != nil {
		return issued{}, err
	}
	warnDropped(c)
	return fromCatalog(token, c), nil
}

// fromMachine fills in the token on a linked machine: the server makes or
// returns this worktree's token, with no admin token. A command then goes
// through a running agent for the same server, else through a private
// agent forwarding to it.
func (o *runOpts) fromMachine() error {
	if o.token != "" {
		return nil
	}
	dir, err := homeDir()
	if err != nil {
		return err
	}
	mi, cred, err := linkedMachine(dir)
	if err != nil || mi == nil {
		return err
	}
	if o.remote != "" && !sameServer(o.remote, mi.Server) {
		return nil // another server: its token isn't this machine's to give
	}
	tok, err := machineToken(context.Background(), mi, cred, o.envID, o.name)
	if err != nil {
		return err
	}
	o.token, o.envID, o.name = tok, "", ""
	if o.remote == "" {
		ai, up := runningAgent(dir)
		if !up || !sameServer(ai.Remote, mi.Server) {
			o.remote = mi.Server
		}
	}
	return nil
}

// vars builds the environment for a command that uses what is already
// running on this box, or quick start against --remote.
func vars(o runOpts) (map[string]string, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	if o.remote != "" {
		if !o.direct {
			return nil, errors.New("--remote without --direct needs a proxy for the command: use keystub run, or start `keystub agent --remote URL`")
		}
		is, err := catalogFrom(o.remote, o.token)
		if err != nil {
			return nil, err
		}
		return build(is, where{edgeURL: strings.TrimSuffix(o.remote, "/")}, true)
	}
	dir, err := homeDir()
	if err != nil {
		return nil, err
	}
	w, si, ai, err := local(dir, o.token != "")
	if err != nil {
		return nil, err
	}
	if o.token != "" {
		is, err := catalogFrom(w.edgeURL, o.token)
		if err != nil {
			return nil, err
		}
		if !o.direct {
			is = onlyDecrypted(is, ai)
		}
		return build(is, w, o.direct)
	}
	is, err := ensure(dir, *si, o.envID, o.name)
	if err != nil {
		return nil, err
	}
	return build(is, w, o.direct)
}

// ensure asks the local server, with its admin token, for this worktree's
// token in envID, creating it on first use.
func ensure(dir string, info serveInfo, envID, name string) (issued, error) {
	tb, err := os.ReadFile(filepath.Join(dir, "admin.token"))
	if err != nil {
		return issued{}, err
	}
	admin := strings.TrimSpace(string(tb))
	if name == "" {
		name = runenv.DefaultKeyName()
	}

	// Talk to the dashboard directly, even when run inside another `keystub run`.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	call := func(method, path string, body, out any) error {
		var rd *bytes.Reader
		if body != nil {
			jb, _ := json.Marshal(body)
			rd = bytes.NewReader(jb)
		} else {
			rd = bytes.NewReader(nil)
		}
		req, err := http.NewRequest(method, "http://"+info.DashboardAddr+path, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("can't reach Keystub; is `keystub serve` still running?")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var e dashboard.APIError
			if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error.Message != "" {
				return errors.New(e.Error.Message)
			}
			return fmt.Errorf("%s %s: %s", method, path, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}

	if envID == "" {
		envID = envOr("KEYSTUB_ENV", core.DefaultEnv)
	}
	var key dashboard.TokenResponse
	if err := call("POST", "/api/tokens/ensure", map[string]string{"env": envID, "name": name}, &key); err != nil {
		return issued{}, err
	}
	var svcs struct {
		Services []core.Service `json:"services"`
	}
	if err := call("GET", "/api/services", nil, &svcs); err != nil {
		return issued{}, err
	}
	is := issued{token: key.Token, name: key.Name, env: key.Env}
	for _, s := range svcs.Services {
		is.services = append(is.services, svcVars{ID: s.ID, Name: s.Name, EnvVars: s.EnvVars, BaseURL: s.BaseURL})
	}
	return is, nil
}

const runUsage = "usage: keystub run [--env PROJECT/ENV] [--name NAME] [--token TOKEN] [--remote URL] [--direct] -- COMMAND [ARGS...]"

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var o runOpts
	o.flags(fs)
	o.parse(fs, args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		return errors.New(runUsage)
	}
	path, err := exec.LookPath(cmd[0])
	if err != nil {
		return err
	}
	if err := o.fromMachine(); err != nil {
		return err
	}
	if o.remote != "" && !o.direct {
		return runWithAgent(o, path, cmd)
	}
	v, err := vars(o)
	if err != nil {
		return err
	}
	// Replace this process, so signals and exit codes behave as if the
	// command were run directly.
	return syscall.Exec(path, cmd, runenv.Environ(v))
}

// runWithAgent starts an agent for this one command (a sandbox or CI job
// with only a token) and runs the command as a child, since the agent must
// outlive the exec.
func runWithAgent(o runOpts, path string, cmd []string) error {
	if err := o.check(); err != nil {
		return err
	}
	remote, err := parseRemote(o.remote)
	if err != nil {
		return err
	}
	dir, err := homeDir()
	if err != nil {
		return err
	}
	a, err := agent.Start(context.Background(), agent.Config{Home: dir, Remote: remote, Token: o.token, Listen: "127.0.0.1:0", AllowHosts: envHosts()})
	if err != nil {
		return err
	}
	defer a.Close()
	warnIgnored(a.Ignored, "set $KEYSTUB_ALLOW_HOSTS (comma-separated HOST for a custom service, SERVICE=HOST for a built-in one's own server)")
	warnDropped(a.Catalog)
	v, err := build(fromCatalog(o.token, a.Catalog), where{proxyAddr: a.Addr, caPath: a.CAPath, bundlePath: a.BundlePath}, false)
	if err != nil {
		return err
	}
	return runChild(path, cmd, runenv.Environ(v))
}

// warnIgnored names the hosts the edge listed that the agent won't
// decrypt, and how to allow them (how says where: a flag or the variable).
func warnIgnored(hosts []string, how string) {
	if len(hosts) > 0 {
		fmt.Fprintf(os.Stderr, "keystub: warning: not decrypting %s: not in Keystub's catalog for that service, and a built-in service's host is decrypted only as that service. To trust another host on this box, %s\n", strings.Join(hosts, ", "), how)
	}
}

// warnDropped names the variables a catalog asked for that weren't set.
func warnDropped(c proxy.CatalogResponse) {
	if len(c.Dropped) > 0 {
		fmt.Fprintf(os.Stderr, "keystub: warning: not setting %s: a server's custom service may set only variables named like FOO_KEY, FOO_TOKEN, FOO_SECRET or FOO_PASSWORD that no built-in service reads\n", strings.Join(c.Dropped, ", "))
	}
}

// exitCode is a child's exit status, passed on as keystub's own.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// stdinIsTerminal reports whether keystub runs in a terminal, where Ctrl-C
// reaches the whole foreground process group, the child included.
var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// stopSignals are the signals that stop keystub (and are passed to a
// child), less any the process started with ignored: under `nohup`,
// SIGHUP must keep being ignored, by keystub and its child.
func stopSignals() []os.Signal {
	var out []os.Signal
	for _, s := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		if !signal.Ignored(s) {
			out = append(out, s)
		}
	}
	return out
}

// runChild runs a command to the end and returns its exit status as an
// exitCode. SIGTERM and SIGHUP are passed on. SIGINT is passed on too,
// except in a terminal, where the child already got it from Ctrl-C and a
// second one would read as "force quit".
func runChild(path string, cmd, environ []string) error {
	forwardInt := !stdinIsTerminal()
	c := exec.Command(path, cmd[1:]...)
	c.Args[0] = cmd[0]
	c.Env, c.Stdin, c.Stdout, c.Stderr = environ, os.Stdin, os.Stdout, os.Stderr
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, stopSignals()...)
	defer func() { signal.Stop(sig); close(sig) }()
	if err := c.Start(); err != nil {
		return err
	}
	go func() {
		for s := range sig {
			if s != os.Interrupt || forwardInt {
				_ = c.Process.Signal(s)
			}
		}
	}()
	err := c.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitCode(128 + int(ws.Signal()))
		}
		return exitCode(ee.ExitCode())
	}
	return err
}

func env(args []string) error {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	var o runOpts
	o.flags(fs)
	o.parse(fs, args)
	explicitRemote := o.remote != ""
	if err := o.fromMachine(); err != nil {
		return err
	}
	if o.remote != "" && !explicitRemote && !o.direct {
		return errors.New("this machine is linked but no agent is running for its server; start `keystub agent`, or use --direct")
	}
	v, err := vars(o)
	if err != nil {
		return err
	}
	fmt.Print(runenv.Exports(v))
	return nil
}
