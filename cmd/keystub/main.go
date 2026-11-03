// Command keystub runs the Keystub proxy and dashboard, and starts commands
// that use it.
//
//	keystub serve                 start the proxy and the dashboard
//	keystub agent --remote URL    start only the proxy, forwarding to an edge
//	keystub gateway --edge URL    the hosted remote proxy, for many accounts
//	keystub run -- npm run dev    run a command with this worktree's proxy token
//	eval "$(keystub env)"         the same variables, for a shell or .envrc
//	keystub keys|envs|tokens|…    set Keystub up through its API (internal/cli)
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/vivekverma239/keystub/internal/legacy"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/vivekverma239/keystub/docs"
	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/cli"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/dashboard"
	"github.com/vivekverma239/keystub/internal/limit"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/reqlog"
	"github.com/vivekverma239/keystub/internal/runenv"
	"github.com/vivekverma239/keystub/internal/secrets"
	"github.com/vivekverma239/keystub/internal/storage/jsonfile"
	"github.com/vivekverma239/keystub/internal/storage/sqlite"
)

const usageText = `Keystub keeps real API keys out of your processes.

Usage:
  keystub serve [--proxy 127.0.0.1:8787] [--dashboard 127.0.0.1:8788]
                [--edge 127.0.0.1:8789] [--require-token]
                [--secrets auto|keychain|env|file] [--storage json|sqlite]
                [--client-ip-header NAME]
  keystub link [--name NAME] [--force] SERVER_URL
  keystub unlink
  keystub agent --remote URL [--token TOKEN] [--proxy 127.0.0.1:8787]
                [--allow-host [SERVICE=]HOST]...
  keystub gateway --edge URL [--listen :8080] [--health :8081]
                [--tls-in-front | --tls-cert FILE --tls-key FILE]
                [--tunnel-port 443]...
  keystub run [--env PROJECT/ENV] [--name NAME] [--direct] -- COMMAND [ARGS...]
  keystub run --token TOKEN [--remote URL] [--direct] -- COMMAND [ARGS...]
  keystub env [--env PROJECT/ENV] [--name NAME] [--token TOKEN] [--direct]
  keystub skill install [--agent claude|codex|cursor|agents|all] [--project]
                [--dir DIR] [--json]

Set Keystub up from the command line (hosted or self-hosted):
  keystub login [--no-browser] | logout | whoami
  keystub init [PROJECT/ENV] [--env-file FILE] [--key-name NAME] [--write-env] [--dry-run]
  keystub doctor [PROJECT/ENV] [--env-file FILE]
  keystub services list | add | remove
  keystub keys list | add | scan | show | replace | rename | limits | delete
  keystub projects list | limits
  keystub envs list | add | limits | delete | link | unlink | links
  keystub tokens create | list | revoke
  keystub usage [PROJECT/ENV] [--by service,token,key] [--range 7d]
  keystub setup PROJECT/ENV
  keystub ca [-o FILE]
  keystub help agents           a setup guide a coding agent can follow
  keystub version
These take --json, --yes (for deletes) and --server URL ($KEYSTUB_SERVER;
default: the server you logged in to, else a keystub serve on this
machine, else https://app.keystub.app). Credentials: $KEYSTUB_API_KEY,
else keystub login (~/.keystub/cli.json), else the local server's admin
API key. Exit codes: 0 ok, 1 error, 2 usage, 3 not signed in, 4 not
found, 5 conflict.

NAME defaults to the git worktree's folder, so each worktree gets its own
token. ENV defaults to $KEYSTUB_ENV, else default/dev. --direct is quick
start: SDK base URLs point at the edge, with no proxy or CA, for services
that have a base URL in the catalog.

With $KEYSTUB_TOKEN (or --token, which shows in ps), run and env use that
token as it is, with no admin access. --remote URL forwards to that edge: run starts a private
agent for the one command, so the box needs no server and holds no keys.
Without --remote they use the running agent, else the running server.

keystub gateway is the hosted remote proxy (Keystub runs it): boxes set
HTTPS_PROXY=https://keystub:<token>@<gateway> and trust their account's CA,
with no binary. It checks tokens with the edge and forwards decrypted
requests to the edge's /h; its credential comes from $KEYSTUB_GATEWAY_KEY.

keystub link links this machine to a server: an admin approves the code it
shows on the dashboard's Machines page. On a linked machine, run and env get
this worktree's token from that server with no admin token or --token, and
keystub agent needs no flags.

keystub skill install writes the Keystub skill (a SKILL.md folder that
teaches a coding agent the commands above) where agents read skills:
~/.claude/skills for Claude Code and ~/.agents/skills for Codex and Cursor
(--agent all, the default), or this folder's with --project.
Data lives in ~/.keystub (or $KEYSTUB_HOME). The master key lives in the
macOS Keychain by default, or in $KEYSTUB_MASTER_KEY (64 hex characters) on
servers; --secrets picks explicitly.
`

// version is the release this binary was built from, set at build time
// (-ldflags "-X main.version=v0.1.0"); "dev" for a local build.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "agent":
		err = agentCmd(os.Args[2:])
	case "gateway":
		err = gatewayCmd(os.Args[2:])
	case "link":
		err = linkCmd(os.Args[2:])
	case "unlink":
		err = unlinkCmd(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	case "env":
		err = env(os.Args[2:])
	case "skill":
		err = skillCmd(os.Args[2:])
	case "version", "--version":
		fmt.Println("keystub", version)
		return
	case "help", "-h", "--help":
		if len(os.Args) > 2 && os.Args[2] == "agents" {
			fmt.Print(docs.AgentGuide)
			return
		}
		fmt.Print(usageText)
		return
	default:
		if slices.Contains(cli.Commands, os.Args[1]) {
			cliMain(os.Args[1], os.Args[2:])
			return
		}
		fmt.Fprintf(os.Stderr, "keystub: unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	var code exitCode
	if errors.As(err, &code) {
		os.Exit(int(code))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keystub:", err)
		os.Exit(1)
	}
}

func homeDir() (string, error) {
	if h := legacy.Getenv("KEYSTUB_HOME"); h != "" {
		return h, nil
	}
	d, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return legacy.Home(d), nil
}

// serveInfo tells `run` and `env` where a running `serve` listens.
type serveInfo struct {
	ProxyAddr     string `json:"proxyAddr"`
	DashboardAddr string `json:"dashboardAddr"`
	EdgeAddr      string `json:"edgeAddr"`
}

func loadOrCreateToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b)
	return t, os.WriteFile(path, []byte(t+"\n"), 0o600)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	proxyAddr := fs.String("proxy", "127.0.0.1:8787", "address for the proxy")
	dashAddr := fs.String("dashboard", "127.0.0.1:8788", "address for the dashboard")
	edgeAddr := fs.String("edge", "127.0.0.1:8789", "address for the /s and /h routes (quick start, agents)")
	requireToken := fs.Bool("require-token", false, "refuse proxy connections without a valid token (always on when the proxy isn't on loopback)")
	secretsFrom := fs.String("secrets", envOr("KEYSTUB_SECRETS", "auto"), "where the master key lives: "+strings.Join(secrets.Names(), ", "))
	clientIPHeader := fs.String("client-ip-header", "", "behind a reverse proxy, a header the proxy nearest keystub sets to the client's address alone (CF-Connecting-IP, X-Real-IP), for the cap on keystub link requests per source; X-Forwarded-For only with one proxy (its last address is the hop before keystub); only set it behind a proxy, since anyone can write it otherwise")
	storageKind := fs.String("storage", envOr("KEYSTUB_STORAGE", "json"), "where everything is stored: json (a file per kind) or sqlite (one keystub.db)")
	_ = fs.Parse(args)
	if err := proxy.CheckClientIPHeader(*clientIPHeader); err != nil {
		return err
	}
	ctx := context.Background()

	dir, err := homeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Each port gets its adapter here; nothing below this block knows which.
	st, err := openStorage(ctx, *storageKind, dir)
	if err != nil {
		return err
	}
	defer st.close()
	sealer, keySource, note, err := secrets.Open(ctx, *secretsFrom, dir)
	if err != nil {
		return err
	}
	if note != "" {
		fmt.Fprintln(os.Stderr, "keystub: warning:", note)
	}
	engine, err := core.NewEngine(ctx, st.repo, sealer, st.limiter)
	if err != nil {
		return err
	}
	authority, err := ca.LoadOrCreate(dir)
	if err != nil {
		return err
	}
	lg := st.log
	caPath, bundlePath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-bundle.pem")
	if err := runenv.WriteBundle(bundlePath, authority.CertPEM()); err != nil {
		_ = os.Remove(bundlePath) // don't leave an old one that run would trust
		fmt.Fprintln(os.Stderr, "keystub: warning: no CA bundle, so Python and curl won't trust the proxy:", err)
	}
	token, err := loadOrCreateToken(filepath.Join(dir, "admin.token"))
	if err != nil {
		return err
	}

	pl, err := net.Listen("tcp", *proxyAddr)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	dl, err := net.Listen("tcp", *dashAddr)
	if err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	el, err := net.Listen("tcp", *edgeAddr)
	if err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	info := serveInfo{ProxyAddr: pl.Addr().String(), DashboardAddr: dl.Addr().String(), EdgeAddr: el.Addr().String()}
	if !proxy.IsLoopback(info.EdgeAddr) {
		fmt.Fprintf(os.Stderr, "keystub: warning: the edge at %s speaks plain HTTP; put TLS in front of it before exposing it\n", info.EdgeAddr)
	}
	for _, a := range []string{info.ProxyAddr, info.DashboardAddr, info.EdgeAddr} {
		if !proxy.IsLoopback(a) {
			fmt.Fprintf(os.Stderr, "keystub: warning: %s is reachable from other machines\n", a)
		}
	}

	dash, err := dashboard.New(&dashboard.Server{Core: engine, Log: lg, Token: token, ProxyAddr: info.ProxyAddr, EdgeAddr: info.EdgeAddr, CAPath: caPath, BundlePath: bundlePath, SecretsIn: keySource.Name(), Notices: readNotes(dir)})
	if err != nil {
		return err
	}
	px := proxy.New(engine, authority, lg)
	px.RequireToken = *requireToken || !proxy.IsLoopback(info.ProxyAddr)
	px.BlockPrivate = !proxy.IsLoopback(info.ProxyAddr)
	proxySrv := &http.Server{Handler: px, ReadHeaderTimeout: 15 * time.Second}
	dashSrv := &http.Server{Handler: dash, ReadHeaderTimeout: 15 * time.Second}
	edge := proxy.NewEdge(engine, lg)
	edge.Link = engine // keystub link, and tokens for linked machines
	edge.ClientIPHeader = *clientIPHeader
	edgeSrv := &http.Server{Handler: edge, ReadHeaderTimeout: 15 * time.Second}

	infoPath := filepath.Join(dir, "serve.json")
	b, _ := json.Marshal(info)
	if err := os.WriteFile(infoPath, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(infoPath)

	errc := make(chan error, 3)
	go func() { errc <- proxySrv.Serve(pl) }()
	go func() { errc <- dashSrv.Serve(dl) }()
	go func() { errc <- edgeSrv.Serve(el) }()

	fmt.Printf("Keystub is running.\n  Proxy:      %s\n  Edge:       http://%s\n  Dashboard:  http://%s/login?token=%s\n  Master key: %s\n\nRun a command through it:  keystub run -- npm run dev\n", info.ProxyAddr, info.EdgeAddr, info.DashboardAddr, token, keySource.Name())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case err = <-errc:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxySrv.Shutdown(ctx)
	_ = dashSrv.Shutdown(ctx)
	_ = edgeSrv.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func envOr(name, def string) string {
	if v := legacy.Getenv(name); v != "" {
		return v
	}
	return def
}

// stores is what a storage choice provides: the model, limit counts and
// the request log.
type stores struct {
	repo    core.Repository
	limiter core.Limiter
	log     interface {
		core.Sink
		core.LogReader
	}
	close func()
}

// notesFile keeps what converting older data changed (tokens it revoked),
// so the dashboard and `keystub whoami` show it on later starts too, until
// the operator deletes the file.
const notesFile = "conversion-notes.txt"

// warnConverted says what converting older data to saved keys and links
// changed, and appends it to notesFile.
func warnConverted(dir string, notes []string) {
	if len(notes) == 0 {
		return
	}
	for _, n := range notes {
		fmt.Fprintln(os.Stderr, "keystub: warning:", n)
	}
	f, err := os.OpenFile(filepath.Join(dir, notesFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keystub: warning: couldn't keep the conversion notes:", err)
		return
	}
	defer f.Close()
	for _, n := range notes {
		fmt.Fprintln(f, n)
	}
}

// readNotes reads notesFile, one note per line.
func readNotes(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, notesFile))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// openStorage picks the adapters for one storage choice. Postgres joins here.
func openStorage(ctx context.Context, kind, dir string) (stores, error) {
	switch kind {
	case "json":
		repo, notes, err := jsonfile.OpenNotes(filepath.Join(dir, "state.json"))
		if err != nil {
			return stores{}, err
		}
		warnConverted(dir, notes)
		lg, err := reqlog.Open(filepath.Join(dir, "requests.jsonl"), 1000)
		if err != nil {
			return stores{}, err
		}
		return stores{repo: repo, limiter: limit.NewMemory(), log: lg, close: func() { lg.Close() }}, nil
	case "sqlite":
		db, err := sqlite.Open(legacy.File(dir, "keystub.db", "stubkey.db"))
		if err != nil {
			return stores{}, err
		}
		// Moving from the JSON file: bring its projects, keys and tokens along.
		jsonPath := filepath.Join(dir, "state.json")
		empty, err := db.Empty(ctx)
		if err != nil {
			db.Close()
			return stores{}, err
		}
		if empty {
			if _, err := os.Stat(jsonPath); err == nil {
				old, notes, err := jsonfile.OpenNotes(jsonPath)
				warnConverted(dir, notes)
				if err == nil {
					err = db.Import(ctx, old)
				}
				if err != nil {
					db.Close()
					return stores{}, fmt.Errorf("import %s: %w", jsonPath, err)
				}
				fmt.Fprintf(os.Stderr, "keystub: imported %s into keystub.db; the JSON file is no longer used\n", jsonPath)
			}
		}
		warnConverted(dir, db.Notes())
		return stores{repo: db, limiter: sqlite.NewLimiter(db), log: sqlite.NewEvents(db, 0), close: func() { db.Close() }}, nil
	default:
		return stores{}, fmt.Errorf("unknown storage %q (choose json or sqlite)", kind)
	}
}
