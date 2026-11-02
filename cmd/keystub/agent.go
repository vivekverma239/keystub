package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/vivekverma239/keystub/internal/legacy"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vivekverma239/keystub/internal/agent"
	"github.com/vivekverma239/keystub/internal/proxy"
)

// agentInfo tells `run` and `env` where a running `keystub agent` listens
// and which edge it forwards to.
type agentInfo struct {
	ProxyAddr  string `json:"proxyAddr"`
	Remote     string `json:"remote"`
	CAPath     string `json:"caPath"`
	BundlePath string `json:"bundlePath,omitempty"`
	PID        int    `json:"pid"` // so a crashed agent's leftover file is noticed
	// Services are the IDs the agent decrypts, kept up to date as its
	// catalog refreshes.
	Services []string `json:"services"`
}

func serviceIDs(c proxy.CatalogResponse) []string {
	ids := []string{}
	for _, s := range c.Services {
		ids = append(ids, s.ID)
	}
	return ids
}

// writeAtomic replaces path whole, so a reader never sees half a file.
func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// hostList is a repeatable --allow-host.
type hostList []string

func (h *hostList) String() string     { return strings.Join(*h, ",") }
func (h *hostList) Set(v string) error { *h = append(*h, v); return nil }

// envHosts is $KEYSTUB_ALLOW_HOSTS, comma-separated.
func envHosts() []string {
	var out []string
	for _, h := range strings.Split(legacy.Getenv("KEYSTUB_ALLOW_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// agentCmd runs only the local proxy, forwarding to a remote edge. The box
// holds a CA and a proxy token, never a real key.
func agentCmd(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	remote := fs.String("remote", legacy.Getenv("KEYSTUB_REMOTE"), "the edge to forward to, e.g. https://keystub.example.com (default: $KEYSTUB_REMOTE)")
	token := fs.String("token", "", "a proxy token, to ask the edge which services to decrypt; prefer $KEYSTUB_TOKEN, since a flag shows in ps")
	listen := fs.String("proxy", "127.0.0.1:8787", "loopback address for the proxy")
	var allow hostList
	fs.Var(&allow, "allow-host", "also decrypt this host when the edge names it: HOST for a custom service (api.internal.example), SERVICE=HOST for a built-in service's own server (gitlab=gitlab.corp.example); repeatable (also: $KEYSTUB_ALLOW_HOSTS, comma-separated)")
	envID := fs.String("env", "", "on a linked machine: the environment of the agent's own token (default: the machine's first)")
	_ = fs.Parse(args)
	if *token == "" {
		*token = legacy.Getenv("KEYSTUB_TOKEN") // not the flag's default, which -h would print
	}
	dir, err := homeDir()
	if err != nil {
		return err
	}
	// On a linked machine the server and the agent's token come from the
	// link: a token called "<machine>/agent", used to read the catalog.
	var renew func(context.Context) (string, error)
	if *token == "" {
		mi, cred, err := linkedMachine(dir)
		if err != nil {
			return err
		}
		if mi != nil {
			if *remote == "" {
				*remote = mi.Server
			}
			if sameServer(*remote, mi.Server) {
				renew = func(ctx context.Context) (string, error) { return machineToken(ctx, mi, cred, *envID, "agent") }
				if *token, err = renew(context.Background()); err != nil {
					return err
				}
			}
		}
	}
	if *remote == "" {
		return errors.New("usage: keystub agent --remote URL [--token TOKEN] [--proxy 127.0.0.1:8787], or keystub link SERVER_URL first")
	}
	u, err := parseRemote(*remote)
	if err != nil {
		return err
	}
	infoPath := filepath.Join(dir, "agent.json")
	var mu sync.Mutex
	var info agentInfo
	write := func(c proxy.CatalogResponse) error {
		mu.Lock()
		defer mu.Unlock()
		info.Services = serviceIDs(c)
		b, _ := json.Marshal(info)
		return writeAtomic(infoPath, b)
	}
	a, err := agent.Start(context.Background(), agent.Config{
		Home: dir, Remote: u, Token: *token, RefreshToken: renew, Listen: *listen, AllowHosts: append(allow, envHosts()...),
		OnRefresh: func(c proxy.CatalogResponse) {
			if err := write(c); err != nil {
				fmt.Fprintln(os.Stderr, "keystub: warning:", err)
			}
		},
	})
	if err != nil {
		return err
	}
	defer a.Close()
	mu.Lock()
	info = agentInfo{ProxyAddr: a.Addr, Remote: u.String(), CAPath: a.CAPath, BundlePath: a.BundlePath, PID: os.Getpid()}
	mu.Unlock()
	if err := write(a.Catalog); err != nil {
		return err
	}
	defer os.Remove(infoPath)
	warnIgnored(a.Ignored, "pass --allow-host HOST (a custom service) or SERVICE=HOST (a built-in one's own server), or set $KEYSTUB_ALLOW_HOSTS")
	warnDropped(a.Catalog)

	names := make([]string, 0, len(a.Catalog.Services))
	for _, s := range a.Catalog.Services {
		names = append(names, s.Name)
	}
	fmt.Printf("Keystub agent is running, with no keys on this box.\n  Proxy:    %s\n  Edge:     %s\n  Services: %s\n\nRun a command through it:  keystub run --token sk-stub-… -- npm run dev\n",
		a.Addr, u, strings.Join(names, ", "))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, stopSignals()...) // SIGHUP: its terminal closed, unless under nohup
	<-sig
	return nil
}
