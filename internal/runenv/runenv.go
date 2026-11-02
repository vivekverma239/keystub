// Package runenv builds the environment `keystub run` starts a command
// with: the proxy, the CA, and a placeholder for every service's key.
package runenv

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/vivekverma239/keystub/internal/core"
)

// Config is what the environment is built from.
type Config struct {
	ProxyAddr  string   // e.g. 127.0.0.1:8787
	Token      string   // the proxy token
	KeyName    string   // the token's name
	EnvID      string   // the token's environment, e.g. "my-app/dev"
	CAPath     string   // our CA alone, for runtimes that add to their roots
	BundlePath string   // system roots plus our CA, for runtimes that replace them; "" if missing
	EnvVars    []string // "OPENAI_API_KEY", or "NAME=template" with {key} for keys with a shape
	// Direct is quick start: no proxy and no CA, only SDK base URLs that
	// point at the edge, plus the keys.
	Direct   bool
	EdgeURL  string   // e.g. http://127.0.0.1:8789
	BaseURLs []string // "OPENAI_BASE_URL=/s/openai/v1", joined onto EdgeURL
}

// noProxy is always kept off the proxy, so local dev servers work as usual.
var noProxy = []string{"localhost", "127.0.0.1", "::1", ".localhost"}

// Vars returns the variables to set, sorted by name.
func Vars(c Config, current func(string) string) map[string]string {
	if c.Direct {
		v := map[string]string{"KEYSTUB_KEY": c.KeyName, "KEYSTUB_ENV": c.EnvID}
		for _, b := range c.BaseURLs {
			name, path, _ := strings.Cut(b, "=")
			v[name] = strings.TrimSuffix(c.EdgeURL, "/") + path
		}
		addKeys(v, c)
		return v
	}

	pu := url.URL{Scheme: "http", User: url.UserPassword("keystub", c.Token), Host: c.ProxyAddr}
	proxy := pu.String()

	var np []string
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if cur := current(k); cur != "" {
			np = append(np, strings.Split(cur, ",")...)
		}
	}
	npv := strings.Join(dedupe(append(np, noProxy...)), ",")

	v := map[string]string{
		"HTTPS_PROXY": proxy,
		"https_proxy": proxy,
		"NO_PROXY":    npv,
		"no_proxy":    npv,
		// Node adds this CA to its built-in roots; Node 24+ honours HTTPS_PROXY with this flag.
		"NODE_EXTRA_CA_CERTS": c.CAPath,
		"NODE_USE_ENV_PROXY":  "1",
		"KEYSTUB_KEY":         c.KeyName,
		"KEYSTUB_ENV":         c.EnvID,
	}
	// OpenSSL, Python (httpx, requests) and curl replace their roots with
	// this bundle. Pointing them at a missing file would break every TLS
	// call, so leave them alone without one.
	if c.BundlePath != "" {
		v["SSL_CERT_FILE"] = c.BundlePath
		v["REQUESTS_CA_BUNDLE"] = c.BundlePath
		v["CURL_CA_BUNDLE"] = c.BundlePath
	}
	addKeys(v, c)
	return v
}

// addKeys sets each service's key variable to the proxy token, filling
// templates for keys with a shape.
func addKeys(v map[string]string, c Config) {
	for _, e := range c.EnvVars {
		if name, tmpl, ok := strings.Cut(e, "="); ok {
			tmpl = strings.ReplaceAll(tmpl, "{key_compact}", core.Compact(c.Token))
			v[name] = strings.ReplaceAll(tmpl, "{key}", c.Token)
		} else {
			v[e] = c.Token
		}
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Environ merges vars into the current environment for exec.
func Environ(vars map[string]string) []string {
	out := make([]string, 0, len(os.Environ())+len(vars))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := vars[k]; !ok {
			out = append(out, kv)
		}
	}
	for _, k := range sortedKeys(vars) {
		out = append(out, k+"="+vars[k])
	}
	return out
}

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Exports renders vars as shell `export` lines, for `eval "$(keystub env)"`.
// A key that isn't a variable name is left out.
func Exports(vars map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(vars) {
		if !varName.MatchString(k) {
			continue // never a shell command for eval to run
		}
		b.WriteString("export " + k + "=" + shellQuote(vars[k]) + "\n")
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// DefaultKeyName is the git worktree's folder name, or the current folder's.
// Each worktree then gets its own proxy token.
func DefaultKeyName() string {
	if out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err == nil {
		if top := strings.TrimSpace(string(out)); top != "" {
			return filepath.Base(top)
		}
	}
	wd, _ := os.Getwd()
	return filepath.Base(wd)
}

// systemRootFiles are where Linux distributions and macOS keep a PEM bundle.
var systemRootFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/cert.pem",                  // macOS, BSDs
}

func systemRoots() ([]byte, error) {
	for _, p := range systemRootFiles {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	if runtime.GOOS == "darwin" {
		return exec.Command("security", "find-certificate", "-a", "-p",
			"/System/Library/Keychains/SystemRootCertificates.keychain").Output()
	}
	return nil, errors.New("couldn't find the system's root certificates")
}

// WriteBundle writes system roots plus caPEM to path. Hosts that aren't
// intercepted pass through with their real certificates, so tools that
// replace their roots still need the system ones.
func WriteBundle(path string, caPEM []byte) error {
	roots, err := systemRoots()
	if err != nil {
		return err
	}
	b := append(append(append([]byte{}, roots...), '\n'), caPEM...)
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, b) {
		return nil
	}
	// Written under a temporary name and renamed into place, so a command
	// started by another `keystub run` never reads half a bundle.
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o644)
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
