package cli

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// keystub sandbox: a throwaway Docker container that holds this code and
// nothing else of the machine's, set up the way an agent's box is: a
// short-lived token for the environment (made here, never printed), then
// keystub setup inside, so the code runs with stand-ins and short-lived
// credentials only. An agent then installs, runs and tests the app in it
// (keystub sandbox exec), through the ports it publishes, and stop revokes
// the token and removes the container.
//
// The code is copied in, not mounted, without .git, dependency folders, or
// any .env file but an example: the real keys in this folder never enter
// the sandbox.

const sandboxUsage = `sandbox start [PROJECT/ENV] [--name NAME] [--dir DIR] [--image IMAGE] [--port PORT]... [--ttl 2h] [--no-tools]
       sandbox exec NAME -- COMMAND [ARGS...]
       sandbox list
       sandbox stop NAME`

const (
	sandboxImage = "node:22-bookworm"
	sandboxDir   = "/workspace"
	// refreshAfter is when exec runs keystub setup again: short-lived
	// credentials last an hour.
	refreshAfter = 40 * time.Minute
)

// Version is this binary's release ("dev" for a local build), so a sandbox
// can install the same one.
var Version = "dev"

// runDocker runs docker with the given streams.
func (c *ctx) runDocker(stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	return c.Exec(stdin, stdout, stderr, nil, "docker", args...)
}

func (c *ctx) docker(args ...string) (string, error) {
	var out, errb bytes.Buffer
	err := c.runDocker(nil, &out, &errb, args...)
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), errors.New(lastLine(msg))
	}
	return out.String(), nil
}

// sandboxState is what's kept for a sandbox, under ~/.keystub/sandboxes.
// No secret: the token lives only in the container.
type sandboxState struct {
	Name      string            `json:"name"`
	Container string            `json:"container"`
	Env       string            `json:"env"`
	Dir       string            `json:"dir"`
	Image     string            `json:"image"`
	TokenID   string            `json:"tokenId"`
	ExpiresAt *time.Time        `json:"expiresAt,omitempty"`
	Ports     map[string]string `json:"ports,omitempty"` // container port → host address
	SetupAt   time.Time         `json:"setupAt"`
	Status    string            `json:"status,omitempty"` // list: docker's state
}

var sandboxName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

func (c *ctx) sandbox(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub %s", sandboxUsage)
	}
	switch args[0] {
	case "start":
		return c.sandboxStart(args[1:])
	case "exec":
		return c.sandboxExec(args[1:])
	case "list", "ls":
		return c.sandboxList()
	case "stop", "rm":
		return c.sandboxStop(args[1:])
	}
	return usageErr("usage: keystub %s", sandboxUsage)
}

func (c *ctx) sandboxPath(name string) string {
	return filepath.Join(c.Home, "sandboxes", name+".json")
}

func (c *ctx) loadSandbox(name string) (sandboxState, error) {
	var st sandboxState
	b, err := os.ReadFile(c.sandboxPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return st, &Error{Code: ExitNotFound, Message: fmt.Sprintf("no sandbox %q here (keystub sandbox list)", name)}
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func (c *ctx) saveSandbox(st sandboxState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return writePrivate(c.sandboxPath(st.Name), string(b)+"\n")
}

func (c *ctx) sandboxStart(args []string) error {
	p, err := parse(args, []string{"name", "dir", "image", "port", "ttl", "keystub", "copy-env", "env-file"}, []string{"no-tools"})
	if err != nil {
		return err
	}
	if err := p.want(0, 1, "sandbox start [PROJECT/ENV] [--name NAME] [--port PORT]..."); err != nil {
		return err
	}
	dir := p.flags["dir"]
	if dir == "" {
		dir = "."
	}
	dir, _ = filepath.Abs(dir)
	env := readProjectFile(dir)
	if env == "" {
		env = defaultEnv(filepath.Join(dir, ".env"))
	}
	if len(p.args) == 1 {
		env = p.args[0]
	}
	path, err := envPath(env)
	if err != nil {
		return err
	}
	name := p.flags["name"]
	if name == "" {
		name = slugUnsafe.ReplaceAllString(strings.ToLower(filepath.Base(dir)), "-") + "-" + randomSuffix()[:4]
		name = strings.Trim(name, "-")
	}
	if !sandboxName.MatchString(name) {
		return usageErr("a sandbox name is lower case letters, digits and -, up to 41")
	}
	if _, err := os.Stat(c.sandboxPath(name)); err == nil {
		return &Error{Code: ExitConflict, Message: fmt.Sprintf("there's a sandbox %q already: keystub sandbox stop %s, or pick another --name", name, name)}
	}
	image := p.flags["image"]
	if image == "" {
		image = sandboxImage
	}
	ttl := p.flags["ttl"]
	if ttl == "" {
		ttl = "2h"
	}
	var ports []string
	for _, v := range p.all["port"] {
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				if n, err := strconv.Atoi(x); err != nil || n < 1 || n > 65535 {
					return usageErr("--port takes a port number, like 3000")
				}
				ports = append(ports, x)
			}
		}
	}
	copyNames := map[string]bool{}
	for _, v := range p.all["copy-env"] {
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				copyNames[n] = true
			}
		}
	}
	localFile := p.flags["env-file"]
	if localFile == "" {
		localFile = filepath.Join(dir, ".env")
	}
	localNames, localValues, localErr := dotenvNames(localFile)
	if len(copyNames) > 0 {
		if localErr != nil {
			return &Error{Code: ExitNotFound, Message: fmt.Sprintf("--copy-env reads %s, which can't be read: %v", localFile, localErr)}
		}
		for n := range copyNames {
			if _, ok := localValues[n]; !ok {
				return &Error{Code: ExitNotFound, Message: fmt.Sprintf("--copy-env %s: %s doesn't set it", n, localFile)}
			}
		}
	}
	binary := p.flags["keystub"]
	if binary == "" && strings.HasPrefix(hostOS, "linux/") {
		binary, _ = os.Executable()
	}
	if _, err := c.docker("info", "--format", "{{.ServerVersion}}"); err != nil {
		return &Error{Code: ExitError, Message: "Docker isn't running here (" + err.Error() + "): start Docker Desktop, or install Docker"}
	}

	// The token: made for this sandbox, with a delivery key, and expiring.
	made, err := c.makeAccess(path, map[string]any{"name": "sandbox-" + name, "ttl": ttl})
	if err != nil {
		return err
	}
	st := sandboxState{Name: name, Container: "keystub-" + name, Env: env, Dir: dir, Image: image, TokenID: made.ID, ExpiresAt: made.ExpiresAt}
	revoke := func() { _ = c.call("POST", "/api/tokens/"+url.PathEscape(made.ID)+"/revoke", nil, nil) }

	// The access goes in through a file only this user can read, removed
	// as soon as the container has it.
	envFile := filepath.Join(c.Home, "sandboxes", "."+name+".env")
	if err := writePrivate(envFile, "KEYSTUB_TOKEN="+made.Secret+"\nKEYSTUB_DELIVERY_KEY="+made.deliveryKey+"\nKEYSTUB_EDGE="+made.edge+"\n"); err != nil {
		revoke()
		return err
	}
	run := []string{"run", "-d", "--name", st.Container, "--label", "keystub.sandbox=" + name, "--env-file", envFile, "-w", sandboxDir}
	for _, port := range ports {
		run = append(run, "-p", "127.0.0.1::"+port)
	}
	run = append(run, image, "sleep", "infinity")
	_, err = c.docker(run...)
	os.Remove(envFile)
	if err != nil {
		revoke()
		return &Error{Code: ExitError, Message: "couldn't start the container: " + err.Error()}
	}
	fail := func(step string, err error) error {
		_, _ = c.docker("rm", "-f", st.Container)
		revoke()
		_ = os.Remove(c.sandboxPath(name))
		return &Error{Code: ExitError, Message: step + ": " + err.Error() + " (the sandbox was removed and its token revoked)"}
	}
	if err := c.copyCode(dir, st.Container); err != nil {
		return fail("couldn't copy the code in", err)
	}
	if err := c.installKeystub(st.Container, binary); err != nil {
		return fail("couldn't install keystub in the sandbox", err)
	}
	var warnings []string
	if binary == "" && (Version == "dev" || Version == "") {
		warnings = append(warnings, "this is a dev build, so the sandbox has keystub's latest release, which may lack commands this one has: pass --keystub with a Linux build of this one")
	}
	if err := c.saveSandbox(st); err != nil {
		return fail("couldn't keep the sandbox's state", err)
	}

	res := map[string]any{"name": name, "container": st.Container, "env": env, "image": image, "token": map[string]any{"id": made.ID, "expiresAt": made.ExpiresAt}, "dir": sandboxDir}
	var setup map[string]any
	out, err := c.inSandbox(st.Container, "keystub setup --json")
	if err != nil {
		res["setupError"] = lastLine(out)
	} else {
		_ = json.Unmarshal([]byte(lastJSON(out)), &setup)
		res["setup"] = map[string]any{"set": setup["set"], "failed": setup["failed"], "skipped": setup["skipped"], "clis": setup["clis"]}
		st.SetupAt = time.Now()
	}
	// What the folder's env file sets that Keystub doesn't give the
	// sandbox: config to copy in (--copy-env, asked first), or a secret
	// to add to Keystub.
	if localErr == nil {
		names, values := localNames, localValues
		given := map[string]bool{}
		for _, key := range []string{"set", "skipped"} {
			list, _ := setup[key].([]any)
			for _, it := range list {
				m, _ := it.(map[string]any)
				for _, f := range []string{"name", "var"} {
					if n, ok := m[f].(string); ok {
						given[n] = true
					}
				}
			}
		}
		var copied, missing []string
		var lines strings.Builder
		for _, n := range names {
			switch {
			case given[n]:
				if copyNames[n] {
					return fail("--copy-env "+n, errors.New("Keystub gives the sandbox this one; copying it would put the real value in"))
				}
			case copyNames[n]:
				copied = append(copied, n)
				lines.WriteString(n + "=" + dotenvQuote(values[n]) + "\n")
			default:
				missing = append(missing, n)
			}
		}
		var secretish, config []string
		for _, n := range missing {
			if looksSecret(n, values[n]) {
				secretish = append(secretish, n)
			} else {
				config = append(config, n)
			}
		}
		if lines.Len() > 0 {
			var errb bytes.Buffer
			if err := c.runDocker(strings.NewReader(lines.String()), io.Discard, &errb, "exec", "-i", st.Container, "sh", "-c", "cat >> "+sandboxDir+"/.env"); err != nil {
				return fail("couldn't copy the variables in", errors.New(firstNonEmpty(errb.String(), err.Error())))
			}
			res["copied"] = copied
		}
		if len(missing) > 0 {
			res["notInSandbox"] = map[string][]string{"secrets": secretish, "config": config}
		}
	}
	if !p.has("no-tools") {
		var tools map[string]any
		if out, err := c.inSandbox(st.Container, "keystub tools install --json"); err == nil || out != "" {
			if json.Unmarshal([]byte(lastJSON(out)), &tools) == nil {
				res["tools"] = tools["tools"]
			}
		}
		// gcloud installed after setup needs setup again to be pointed at
		// the token file.
		if ts, ok := res["tools"].([]any); ok {
			for _, t := range ts {
				if m, _ := t.(map[string]any); m["name"] == "gcloud" && strings.HasPrefix(fmt.Sprint(m["done"]), "installed") {
					_, _ = c.inSandbox(st.Container, "keystub setup --json")
				}
			}
		}
	}
	if len(ports) > 0 {
		st.Ports = map[string]string{}
		for _, port := range ports {
			if out, err := c.docker("port", st.Container, port+"/tcp"); err == nil {
				st.Ports[port] = "http://" + strings.TrimSpace(strings.Split(out, "\n")[0])
			}
		}
		res["ports"] = st.Ports
	}
	_ = c.saveSandbox(st)
	if len(warnings) > 0 {
		res["warnings"] = warnings
	}
	next := []string{}
	if m, ok := res["notInSandbox"].(map[string][]string); ok {
		if len(m["secrets"]) > 0 {
			next = append(next, "ask the user to add "+strings.Join(m["secrets"], ", ")+" to "+env+" in Keystub (they look like secrets "+filepath.Base(localFile)+" sets and Keystub doesn't give), if the app needs them")
		}
		if len(m["config"]) > 0 {
			next = append(next, "ask the user whether to copy "+strings.Join(m["config"], ", ")+" in (config "+filepath.Base(localFile)+" sets): start again with --copy-env NAME,...")
		}
	}
	next = append(next,
		"keystub sandbox exec "+name+" -- <install command, e.g. npm ci>",
		"keystub sandbox exec "+name+" -- keystub verify",
	)
	if len(ports) > 0 {
		next = append(next, "start the app in the background, listening on 0.0.0.0, then call it at the ports' host addresses")
	}
	next = append(next, "keystub sandbox stop "+name+"   (revokes the token, removes the container)")
	res["next"] = next
	return c.emit(res, func(w io.Writer) {
		fmt.Fprintf(w, "Sandbox %s is up (%s, %s), with a token for %s that expires %s.\n", name, st.Container, image, env, made.ExpiresAt.Local().Format("15:04"))
		if e, ok := res["setupError"]; ok {
			fmt.Fprintf(w, "keystub setup failed inside: %v\n", e)
		}
		for p, a := range st.Ports {
			fmt.Fprintf(w, "  port %s → %s\n", p, a)
		}
		for _, n := range next {
			fmt.Fprintln(w, "Next:", n)
		}
	})
}

// lastJSON is the JSON value at the end of out: from the last line that
// starts one at its first column (other output may come before it).
func lastJSON(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "{") {
			return strings.Join(lines[i:], "\n")
		}
	}
	return out
}

// sandboxShell runs a command in the sandbox's folder with ~/.local/bin on
// the PATH and keystub setup's variables exported.
const sandboxShell = `export PATH="$HOME/.local/bin:$PATH"; [ -f "$HOME/.keystub/env.sh" ] && . "$HOME/.keystub/env.sh"; `

// inSandbox runs a shell line in the container and returns its output.
func (c *ctx) inSandbox(container, line string) (string, error) {
	var out bytes.Buffer
	err := c.runDocker(nil, &out, &out, "exec", "-w", sandboxDir, container, "bash", "-c", sandboxShell+line)
	return out.String(), err
}

// installKeystub puts keystub in the container: the given Linux binary, or
// this release from the installer (which checks it against the release's
// checksums).
func (c *ctx) installKeystub(container, binary string) error {
	if binary != "" {
		if _, err := c.docker("cp", binary, container+":/usr/local/bin/keystub"); err != nil {
			return err
		}
		_, err := c.docker("exec", container, "chmod", "755", "/usr/local/bin/keystub")
		return err
	}
	ver := ""
	if Version != "dev" && Version != "" {
		ver = "KEYSTUB_VERSION=" + Version + " "
	}
	out, err := c.inSandbox(container, "curl -fsSL https://raw.githubusercontent.com/vivekverma239/keystub/main/install.sh | "+ver+"KEYSTUB_INSTALL_DIR=/usr/local/bin KEYSTUB_SKILL=no sh")
	if err != nil {
		return errors.New(lastLine(out))
	}
	return nil
}

// sandboxSkipDirs are left out of the copy: history, dependencies and
// build output, which the sandbox makes for itself.
var sandboxSkipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, ".next": true, ".turbo": true, ".wrangler": true, ".convex": true, ".keystub": true, "target": true, ".gradle": true, ".terraform": true}

// secretFile is a file that may hold real keys: any .env file but an
// example, and wrangler's .dev.vars.
func secretFile(name string) bool {
	if name == ".dev.vars" || strings.HasPrefix(name, ".dev.vars.") {
		return true
	}
	if !strings.HasPrefix(name, ".env") {
		return false
	}
	for _, ok := range []string{"example", "sample", "template", "dist"} {
		if strings.HasSuffix(name, "."+ok) {
			return false
		}
	}
	return true
}

// copyCode copies the folder into the container's /workspace as a tar
// stream, leaving out sandboxSkipDirs, secret files and files over 50 MB.
func (c *ctx) copyCode(dir, container string) error {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if rel == "." {
				return nil
			}
			if d.IsDir() {
				if sandboxSkipDirs[d.Name()] {
					return filepath.SkipDir
				}
			} else if secretFile(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			link := ""
			if info.Mode()&fs.ModeSymlink != 0 {
				link, _ = os.Readlink(path)
			} else if !info.Mode().IsRegular() && !info.IsDir() {
				return nil
			}
			if info.Mode().IsRegular() && info.Size() > 50<<20 {
				return nil
			}
			h, err := tar.FileInfoHeader(info, link)
			if err != nil {
				return nil
			}
			h.Name = filepath.ToSlash(rel)
			h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				_, err = io.Copy(tw, f)
				f.Close()
				return err
			}
			return nil
		})
		if err == nil {
			err = tw.Close()
		}
		pw.CloseWithError(err)
	}()
	var errb bytes.Buffer
	if err := c.runDocker(pr, io.Discard, &errb, "exec", "-i", container, "tar", "-x", "-C", sandboxDir, "--no-same-owner"); err != nil {
		pr.CloseWithError(err)
		return errors.New(firstNonEmpty(lastLine(errb.String()), err.Error()))
	}
	return nil
}

func (c *ctx) sandboxExec(args []string) error {
	if len(args) == 0 {
		return usageErr("usage: keystub sandbox exec NAME -- COMMAND [ARGS...]")
	}
	name, rest := args[0], args[1:]
	direct := false
	for len(rest) > 0 && rest[0] != "--" {
		if rest[0] != "--direct" {
			return usageErr("usage: keystub sandbox exec NAME [--direct] -- COMMAND [ARGS...]")
		}
		direct = true
		rest = rest[1:]
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return usageErr("usage: keystub sandbox exec NAME [--direct] -- COMMAND [ARGS...]")
	}
	st, err := c.loadSandbox(name)
	if err != nil {
		return err
	}
	// Short-lived credentials last an hour: refresh them first when due.
	if time.Since(st.SetupAt) > refreshAfter {
		if _, err := c.inSandbox(st.Container, "keystub setup --json"); err == nil {
			st.SetupAt = time.Now()
			_ = c.saveSandbox(st)
		}
	}
	a := []string{"exec", "-i"}
	if c.StdinTerminal && isTTY(c.Stdout) {
		a = append(a, "-t")
	}
	// Through Keystub's proxy by default, so services with no base URL
	// (a stand-in in a header the SDK sends to its own host) work too;
	// other traffic passes through it untouched.
	run := `exec keystub run --remote "$KEYSTUB_EDGE" -- "$@"`
	if direct {
		run = `exec "$@"`
	}
	a = append(a, "-w", sandboxDir, st.Container, "bash", "-c", sandboxShell+run, "bash")
	a = append(a, rest...)
	err = c.runDocker(c.Stdin, c.Stdout, c.Stderr, a...)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &Error{Code: ee.ExitCode(), Message: fmt.Sprintf("the command exited with %d", ee.ExitCode())}
	}
	return err
}

func (c *ctx) sandboxList() error {
	files, _ := filepath.Glob(filepath.Join(c.Home, "sandboxes", "*.json"))
	sort.Strings(files)
	out := []sandboxState{}
	for _, f := range files {
		st, err := c.loadSandbox(strings.TrimSuffix(filepath.Base(f), ".json"))
		if err != nil {
			continue
		}
		s, err := c.docker("inspect", "-f", "{{.State.Status}}", st.Container)
		st.Status = strings.TrimSpace(s)
		if err != nil {
			st.Status = "gone"
		}
		out = append(out, st)
	}
	return c.emit(map[string]any{"sandboxes": out}, func(w io.Writer) {
		if len(out) == 0 {
			fmt.Fprintln(w, "No sandboxes.")
		}
		for _, s := range out {
			fmt.Fprintf(w, "%-24s %-8s %s  %s\n", s.Name, s.Status, s.Env, s.Dir)
		}
	})
}

func (c *ctx) sandboxStop(args []string) error {
	if len(args) != 1 {
		return usageErr("usage: keystub sandbox stop NAME")
	}
	st, err := c.loadSandbox(args[0])
	if err != nil {
		return err
	}
	res := map[string]any{"name": st.Name}
	if err := c.call("POST", "/api/tokens/"+url.PathEscape(st.TokenID)+"/revoke", nil, nil); err != nil {
		var ce *Error
		if !errors.As(err, &ce) || ce.Code != ExitNotFound {
			return fmt.Errorf("couldn't revoke the sandbox's token %s (%v); the sandbox is left as it is", st.TokenID, err)
		}
	}
	res["revoked"] = st.TokenID
	if _, err := c.docker("rm", "-f", st.Container); err != nil && !strings.Contains(err.Error(), "No such container") {
		return fmt.Errorf("revoked the token, but couldn't remove %s: %v", st.Container, err)
	}
	res["removed"] = st.Container
	_ = os.Remove(c.sandboxPath(st.Name))
	return c.emit(res, func(w io.Writer) {
		fmt.Fprintf(w, "Stopped %s: token %s revoked, container removed.\n", st.Name, st.TokenID)
	})
}

// isTTY is whether w is a terminal.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
