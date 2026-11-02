package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vivekverma239/keystub/skills"
)

const skillUsage = "usage: keystub skill install [--agent claude|codex|cursor|agents|all] [--project] [--dir DIR] [--json]"

// skillFolders is where each agent reads skills from: a folder under the
// home directory, and one under the project. "agents" is the shared
// .agents/skills that Codex and Cursor both read.
var skillFolders = map[string]struct{ user, project string }{
	"claude": {".claude/skills", ".claude/skills"},
	"codex":  {".agents/skills", ".agents/skills"},
	"cursor": {".cursor/skills", ".agents/skills"},
	"agents": {".agents/skills", ".agents/skills"},
}

// skillOpts are `keystub skill install`'s flags.
type skillOpts struct {
	agents  string
	project bool
	dir     string
	json    bool
}

func (o *skillOpts) flags(fs *flag.FlagSet) {
	fs.StringVar(&o.agents, "agent", "all", "claude, codex, cursor, agents (the shared .agents/skills), or all: Claude Code's folder and .agents/skills; a comma-separated list for several")
	fs.BoolVar(&o.project, "project", false, "install into this folder's .claude/skills or .agents/skills instead of your home directory's")
	fs.StringVar(&o.dir, "dir", "", "install into DIR/keystub instead of an agent's folder")
	fs.BoolVar(&o.json, "json", false, "print the folders written as JSON")
}

// parseSkill reads `keystub skill …`'s arguments.
func parseSkill(args []string, stderr io.Writer) (skillOpts, error) {
	var o skillOpts
	if len(args) == 0 || args[0] != "install" {
		fmt.Fprintln(stderr, skillUsage)
		return o, exitCode(2)
	}
	fs := flag.NewFlagSet("skill install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o.flags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return o, exitCode(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, skillUsage)
		return o, exitCode(2)
	}
	return o, nil
}

func skillCmd(args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	return skillMain(args, home, cwd, os.Stdout, os.Stderr)
}

func skillMain(args []string, home, cwd string, stdout, stderr io.Writer) error {
	o, err := parseSkill(args, stderr)
	if err != nil {
		return err
	}
	parents, err := skillTargets(o, home, cwd)
	if err != nil {
		fmt.Fprintln(stderr, "keystub:", err)
		return exitCode(2)
	}
	var wrote []string
	for _, p := range parents {
		dir, err := installSkill(skills.Keystub, p)
		if err != nil {
			return err
		}
		wrote = append(wrote, dir)
	}
	if o.json {
		return json.NewEncoder(stdout).Encode(map[string]any{"installed": wrote})
	}
	for _, d := range wrote {
		fmt.Fprintf(stdout, "Installed the Keystub skill in %s\n", d)
	}
	fmt.Fprintln(stdout, "Start a new agent session to load it.")
	return nil
}

// skillTargets lists the folders to install the skill into, each the
// parent of a keystub/ folder.
func skillTargets(o skillOpts, home, cwd string) ([]string, error) {
	if o.dir != "" {
		return []string{o.dir}, nil
	}
	var names []string
	for _, a := range strings.Split(o.agents, ",") {
		switch a = strings.TrimSpace(a); a {
		case "all":
			names = append(names, "claude", "agents")
		case "":
		default:
			if _, ok := skillFolders[a]; !ok {
				return nil, fmt.Errorf("--agent %s: pick claude, codex, cursor, agents or all", a)
			}
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("--agent names no agent")
	}
	var out []string
	for _, n := range names {
		f := skillFolders[n]
		p := filepath.Join(home, filepath.FromSlash(f.user))
		if o.project {
			p = filepath.Join(cwd, filepath.FromSlash(f.project))
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// installSkill writes the skill into parent/keystub, replacing an earlier
// copy of it as a whole. It refuses a keystub folder that isn't the
// Keystub skill.
func installSkill(src fs.FS, parent string) (string, error) {
	final := filepath.Join(parent, skills.Name)
	_, err := os.Lstat(final)
	exists := err == nil
	if exists {
		b, err := os.ReadFile(filepath.Join(final, "SKILL.md"))
		if name, _, merr := skills.Meta(b); err != nil || merr != nil || name != skills.Name {
			return "", fmt.Errorf("%s exists and isn't the Keystub skill; move it away first", final)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(parent, ".keystub-skill-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp) // gone once renamed; a leftover after a failure
	err = fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		dst := filepath.Join(tmp, filepath.FromSlash(p))
		if d.IsDir() {
			return os.Mkdir(dst, 0o755)
		}
		b, err := fs.ReadFile(src, p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err == nil {
		err = os.Chmod(tmp, 0o755) // MkdirTemp makes it 0700
	}
	if err != nil {
		return "", err
	}
	if !exists {
		return final, os.Rename(tmp, final)
	}
	// Move the old copy aside, put the new one in its place, then drop the
	// old one; if the swap fails, the old one goes back.
	old := tmp + "-old"
	if err := os.Rename(final, old); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Rename(old, final)
		return "", err
	}
	return final, os.RemoveAll(old)
}
