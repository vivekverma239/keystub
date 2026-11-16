// Package skills holds the Agent Skill that teaches coding agents to use
// Keystub: skills/keystub, a SKILL.md folder that Claude Code, Codex,
// Cursor and other agents read. It is embedded so `keystub skill install`
// can write it out.
package skills

import (
	"bytes"
	"embed"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed keystub
var files embed.FS

// Name is the skill's name, its folder's name and its frontmatter name.
const Name = "keystub"

// Keystub is the skill's folder: SKILL.md, references/ and agents/.
var Keystub = must(fs.Sub(files, Name))

func must(f fs.FS, err error) fs.FS {
	if err != nil {
		panic(err)
	}
	return f
}

// Meta reads the name and description from a SKILL.md's frontmatter: the
// "key: value" lines between the first two "---" lines.
func Meta(skillMD []byte) (name, description string, err error) {
	lines := strings.Split(strings.ReplaceAll(string(skillMD), "\r\n", "\n"), "\n")
	if len(lines) == 0 || lines[0] != "---" {
		return "", "", errors.New("SKILL.md doesn't start with a --- frontmatter line")
	}
	for _, l := range lines[1:] {
		if l == "---" {
			return name, description, nil
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "name":
			name = strings.TrimSpace(v)
		case "description":
			description = strings.TrimSpace(v)
		}
	}
	return "", "", errors.New("SKILL.md's frontmatter has no closing --- line")
}

// Copy is an installed copy of the skill.
type Copy struct {
	Path    string `json:"path"`
	Current bool   `json:"current"` // the same files as this binary's skill; false: older or newer
}

// Places lists the folders an installed skill may be in: under the home
// directory for every project, and under cwd for this one. Each is the
// parent of a keystub/ folder.
func Places(home, cwd string) []string {
	var out []string
	if home != "" {
		for _, p := range []string{".claude/skills", ".agents/skills", ".cursor/skills"} {
			out = append(out, filepath.Join(home, filepath.FromSlash(p)))
		}
	}
	if cwd != "" && !same(cwd, home) {
		for _, p := range []string{".claude/skills", ".agents/skills"} {
			out = append(out, filepath.Join(cwd, filepath.FromSlash(p)))
		}
	}
	return out
}

// Installed finds the copies of the Keystub skill in those places and says
// whether each matches this binary's. A keystub folder that isn't the
// Keystub skill is left out.
func Installed(home, cwd string) []Copy {
	var out []Copy
	seen := map[string]bool{}
	for _, parent := range Places(home, cwd) {
		dir := filepath.Join(parent, Name)
		// One copy reached two ways (a symlinked home, a linked folder) counts once.
		real, err := filepath.EvalSymlinks(dir)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		b, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
		if err != nil {
			continue
		}
		if name, _, err := Meta(b); err != nil || name != Name {
			continue
		}
		out = append(out, Copy{Path: dir, Current: Same(os.DirFS(dir))})
	}
	return out
}

// Same reports whether dir holds every file of this binary's skill with
// the same contents.
func Same(dir fs.FS) bool {
	same := true
	_ = fs.WalkDir(Keystub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !same {
			return err
		}
		want, _ := fs.ReadFile(Keystub, p)
		got, err := fs.ReadFile(dir, p)
		if err != nil || !bytes.Equal(got, want) {
			same = false
		}
		return nil
	})
	return same
}

// same reports whether two paths name the same folder.
func same(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}
