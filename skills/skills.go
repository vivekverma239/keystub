// Package skills holds the Agent Skill that teaches coding agents to use
// Keystub: skills/keystub, a SKILL.md folder that Claude Code, Codex,
// Cursor and other agents read. It is embedded so `keystub skill install`
// can write it out.
package skills

import (
	"embed"
	"errors"
	"io/fs"
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
