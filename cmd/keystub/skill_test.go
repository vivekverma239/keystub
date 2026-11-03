package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/docs"
	"github.com/vivekverma239/keystub/internal/cli"
	"github.com/vivekverma239/keystub/skills"
)

func TestSkillTargets(t *testing.T) {
	home, cwd := "/h", "/p"
	for _, tc := range []struct {
		o    skillOpts
		want []string
	}{
		{skillOpts{agents: "all"}, []string{"/h/.claude/skills", "/h/.agents/skills"}},
		{skillOpts{agents: "codex"}, []string{"/h/.agents/skills"}},
		{skillOpts{agents: "cursor"}, []string{"/h/.cursor/skills"}},
		{skillOpts{agents: "cursor", project: true}, []string{"/p/.agents/skills"}},
		{skillOpts{agents: "claude,codex,agents", project: true}, []string{"/p/.claude/skills", "/p/.agents/skills"}},
		{skillOpts{agents: "claude", dir: "/x"}, []string{"/x"}},
	} {
		got, err := skillTargets(tc.o, home, cwd)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%+v: got %v %v, want %v", tc.o, got, err, tc.want)
		}
	}
	for _, a := range []string{"vim", "", ","} {
		if _, err := skillTargets(skillOpts{agents: a}, home, cwd); err == nil {
			t.Errorf("--agent %q: want an error", a)
		}
	}
}

func TestSkillInstall(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	var out, errOut bytes.Buffer
	if err := skillMain([]string{"install"}, home, cwd, &out, &errOut); err != nil {
		t.Fatalf("%v: %s", err, errOut.String())
	}
	for _, d := range []string{".claude/skills/keystub", ".agents/skills/keystub"} {
		dir := filepath.Join(home, d)
		if err := fs.WalkDir(skills.Keystub, ".", func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			want, _ := fs.ReadFile(skills.Keystub, p)
			got, err := os.ReadFile(filepath.Join(dir, p))
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("%s/%s: not the embedded file (%v)", d, p, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
			t.Errorf("%s: mode %v, want 0755", d, st.Mode().Perm())
		}
	}

	// Installing again replaces the whole copy, dropping files it no longer has.
	stale := filepath.Join(home, ".claude/skills/keystub/references/old.md")
	_ = os.WriteFile(stale, []byte("old"), 0o644)
	out.Reset()
	if err := skillMain([]string{"install", "--agent", "claude", "--json"}, home, cwd, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a file from the old copy is still there")
	}
	if !strings.Contains(out.String(), `"installed":["`+filepath.Join(home, ".claude/skills/keystub")+`"]`) {
		t.Errorf("--json printed %s", out.String())
	}
	if m, _ := filepath.Glob(filepath.Join(home, ".claude/skills/.keystub-skill-*")); len(m) > 0 {
		t.Errorf("left temporary folders: %v", m)
	}

	// A keystub folder that is something else is left alone.
	other := filepath.Join(cwd, ".agents/skills/keystub")
	_ = os.MkdirAll(other, 0o755)
	_ = os.WriteFile(filepath.Join(other, "SKILL.md"), []byte("---\nname: other\n---\n"), 0o644)
	if err := skillMain([]string{"install", "--agent", "codex", "--project"}, home, cwd, io.Discard, io.Discard); err == nil {
		t.Error("replaced a folder that isn't the Keystub skill")
	}
	if b, _ := os.ReadFile(filepath.Join(other, "SKILL.md")); !strings.Contains(string(b), "name: other") {
		t.Error("the other skill was changed")
	}

	for _, args := range [][]string{nil, {"remove"}, {"install", "extra"}, {"install", "--nope"}, {"install", "--agent", "vim"}} {
		var c exitCode
		if err := skillMain(args, home, cwd, io.Discard, io.Discard); !errors.As(err, &c) || c != 2 {
			t.Errorf("%q: want exit code 2, got %v", args, err)
		}
	}
}

// --- the commands the skill and llms.txt name exist ---

// TestDocumentedCommandsExist runs every keystub command line in the
// skill (SKILL.md and its references) and in llms.txt through the
// CLI's own argument parsing, so neither can name a command, subcommand
// or flag the CLI doesn't have. API commands run against a server that
// can't be reached: a line that parses fails with exit code 1, and one
// that doesn't with 2.
func TestDocumentedCommandsExist(t *testing.T) {
	texts := map[string]string{"docs/llms.txt": docs.AgentGuide}
	// The start page a hosted server serves at /start, with its own URL
	// for {{SERVER}}.
	start, err := os.ReadFile("../../docs/start.md")
	if err != nil {
		t.Fatal(err)
	}
	texts["docs/start.md"] = strings.ReplaceAll(string(start), "{{SERVER}}", "https://app.keystub.app")
	_ = fs.WalkDir(skills.Keystub, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".md") {
			b, _ := fs.ReadFile(skills.Keystub, p)
			texts["skills/keystub/"+p] = string(b)
		}
		return nil
	})
	total := 0
	for name, text := range texts {
		lines := commandLines(text, strings.HasSuffix(name, ".md"))
		total += len(lines)
		for _, l := range lines {
			if err := checkCommand(t, l); err != nil {
				t.Errorf("%s: keystub %s: %v", name, strings.Join(l, " "), err)
			}
		}
	}
	if total < 40 {
		t.Errorf("found only %d keystub command lines; is the extraction broken?", total)
	}
}

var (
	codeSpan   = regexp.MustCompile("`([^`]+)`")
	keystubCmd = regexp.MustCompile(`(?:^|[\s(|;&])keystub\s+([a-z][a-z-]*)`)
	lineEnd    = regexp.MustCompile("`|\\)|\\||;|&&| #|  \\(")
)

// commandLines finds `keystub …` command lines, each as its arguments
// after "keystub". In Markdown only code (fenced blocks and `spans`)
// counts; in plain text such as llms.txt, every line.
func commandLines(text string, markdown bool) [][]string {
	var code []string
	if markdown {
		fenced := false
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "```") {
				fenced = !fenced
				continue
			}
			if fenced {
				code = append(code, l)
				continue
			}
			for _, m := range codeSpan.FindAllStringSubmatch(l, -1) {
				code = append(code, m[1])
			}
		}
	} else {
		code = strings.Split(text, "\n")
	}
	var out [][]string
	for _, c := range code {
		for _, loc := range keystubCmd.FindAllStringSubmatchIndex(c, -1) {
			rest := c[loc[2]:]
			if e := lineEnd.FindStringIndex(rest); e != nil {
				rest = rest[:e[0]]
			}
			out = append(out, shellWords(rest))
		}
	}
	return out
}

// shellWords splits a command line as sh would, quotes and all, leaving
// $VARS as they are.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	in, quote := false, rune(0)
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in {
				words = append(words, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		words = append(words, cur.String())
	}
	return words
}

// checkCommand runs one documented command line through the parsing of
// the command it names.
func checkCommand(t *testing.T, words []string) error {
	cmd, args := words[0], words[1:]
	if slices.Contains([]string{"delete", "remove", "revoke"}, first(args)) && !slices.Contains(args, "--yes") && !slices.Contains(args, "-y") {
		return errors.New("a delete needs --yes: nothing can ask when stdin isn't a terminal")
	}
	switch {
	case slices.Contains(cli.Commands, cmd):
		return checkAPICommand(t, cmd, args)
	case cmd == "run" || cmd == "env":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var o runOpts
		o.flags(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if cmd == "run" && len(args) > 0 && fs.NArg() == 0 {
			return errors.New("no command to run after the flags")
		}
		return nil
	case cmd == "skill":
		if len(args) == 0 {
			return nil
		}
		_, err := parseSkill(args, io.Discard)
		return err
	case cmd == "version":
		if len(args) > 0 {
			return errors.New("version takes no arguments")
		}
		return nil
	case cmd == "help":
		if len(args) > 0 && !slices.Equal(args, []string{"agents"}) {
			return errors.New("help takes only agents")
		}
		return nil
	case slices.Contains([]string{"serve", "agent", "gateway", "link", "unlink"}, cmd):
		for _, a := range args {
			f, _, _ := strings.Cut(a, "=")
			if strings.HasPrefix(f, "-") && !regexp.MustCompile(`[\s\[|]`+regexp.QuoteMeta(f)+`[\s\]|=]`).MatchString(usageText) {
				return errors.New(f + " isn't in keystub's usage")
			}
		}
		return nil
	}
	return errors.New("no such command")
}

func first(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in this test")
}

// checkAPICommand runs an API command against a server it can't reach.
// A line with no arguments beyond its subcommand is a mention, as in
// "pipe it to `keystub keys add`": for it, only the subcommand has to
// exist, which an unknown flag shows (each parses its flags first).
func checkAPICommand(t *testing.T, cmd string, args []string) error {
	mention := len(args) == 0 || (len(args) == 1 && !strings.HasPrefix(args[0], "-") && !slices.Contains([]string{"usage", "setup", "ca"}, cmd))
	if mention {
		args = append(slices.Clone(args), "--not-a-flag")
	}
	var out, errOut bytes.Buffer
	code := cli.Main(cli.Env{
		Stdin:  strings.NewReader("a-value"),
		Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string {
			switch k {
			case "KEYSTUB_API_KEY":
				return "skapi_test"
			case "KEYSTUB_SERVER":
				return "https://keystub.invalid"
			}
			return "a-value" // every --from-env VAR is set
		},
		Home:   t.TempDir(),
		Client: &http.Client{Transport: unreachable{}},
		Sleep:  func(d time.Duration) {},
	}, cmd, args)
	msg := strings.TrimSpace(out.String() + errOut.String())
	if mention {
		if code == cli.ExitUsage && strings.Contains(msg, "unknown flag --not-a-flag") {
			return nil
		}
		return errors.New("no such subcommand: " + msg)
	}
	if code == cli.ExitUsage {
		return errors.New(msg)
	}
	return nil
}
