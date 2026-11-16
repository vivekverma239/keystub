package skills

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/docs"
)

// The open Agent Skills format (agentskills.io/specification): a name of
// lowercase letters, digits and single hyphens, up to 64, matching the
// folder; a description of 1 to 1024 characters.
var skillName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestFrontmatterFollowsTheSpec(t *testing.T) {
	b, err := fs.ReadFile(Keystub, "SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	name, desc, err := Meta(b)
	if err != nil {
		t.Fatal(err)
	}
	if name != Name || !skillName.MatchString(name) || len(name) > 64 {
		t.Errorf("name %q: want %q, lowercase letters, digits and hyphens", name, Name)
	}
	if n := len([]rune(desc)); n == 0 || n > 1024 {
		t.Errorf("description is %d characters; the spec allows 1 to 1024", n)
	}
	for _, word := range []string{"Keystub", ".env", "API key", "sandbox", "agent"} {
		if !strings.Contains(desc, word) {
			t.Errorf("description doesn't mention %q, which should make agents load the skill", word)
		}
	}
}

// The command guide in the skill is llms.txt itself, which `keystub help
// agents` prints and the hosted control plane serves.
func TestCLIGuideIsLLMSTxt(t *testing.T) {
	b, err := fs.ReadFile(Keystub, "references/cli-guide.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != docs.AgentGuide {
		t.Fatal("skills/keystub/references/cli-guide.md differs from docs/llms.txt: cp docs/llms.txt skills/keystub/references/cli-guide.md")
	}
}

func TestReferencedFilesExist(t *testing.T) {
	b, _ := fs.ReadFile(Keystub, "SKILL.md")
	for _, m := range regexp.MustCompile(`references/[a-z0-9-]+\.md`).FindAllString(string(b), -1) {
		if _, err := fs.Stat(Keystub, m); err != nil {
			t.Errorf("SKILL.md names %s, which isn't in the skill", m)
		}
	}
}

// The Claude Code plugin is keystub/ itself: its skills/ folder holds
// the skill, and its marketplace lists it with source "./".
func TestPluginManifests(t *testing.T) {
	var plugin struct {
		Name string `json:"name"`
	}
	readJSON(t, "../.claude-plugin/plugin.json", &plugin)
	if plugin.Name != Name {
		t.Errorf("plugin.json name %q, want %q", plugin.Name, Name)
	}
	var market struct {
		Name  string `json:"name"`
		Owner struct {
			Name string `json:"name"`
		} `json:"owner"`
		Plugins []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"plugins"`
	}
	readJSON(t, "../.claude-plugin/marketplace.json", &market)
	if market.Name == "" || market.Owner.Name == "" || len(market.Plugins) != 1 {
		t.Fatalf("marketplace.json needs name, owner.name and one plugin: %+v", market)
	}
	if p := market.Plugins[0]; p.Name != plugin.Name || p.Source != "./" {
		t.Errorf("marketplace plugin %+v, want name %q and source ./", p, plugin.Name)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestInstalledSaysWhetherACopyIsCurrent(t *testing.T) {
	home := t.TempDir()
	if got := Installed(home, ""); len(got) != 0 {
		t.Fatalf("nothing installed: %v", got)
	}
	dir := filepath.Join(home, ".claude", "skills", Name)
	if err := os.CopyFS(dir, Keystub); err != nil {
		t.Fatal(err)
	}
	if got := Installed(home, ""); len(got) != 1 || !got[0].Current {
		t.Fatalf("a fresh copy: %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: keystub\ndescription: old\n---\nold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Installed(home, ""); len(got) != 1 || got[0].Current {
		t.Fatalf("an old copy: %v", got)
	}
	// A keystub folder that isn't this skill is left out.
	other := filepath.Join(home, ".agents", "skills", Name)
	_ = os.MkdirAll(other, 0o755)
	_ = os.WriteFile(filepath.Join(other, "SKILL.md"), []byte("---\nname: other\n---\n"), 0o644)
	if got := Installed(home, ""); len(got) != 1 {
		t.Fatalf("someone else's folder: %v", got)
	}
}

func TestInstalledCountsALinkedCopyOnce(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agents", "skills", Name)
	if err := os.CopyFS(dir, Keystub); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(home, ".claude", "skills"), 0o755)
	if err := os.Symlink(dir, filepath.Join(home, ".claude", "skills", Name)); err != nil {
		t.Fatal(err)
	}
	if got := Installed(home+"/", home); len(got) != 1 {
		t.Fatalf("one copy, linked: %v", got)
	}
}
