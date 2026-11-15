package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// .keystub.json names the environment a folder belongs to, so keystub
// setup and doctor need no argument there. It holds no secret: it can be
// committed, and a teammate's setup then uses the same environment.
const projectFileName = ".keystub.json"

type projectFile struct {
	Env string `json:"env"`
}

// readProjectFile is the environment dir's .keystub.json names, or "".
func readProjectFile(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, projectFileName))
	if err != nil {
		return ""
	}
	var pf projectFile
	if json.Unmarshal(b, &pf) != nil {
		return ""
	}
	return pf.Env
}

// writeProjectFile writes dir's .keystub.json unless it already names env.
func writeProjectFile(dir, env string) error {
	if readProjectFile(dir) == env {
		return nil
	}
	path := filepath.Join(dir, projectFileName)
	if _, err := os.Stat(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	b, _ := json.MarshalIndent(projectFile{Env: env}, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
