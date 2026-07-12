package appstate

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// State is the small bit of UI state fortochka remembers between runs.
type State struct {
	TunnelWanted bool     `json:"tunnel_wanted"`
	TunnelApps   []string `json:"tunnel_apps"`
}

func Path(dir string) string { return filepath.Join(dir, "state.json") }

func Load(path string) State {
	var s State
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

func Save(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
