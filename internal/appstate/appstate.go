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

// Save writes through a temp file and renames, so an interrupted or concurrent write can't leave a half-written state.json that parses as empty.
func Save(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil { // flush before the rename, or a power loss can leave the renamed file empty
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
