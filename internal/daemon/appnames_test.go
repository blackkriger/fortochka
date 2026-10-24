package daemon

import (
	"path/filepath"
	"testing"

	"fortochka/internal/appstate"
)

func TestLearnNames(t *testing.T) {
	selected := map[string]bool{"agent.exe": true, "discord.exe": true}

	got, changed := learnNames(selected, nil, map[string]string{"agent.exe": "Battle.net Update Agent", "steam.exe": "Steam"})
	if !changed || got["agent.exe"] != "Battle.net Update Agent" {
		t.Fatalf("a selected app seen running must be remembered by its description: %v, changed=%v", got, changed)
	}
	if _, ok := got["steam.exe"]; ok {
		t.Error("an app that is not selected must not be remembered")
	}

	again, changed := learnNames(selected, got, nil)
	if changed || again["agent.exe"] != "Battle.net Update Agent" {
		t.Errorf("with the app closed the remembered name must stay and nothing needs saving: %v, changed=%v", again, changed)
	}

	pruned, changed := learnNames(map[string]bool{"discord.exe": true}, again, nil)
	if !changed || len(pruned) != 0 {
		t.Errorf("unselecting an app must forget its name: %v, changed=%v", pruned, changed)
	}
}

func TestDisplayNames(t *testing.T) {
	selected := map[string]bool{"agent.exe": true}
	remembered := map[string]string{"agent.exe": "Battle.net Update Agent", "gone.exe": "Old App"}

	shown := displayNames(selected, remembered, map[string]string{"steam.exe": "Steam"})
	if shown["agent.exe"] != "Battle.net Update Agent" {
		t.Errorf("a selected app that is not running must show its remembered name, got %q", shown["agent.exe"])
	}
	if shown["steam.exe"] != "Steam" {
		t.Error("running apps keep their live names")
	}
	if _, ok := shown["gone.exe"]; ok {
		t.Error("a remembered name of an unselected app must not be shown")
	}

	live := displayNames(selected, remembered, map[string]string{"agent.exe": "Battle.net Agent v2"})
	if live["agent.exe"] != "Battle.net Agent v2" {
		t.Errorf("the live description wins over the remembered one, got %q", live["agent.exe"])
	}
}

func TestAppNamesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	in := appstate.State{TunnelApps: []string{"agent.exe"}, TunnelAppNames: map[string]string{"Agent.EXE": "Battle.net Update Agent"}}
	if err := appstate.Save(path, in); err != nil {
		t.Fatal(err)
	}
	out := appstate.Load(path)
	names, _ := learnNames(map[string]bool{"agent.exe": true}, lowerKeys(out.TunnelAppNames), nil)
	if names["agent.exe"] != "Battle.net Update Agent" {
		t.Errorf("the remembered name must come back after a restart, got %v", names)
	}
}
