package main

import (
	"testing"

	"fortochka/internal/ipc"
)

func TestAppTitlesDisambiguateSameNames(t *testing.T) {
	st := ipc.Status{AppNames: map[string]string{
		"battle.net.exe": "Battle.net",
		"temp_55378fa22eff4403dae46bf6f2453db5.exe": "battle.net",
		"discord.exe":   "Discord",
		"fortochka.exe": "fortochka",
	}}
	set := map[string]bool{
		"battle.net.exe": true,
		"temp_55378fa22eff4403dae46bf6f2453db5.exe": true,
		"discord.exe":   true,
		"fortochka.exe": true,
	}

	titles := appTitles(st, set, "fortochka.exe")
	if got := titles["battle.net.exe"]; got != "Battle.net (battle.net.exe)" {
		t.Errorf("battle.net.exe = %q, want the file name added to tell it apart", got)
	}
	if got := titles["temp_55378fa22eff4403dae46bf6f2453db5.exe"]; got != "battle.net (temp_55378fa22eff4403dae46bf6f2453db5.exe)" {
		t.Errorf("the temp copy = %q, want the file name added: names that differ only in case look the same in the menu", got)
	}
	if got := titles["discord.exe"]; got != "Discord" {
		t.Errorf("a unique name must stay as is, got %q", got)
	}
	if _, ok := titles["fortochka.exe"]; ok {
		t.Error("fortochka itself must not be offered for routing")
	}
}

func TestAppsSignatureFollowsTitles(t *testing.T) {
	selected := map[string]bool{"agent.exe": true}
	before := appsSignature(map[string]string{"agent.exe": "Agent"}, selected)
	after := appsSignature(map[string]string{"agent.exe": "Battle.net Update Agent"}, selected)
	if before == after {
		t.Error("a new title must change the signature, or the menu keeps showing the old one")
	}
}
