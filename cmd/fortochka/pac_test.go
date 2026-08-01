package main

import "testing"

func TestOurPAC(t *testing.T) {
	ours := []string{
		"http://127.0.0.1:1081/proxy.pac",
		"http://localhost:1081/proxy.pac",
		"http://127.0.0.2:9/proxy.pac",
		"http://:1081/proxy.pac",
		"http://0.0.0.0:1081/proxy.pac",
	}
	for _, u := range ours {
		if !ourPAC(u) {
			t.Errorf("ourPAC(%q) = false, want true", u)
		}
	}
	// Never clear another tool's or a corporate PAC.
	foreign := []string{
		"",
		"http://127.0.0.1:9090/clash.pac",
		"http://192.168.1.10:8080/proxy.pac",
		"http://proxy.corp.example/proxy.pac",
		"not a url at all",
	}
	for _, u := range foreign {
		if ourPAC(u) {
			t.Errorf("ourPAC(%q) = true, want false", u)
		}
	}
}
