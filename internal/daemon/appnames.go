package daemon

import "strings"

func learnNames(selected map[string]bool, remembered, running map[string]string) (map[string]string, bool) {
	out := make(map[string]string, len(selected))
	changed := false
	for app, name := range remembered {
		if selected[app] && name != "" {
			out[app] = name
		} else {
			changed = true
		}
	}
	for app := range selected {
		if name := running[app]; name != "" && out[app] != name {
			out[app] = name
			changed = true
		}
	}
	return out, changed
}

func displayNames(selected map[string]bool, remembered, running map[string]string) map[string]string {
	out := make(map[string]string, len(running)+len(remembered))
	for app, name := range remembered {
		if selected[app] {
			out[app] = name
		}
	}
	for app, name := range running {
		out[app] = name
	}
	return out
}

func lowerKeys(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			out[k] = v
		}
	}
	return out
}
