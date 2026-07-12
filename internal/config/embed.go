package config

import (
	_ "embed"
	"os"
)

//go:embed default.yaml
var defaultYAML []byte

// EnsureDefault writes the bundled default config to path if nothing is there yet, so a freshly-installed single-exe engine starts with the Telegram rules and list sources instead of bare defaults.
func EnsureDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, defaultYAML, 0o644)
}
