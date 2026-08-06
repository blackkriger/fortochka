package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WG     WG     `yaml:"wg"`
	Listen Listen `yaml:"listen"`
	Lists  Lists  `yaml:"lists"`
	Rules  []Rule `yaml:"rules"`
}

type WG struct {
	Endpoint        string `yaml:"endpoint"`
	PrivateKey      string `yaml:"private_key"`
	ServerPublicKey string `yaml:"server_public_key"`
	PresharedKey    string `yaml:"preshared_key"`
	Address         string `yaml:"address"`
	DNS             string `yaml:"dns"`

	Jc   string `yaml:"jc"`
	Jmin string `yaml:"jmin"`
	Jmax string `yaml:"jmax"`
	S1   string `yaml:"s1"`
	S2   string `yaml:"s2"`
	H1   string `yaml:"h1"`
	H2   string `yaml:"h2"`
	H3   string `yaml:"h3"`
	H4   string `yaml:"h4"`
}

type Listen struct {
	Proxy string `yaml:"proxy"`
	PAC   string `yaml:"pac"`
}

type Lists struct {
	RefilterDomains string        `yaml:"refilter_domains"`
	RefilterIPs     string        `yaml:"refilter_ips"`
	Refresh         time.Duration `yaml:"refresh"`
	DefaultAction   string        `yaml:"default_action"`
}

type Rule struct {
	Suffix  string `yaml:"suffix"`
	Keyword string `yaml:"keyword"`
	CIDR    string `yaml:"cidr"`
	Action  string `yaml:"action"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	return &c, nil
}

// Default returns a config with only built-in defaults applied, for when no fortochka.yaml is present (the engine still runs; block lists are just empty).
func Default() *Config {
	c := &Config{}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	if c.Listen.Proxy == "" {
		c.Listen.Proxy = "127.0.0.1:1080"
	}
	if c.Listen.PAC == "" {
		c.Listen.PAC = "127.0.0.1:1081"
	}
	if c.WG.DNS == "" {
		c.WG.DNS = "1.1.1.1"
	}
	if c.Lists.Refresh <= 0 { // a non-positive interval would panic the timer and take the service down
		c.Lists.Refresh = 12 * time.Hour // the block lists move slowly, and a refresh also happens whenever the tunnel comes up
	}
	if c.Lists.DefaultAction == "" {
		c.Lists.DefaultAction = "direct"
	}
}
