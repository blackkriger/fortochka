package rules

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

type Action int

const (
	Direct Action = iota
	WG
)

func ParseAction(s string) Action {
	if strings.EqualFold(strings.TrimSpace(s), "wg") {
		return WG
	}
	return Direct
}

// Rule is one match condition. Exactly one matcher field is expected to be set.
type Rule struct {
	Suffix  string
	Keyword string
	CIDR    string
	Action  Action
}

type compiled struct {
	suffixes map[string]Action
	keywords []Rule
	cidrs    []cidrRule
	def      Action
}

type cidrRule struct {
	prefix netip.Prefix
	action Action
}

// Engine decides Direct vs WG for a destination; manual rules take priority over the auto-fetched list, and both are recompiled atomically on update.
type Engine struct {
	mu      sync.Mutex
	manual  []Rule
	list    []Rule
	def     Action
	current atomic.Pointer[compiled]
}

func New(def Action) *Engine {
	e := &Engine{def: def}
	e.rebuild()
	return e
}

func (e *Engine) SetManual(r []Rule) {
	e.mu.Lock()
	e.manual = r
	e.mu.Unlock()
	e.rebuild()
}

func (e *Engine) SetList(r []Rule) {
	e.mu.Lock()
	e.list = r
	e.mu.Unlock()
	e.rebuild()
}

func (e *Engine) rebuild() {
	e.mu.Lock()
	all := make([]Rule, 0, len(e.manual)+len(e.list))
	all = append(all, e.manual...) // manual first → wins on suffix map overwrite order
	all = append(all, e.list...)
	def := e.def
	e.mu.Unlock()

	c := &compiled{suffixes: make(map[string]Action), def: def}
	for _, r := range all {
		switch {
		case r.Suffix != "":
			key := strings.ToLower(strings.TrimPrefix(r.Suffix, "."))
			if _, seen := c.suffixes[key]; !seen {
				c.suffixes[key] = r.Action
			}
		case r.Keyword != "":
			c.keywords = append(c.keywords, r)
		case r.CIDR != "":
			if p, err := netip.ParsePrefix(r.CIDR); err == nil {
				c.cidrs = append(c.cidrs, cidrRule{prefix: p, action: r.Action})
			}
		}
	}
	e.current.Store(c)
}

// Decide resolves an action for host (a domain or IP literal) and port.
func (e *Engine) Decide(host string) Action {
	c := e.current.Load()
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if ip, err := netip.ParseAddr(host); err == nil {
		for _, cr := range c.cidrs {
			if cr.prefix.Contains(ip) {
				return cr.action
			}
		}
		return c.def
	}

	for name := host; name != ""; {
		if a, ok := c.suffixes[name]; ok {
			return a
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}
	for _, r := range c.keywords {
		if strings.Contains(host, r.Keyword) {
			return r.Action
		}
	}
	return c.def
}
