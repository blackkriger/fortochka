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

// Manual and fetched rules compile into separate matchers. Merging them would decide by specificity rather than by origin: the lists carry entries like www.youtube.com, and a longest-suffix search reaches those before a manual youtube.com, so the override would silently lose.
type compiled struct {
	manual matcher
	list   matcher
	def    Action
}

type matcher struct {
	suffixes map[string]Action
	keywords []Rule
	cidrs    []cidrRule
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

// rebuild compiles and publishes under mu so a slow rebuild can't publish its stale snapshot after a newer one.
func (e *Engine) rebuild() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.current.Store(&compiled{manual: compile(e.manual), list: compile(e.list), def: e.def})
}

func compile(rs []Rule) matcher {
	m := matcher{suffixes: make(map[string]Action, len(rs))}
	for _, r := range rs {
		switch {
		case r.Suffix != "":
			key := strings.ToLower(strings.TrimPrefix(r.Suffix, "."))
			if _, seen := m.suffixes[key]; !seen {
				m.suffixes[key] = r.Action
			}
		case r.Keyword != "":
			m.keywords = append(m.keywords, r)
		case r.CIDR != "":
			if p, err := netip.ParsePrefix(r.CIDR); err == nil {
				m.cidrs = append(m.cidrs, cidrRule{prefix: p, action: r.Action})
			}
		}
	}
	return m
}

// Decide resolves an action for host (a domain or IP literal); a manual rule answers first whatever its shape, and only then the fetched lists.
func (e *Engine) Decide(host string) Action {
	c := e.current.Load()
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if a, ok := c.manual.match(host); ok {
		return a
	}
	if a, ok := c.list.match(host); ok {
		return a
	}
	return c.def
}

func (m matcher) match(host string) (Action, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, cr := range m.cidrs {
			if cr.prefix.Contains(ip) {
				return cr.action, true
			}
		}
		return 0, false
	}
	for name := host; name != ""; {
		if a, ok := m.suffixes[name]; ok {
			return a, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}
	for _, r := range m.keywords {
		if strings.Contains(host, r.Keyword) {
			return r.Action, true
		}
	}
	return 0, false
}
