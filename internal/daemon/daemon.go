// Package daemon is the fortochka engine (WireGuard tunnel, per-app WinDivert interception, mixed proxy, PAC server and routing rules); it runs inside the Windows service and is driven by the tray over IPC.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fortochka/internal/appstate"
	"fortochka/internal/apptunnel"
	"fortochka/internal/config"
	"fortochka/internal/ipc"
	"fortochka/internal/lists"
	"fortochka/internal/pac"
	"fortochka/internal/procnet"
	"fortochka/internal/proxy"
	"fortochka/internal/rules"
	"fortochka/internal/userrules"
	"fortochka/internal/wg"
	"fortochka/internal/wgconf"
)

type Daemon struct {
	cfg    *config.Config
	dir    string
	tunnel *wg.Manager
	apps   *apptunnel.Engine

	proxyLn net.Listener
	pacSrv  *http.Server
	cancel  context.CancelFunc

	statePath string

	mu           sync.Mutex
	tunnelWanted bool
	selApps      map[string]bool
	lastState    wg.State
	rebuildFails int

	portMu     sync.Mutex
	portSnap   map[uint16]uint32 // local-TCP-port → PID, refreshed at most every 500ms for the proxy per-app check
	portSnapAt time.Time
	pidNames   map[uint32]string
}

// New builds the engine from cfg (using dir for state/tunnel/rules), starts the proxy/PAC/rules/lists and resumes the tunnel if it was up last session.
func New(cfg *config.Config, dir string) (*Daemon, error) {
	d := &Daemon{
		cfg:       cfg,
		dir:       dir,
		tunnel:    wg.NewManager(),
		selApps:   map[string]bool{},
		lastState: wg.State(-1),
		statePath: appstate.Path(dir),
	}
	state := appstate.Load(d.statePath)
	d.tunnelWanted = state.TunnelWanted
	for _, a := range state.TunnelApps {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			d.selApps[a] = true
		}
	}
	if _, err := os.Stat(d.tunnelPath()); err == nil {
		secureFile(d.tunnelPath()) // lock down the key file (covers migrated configs too)
	}

	engine := rules.New(rules.ParseAction(cfg.Lists.DefaultAction))
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	server := &proxy.Server{Engine: engine, Direct: &net.Dialer{}, WG: d.tunnel, ForceWG: d.forceWGForPort}

	rulesPath := userrules.Path(dir)
	if err := userrules.EnsureDefault(rulesPath); err != nil {
		log.Printf("rules: %v", err)
	}
	yamlRules := append(builtinDirect(), manualRules(cfg.Rules)...)
	applyManual := func() {
		custom, err := userrules.Load(rulesPath)
		if err != nil {
			log.Printf("rules: load %s: %v", rulesPath, err)
		}
		all := append(append([]rules.Rule{}, yamlRules...), custom...)
		engine.SetManual(all)
		server.Rebalance() // reroute live connections whose decision changed
		log.Printf("rules: applied %d built-in + %d custom", len(yamlRules), len(custom))
	}
	applyManual()
	go userrules.Watch(ctx, rulesPath, applyManual)
	go lists.Run(ctx, lists.Source{
		DomainsURL: cfg.Lists.RefilterDomains,
		IPsURL:     cfg.Lists.RefilterIPs,
		Refresh:    cfg.Lists.Refresh,
	}, engine)

	ln, err := net.Listen("tcp", cfg.Listen.Proxy)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("proxy listen: %w", err)
	}
	d.proxyLn = ln
	go func() {
		if err := server.Serve(ln); err != nil {
			log.Printf("proxy: %v", err)
		}
	}()

	d.pacSrv = &http.Server{Addr: cfg.Listen.PAC, Handler: pac.Handler(cfg.Listen.Proxy, discordDomains)}
	go func() {
		if err := d.pacSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("pac: %v", err)
		}
	}()

	d.apps = apptunnel.New(d.tunnel, log.Printf)
	log.Printf("fortochka engine up — proxy %s, pac %s", cfg.Listen.Proxy, pac.URL(cfg.Listen.PAC))

	if d.tunnelWanted {
		if c, ok := d.loadWGConfig(); ok {
			if err := d.tunnel.Connect(c); err != nil {
				log.Printf("wireguard: resume failed: %v", err)
			} else {
				log.Printf("wireguard: resumed connection to %s", d.tunnel.Endpoint())
			}
		} else {
			log.Printf("wireguard: resume wanted but no config found")
		}
	} else {
		log.Printf("wireguard: idle — import a .conf and press Connect")
	}
	if len(d.selApps) > 0 {
		log.Printf("apptunnel: %d app(s) selected (active only while tunnel is up)", len(d.selApps))
	}

	go d.watch(ctx)
	return d, nil
}

// Handle dispatches one IPC request; every command returns a fresh Status so the tray updates immediately without a follow-up poll.
func (d *Daemon) Handle(req ipc.Request) ipc.Response {
	switch req.Cmd {
	case ipc.CmdStatus:
		// nothing to change
	case ipc.CmdConnect:
		if err := d.Connect(); err != nil {
			return ipc.Response{Error: err.Error()}
		}
	case ipc.CmdDisconnect:
		if err := d.Disconnect(); err != nil {
			return ipc.Response{Error: err.Error()}
		}
	case ipc.CmdImport:
		if err := d.Import([]byte(req.Data)); err != nil {
			return ipc.Response{Error: err.Error()}
		}
	case ipc.CmdSetApps:
		d.SetApps(req.Apps)
	default:
		return ipc.Response{Error: "unknown command: " + req.Cmd}
	}
	s := d.Status()
	return ipc.Response{OK: true, Status: &s}
}

func (d *Daemon) Status() ipc.Status {
	d.mu.Lock()
	apps := sortedKeys(d.selApps)
	wanted := d.tunnelWanted
	d.mu.Unlock()
	named := apptunnel.RunningNetAppsNamed()
	running := make([]string, 0, len(named))
	for k := range named {
		running = append(running, k)
	}
	sort.Strings(running)
	return ipc.Status{
		State:        stateName(d.tunnel.State()),
		Endpoint:     d.tunnel.Endpoint(),
		HasConfig:    d.hasWGConfig(),
		TunnelWanted: wanted,
		Apps:         apps,
		RunningApps:  running,
		AppNames:     named,
		PACURL:       pac.URL(d.cfg.Listen.PAC),
		ProxyAddr:    d.cfg.Listen.Proxy,
	}
}

func (d *Daemon) Connect() error {
	c, ok := d.loadWGConfig()
	if !ok {
		return errors.New("no WireGuard config; import one first")
	}
	if err := d.tunnel.Connect(c); err != nil {
		return err
	}
	d.mu.Lock()
	d.tunnelWanted = true
	d.rebuildFails = 0
	d.mu.Unlock()
	d.persist()
	log.Printf("daemon: connecting -> %s", d.tunnel.Endpoint())
	return nil
}

func (d *Daemon) Disconnect() error {
	d.mu.Lock()
	d.tunnelWanted = false
	d.mu.Unlock()
	d.tunnel.Close()
	d.persist()
	d.reconcile()
	log.Printf("daemon: tunnel disconnected")
	return nil
}

func (d *Daemon) Import(data []byte) error {
	c, err := wgconf.Parse(data)
	if err != nil {
		return err
	}
	if err := d.tunnel.Connect(c); err != nil {
		return err
	}
	if err := os.WriteFile(d.tunnelPath(), data, 0o600); err != nil {
		log.Printf("daemon: save tunnel: %v", err)
	}
	secureFile(d.tunnelPath())
	d.mu.Lock()
	d.tunnelWanted = true
	d.rebuildFails = 0
	d.mu.Unlock()
	d.persist()
	log.Printf("daemon: imported config, connecting -> %s", c.Endpoint)
	return nil
}

func (d *Daemon) SetApps(names []string) {
	d.mu.Lock()
	d.selApps = map[string]bool{}
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			d.selApps[n] = true
		}
	}
	d.mu.Unlock()
	d.persist()
	d.reconcile()
	log.Printf("daemon: routed apps set to %v", names)
}

func (d *Daemon) Close() {
	if d.cancel != nil {
		d.cancel()
	}
	if d.apps != nil {
		d.apps.Stop()
	}
	if d.pacSrv != nil {
		d.pacSrv.Close()
	}
	if d.proxyLn != nil {
		d.proxyLn.Close()
	}
	d.tunnel.Close()
	log.Printf("fortochka engine stopped")
}

// reconnectAfter is how long the tunnel may stay down (while wanted) before the supervisor rebuilds it, since the userspace bind can die on a network change and never self-heal.
const reconnectAfter = 15 * time.Second

// maxRebuildAttempts bounds automatic rebuilds so a tunnel that won't come up (e.g. a stuck server session on a shared WG key) is dropped instead of hammering the key forever and blocking the official client; the user presses Connect to retry.
const maxRebuildAttempts = 6

// watch drives per-app interception off the tunnel state (WinDivert is active only while connected) and supervises the tunnel, rebuilding it when it dies.
func (d *Daemon) watch(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var downSince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := d.tunnel.State()
			d.mu.Lock()
			changed := s != d.lastState
			d.lastState = s
			wanted := d.tunnelWanted
			d.mu.Unlock()
			if changed {
				log.Printf("tunnel: %s", stateName(s))
				d.reconcile()
			}
			d.superviseTunnel(wanted, s, &downSince)
		}
	}
}

func (d *Daemon) superviseTunnel(wanted bool, s wg.State, downSince *time.Time) {
	if !wanted || s == wg.Connected {
		*downSince = time.Time{}
		d.mu.Lock()
		d.rebuildFails = 0
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	gaveUp := d.rebuildFails >= maxRebuildAttempts
	d.mu.Unlock()
	if gaveUp {
		return
	}
	now := time.Now()
	if downSince.IsZero() {
		*downSince = now
		return
	}
	if now.Sub(*downSince) < reconnectAfter {
		return
	}
	*downSince = now
	c, ok := d.loadWGConfig()
	if !ok {
		return
	}
	d.mu.Lock()
	if !d.tunnelWanted { // user disconnected while we were deciding
		d.mu.Unlock()
		return
	}
	d.rebuildFails++
	fails := d.rebuildFails
	d.mu.Unlock()

	if fails >= maxRebuildAttempts {
		log.Printf("wireguard: tunnel down after %d attempts — giving up and closing it (press Connect to retry)", fails)
		d.tunnel.Close() // stop hammering the shared WG key so the official client can connect
		d.reconcile()
		return
	}
	log.Printf("wireguard: tunnel down (%s) — rebuilding (%d/%d)", stateName(s), fails, maxRebuildAttempts)
	if err := d.tunnel.Connect(c); err != nil {
		log.Printf("wireguard: rebuild failed: %v", err)
	}
}

// forceWGForPort reports whether the process owning a proxy client's local TCP port is a per-app-tunneled app, so the proxy routes all of its traffic through WG — this covers proxy-aware apps whose loopback traffic the WinDivert redirect can't see. The port→PID lookup is skipped entirely when no apps are selected.
func (d *Daemon) forceWGForPort(localPort uint16) bool {
	d.mu.Lock()
	n := len(d.selApps)
	d.mu.Unlock()
	if n == 0 {
		return false
	}
	name := d.appNameForPort(localPort)
	if name == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.selApps[name]
}

// appNameForPort resolves the process name owning a local TCP port, serving the port→PID table from a 500ms cache so a burst of proxy connections shares one OS table walk; PID→name is cached within each snapshot.
func (d *Daemon) appNameForPort(port uint16) string {
	d.portMu.Lock()
	defer d.portMu.Unlock()
	if d.portSnap == nil || time.Since(d.portSnapAt) > 500*time.Millisecond {
		if m := procnet.TCPPortPID(); m != nil {
			d.portSnap = m
			d.portSnapAt = time.Now()
			d.pidNames = map[uint32]string{}
		}
	}
	pid := d.portSnap[port]
	if pid == 0 {
		return ""
	}
	name, ok := d.pidNames[pid]
	if !ok {
		name = strings.ToLower(procnet.ProcName(pid))
		d.pidNames[pid] = name
	}
	return name
}

func (d *Daemon) reconcile() {
	connected := d.tunnel.State() == wg.Connected
	d.mu.Lock()
	apps := sortedKeys(d.selApps)
	d.mu.Unlock()
	if connected && len(apps) > 0 {
		d.apps.SetApps(apps)
	} else {
		d.apps.SetApps(nil)
	}
}

func (d *Daemon) persist() {
	d.mu.Lock()
	s := appstate.State{TunnelWanted: d.tunnelWanted, TunnelApps: sortedKeys(d.selApps)}
	d.mu.Unlock()
	if err := appstate.Save(d.statePath, s); err != nil {
		log.Printf("daemon: save state: %v", err)
	}
}

func (d *Daemon) tunnelPath() string { return filepath.Join(d.dir, "tunnel.conf") }

func (d *Daemon) hasWGConfig() bool {
	if _, err := os.Stat(d.tunnelPath()); err == nil {
		return true
	}
	return d.cfg.WG.PrivateKey != ""
}

func (d *Daemon) loadWGConfig() (wg.Config, bool) {
	if p := d.tunnelPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			if c, err := wgconf.ParseFile(p); err == nil {
				return c, true
			}
		}
	}
	if d.cfg.WG.PrivateKey != "" {
		return wg.Config{
			Endpoint:        d.cfg.WG.Endpoint,
			PrivateKey:      d.cfg.WG.PrivateKey,
			ServerPublicKey: d.cfg.WG.ServerPublicKey,
			PresharedKey:    d.cfg.WG.PresharedKey,
			Address:         d.cfg.WG.Address,
			DNS:             d.cfg.WG.DNS,
			Jc:              d.cfg.WG.Jc,
			Jmin:            d.cfg.WG.Jmin,
			Jmax:            d.cfg.WG.Jmax,
			S1:              d.cfg.WG.S1,
			S2:              d.cfg.WG.S2,
			H1:              d.cfg.WG.H1,
			H2:              d.cfg.WG.H2,
			H3:              d.cfg.WG.H3,
			H4:              d.cfg.WG.H4,
		}, true
	}
	return wg.Config{}, false
}

func stateName(s wg.State) string {
	switch s {
	case wg.Connected:
		return ipc.StateConnected
	case wg.Connecting:
		return ipc.StateConnecting
	default:
		return ipc.StateDisconnected
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func manualRules(in []config.Rule) []rules.Rule {
	out := make([]rules.Rule, 0, len(in))
	for _, r := range in {
		out = append(out, rules.Rule{
			Suffix:  r.Suffix,
			Keyword: r.Keyword,
			CIDR:    r.CIDR,
			Action:  rules.ParseAction(r.Action),
		})
	}
	return out
}

// discordDomains are pinned direct: Discord tunnels poorly (voice latency), so it is left to a co-running DPI-bypass tool — hardcoded so no fetched block list can pull it back into the tunnel; kept in sync with zapret's Discord hostlist so no Discord domain leaks back through the proxy.
var discordDomains = []string{
	"discord.com", "discord.gg", "discord.media", "discord.app", "discord.co",
	"discord.design", "discord.dev", "discord.gift", "discord.gifts", "discord.new",
	"discord.store", "discord.status", "discordapp.com", "discordapp.net", "discordcdn.com",
	"discordactivities.com", "discord-activities.com", "discordmerch.com",
	"discordpartygames.com", "discordsays.com", "discordsez.com", "discordstatus.com",
	"discord-attachments-uploads-prd.storage.googleapis.com",
}

func builtinDirect() []rules.Rule {
	out := make([]rules.Rule, 0, len(discordDomains))
	for _, d := range discordDomains {
		out = append(out, rules.Rule{Suffix: d, Action: rules.Direct})
	}
	return out
}
