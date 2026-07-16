package main

import (
	_ "embed"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"fortochka/internal/filedialog"
	"fortochka/internal/ipc"
	"fortochka/internal/paths"
	"fortochka/internal/sysproxy"
	"fortochka/internal/userrules"
)

// Disconnected reuses the plain exe icon; only the status colours are separate.
//
//go:embed fortochka.ico
var iconDisconnected []byte

//go:embed st_connecting.ico
var iconConnecting []byte

//go:embed st_connected.ico
var iconConnected []byte

// version is stamped at build time via: -ldflags "-X main.version=0.1.0"
var version = "dev"

func main() {
	var (
		svcMode   = flag.Bool("service", false, "run as the Windows service (used by the SCM)")
		install   = flag.Bool("install", false, "install and start the engine service, then enable the tray")
		uninstall = flag.Bool("uninstall", false, "stop and remove the engine service")
	)
	flag.Parse()

	switch {
	case *svcMode:
		runService()
	case *install:
		if err := doInstall(); err != nil {
			log.Fatalf("install: %v", err)
		}
	case *uninstall:
		if err := doUninstall(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
	default:
		runTray()
	}
}

func runTray() {
	mux, logFile := setupTrayLogging()
	if logFile != nil {
		defer logFile.Close()
	}
	logConsole := newConsole(mux)
	log.Printf("========== fortochka tray start (v%s) ==========", version)

	dir := paths.DataDir()
	ui := &tray{
		console:   logConsole,
		dir:       dir,
		rulesPath: userrules.Path(dir),
		appItems:  map[string]*systray.MenuItem{},
	}
	if exe, err := os.Executable(); err == nil {
		ui.selfExe = strings.ToLower(filepath.Base(exe))
	}
	if !ensureService() {
		log.Printf("tray: engine service is not reachable; the tray will keep retrying")
	}
	systray.Run(ui.onReady, ui.onExit)
}

// tray is a thin client: renders ipc.Status and forwards user actions to the engine, owning only the per-user system proxy that can't live in the LocalSystem service.
type tray struct {
	console   *console
	dir       string
	rulesPath string
	selfExe   string

	mTunnel  *systray.MenuItem
	mStatus  *systray.MenuItem
	mImport  *systray.MenuItem
	mApps    *systray.MenuItem
	mAddSite *systray.MenuItem
	mServer  *systray.MenuItem
	mPAC     *systray.MenuItem
	mSocks   *systray.MenuItem

	mSvcInstall *systray.MenuItem
	mSvc        *systray.MenuItem
	mSvcAuto    *systray.MenuItem

	mu        sync.Mutex
	cur       ipc.Status
	lastState string
	proxyOn   bool
	serviceUp bool
	appItems  map[string]*systray.MenuItem
}

func (t *tray) onReady() {
	systray.SetTitle("f")
	systray.SetTooltip("fortochka")
	systray.SetIcon(iconDisconnected)

	t.mStatus = systray.AddMenuItem("…", "Tunnel status")
	t.mStatus.Disable()
	t.mTunnel = systray.AddMenuItem("Connect", "Connect / disconnect the tunnel")
	go func() {
		for range t.mTunnel.ClickedCh {
			t.toggleTunnel()
		}
	}()
	systray.AddSeparator()

	t.mImport = systray.AddMenuItem("Import AmneziaWG config…", "Load an AmneziaWG .conf file")
	mInfo := systray.AddMenuItem("Connection info", "Local endpoints")
	t.mServer = mInfo.AddSubMenuItem("Server:  —", "AmneziaWG server endpoint")
	t.mServer.Disable()
	t.mPAC = mInfo.AddSubMenuItem("PAC:  —", "System proxy auto-config URL")
	t.mPAC.Disable()
	t.mSocks = mInfo.AddSubMenuItem("SOCKS5:  —", "Point Telegram here manually")
	t.mSocks.Disable()
	systray.AddSeparator()

	t.mAddSite = systray.AddMenuItem("Route address through tunnel…", "Add a domain or IP address to the routed list")
	t.mApps = systray.AddMenuItem("Route app through tunnel", "Send a whole app's traffic through the tunnel")

	mService := systray.AddMenuItem("Service", "Background service control")
	t.mSvcInstall = mService.AddSubMenuItem("Install service", "Install the background engine (asks for admin)")
	t.mSvc = mService.AddSubMenuItem("Service: …", "Turn fortochka fully off — stop and remove the engine")
	t.mSvcAuto = mService.AddSubMenuItemCheckbox("Start with Windows", "Start the engine service at boot", false)
	t.mSvcInstall.Hide()

	mMore := systray.AddMenuItem("More", "Folder and logs")
	mOpenDir := mMore.AddSubMenuItem("Open program folder", "Open the fortochka data folder")
	mLog := mMore.AddSubMenuItem("Show / hide log console", "Toggle the live log window")
	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Close the tray (the engine keeps running)")

	go func() {
		for {
			select {
			case <-t.mImport.ClickedCh:
				t.importConfig()
			case <-t.mAddSite.ClickedCh:
				openEditor(t.rulesPath)
			case <-mOpenDir.ClickedCh:
				openFolder(t.dir)
			case <-mLog.ClickedCh:
				t.console.toggle()
			case <-t.mSvcInstall.ClickedCh:
				t.installEngine()
			case <-t.mSvc.ClickedCh:
				t.toggleService()
			case <-t.mSvcAuto.ClickedCh:
				t.toggleServiceAutostart()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()

	t.updateEngineMenu(ipc.Available())
	go t.watchStatus()
}

func (t *tray) onExit() {
	// The engine (and proxy) keeps running as a service, so leave the system proxy as-is on exit.
	log.Printf("========== fortochka tray exit ==========")
}

// watchStatus polls the engine once a second and re-renders the tray.
func (t *tray) watchStatus() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		st, ok := status()
		if ok {
			t.apply(st)
		} else {
			t.setOffline()
		}
		t.updateEngineMenu(ok)
	}
}

// updateEngineMenu shows "Install service" when absent, else the on/off toggle and autostart; autostart is disabled while stopped since only the running service can toggle it.
func (t *tray) updateEngineMenu(running bool) {
	if !serviceInstalled() {
		t.mSvcInstall.Show()
		t.mSvc.Hide()
		t.mSvcAuto.Hide()
		return
	}
	t.mSvcInstall.Hide()
	t.mSvc.Show()
	t.mSvcAuto.Show()
	if running {
		t.mSvc.SetTitle("fortochka is on — click to turn off")
		t.mSvcAuto.Enable()
	} else {
		t.mSvc.SetTitle("fortochka is off — click to turn on")
		t.mSvcAuto.Disable()
	}
}

func (t *tray) apply(st ipc.Status) {
	t.mu.Lock()
	t.cur = st
	t.lastState = st.State
	t.serviceUp = true
	t.mu.Unlock()

	systray.SetIcon(iconForName(st.State))
	systray.SetTooltip("fortochka — " + stateText(st.State))

	t.mTunnel.SetTitle(tunnelLabel(st))
	t.mTunnel.SetTooltip("Server: " + dash(st.Endpoint))
	if st.State == ipc.StateConnecting || (st.State == ipc.StateDisconnected && !st.HasConfig) {
		t.mTunnel.Disable()
	} else {
		t.mTunnel.Enable()
	}
	t.mStatus.SetTitle(headerLabel(st))
	t.mServer.SetTitle("Server:  " + dash(st.Endpoint))
	t.mPAC.SetTitle("PAC:  " + dash(st.PACURL))
	t.mSocks.SetTitle("SOCKS5:  " + dash(st.ProxyAddr))

	if st.AutostartOn {
		t.mSvcAuto.Check()
	} else {
		t.mSvcAuto.Uncheck()
	}

	// engine is reachable, so its IPC-backed actions are usable again
	t.mImport.Enable()
	t.mApps.Enable()
	t.mAddSite.Enable()

	t.syncApps(st)
	t.syncProxy(st)
}

// syncProxy sets the per-user WinINET proxy on connect and clears it otherwise, under t.mu so the poll and click handlers can't race on proxyOn.
func (t *tray) syncProxy(st ipc.Status) {
	t.mu.Lock()
	defer t.mu.Unlock()
	want := st.State == ipc.StateConnected && st.PACURL != ""
	switch {
	case want && !t.proxyOn:
		if err := sysproxy.Enable(st.PACURL); err != nil {
			log.Printf("tray: system proxy enable: %v", err)
		} else {
			t.proxyOn = true
		}
	case !want && t.proxyOn:
		_ = sysproxy.Disable()
		t.proxyOn = false
	}
}

// hiddenApps never appear in the route-through-tunnel list: Discord is pinned direct in the engine, so offering to tunnel it would only mislead.
var hiddenApps = map[string]bool{"discord.exe": true}

// syncApps keeps the "Route app through tunnel" submenu in step with the engine, listing running and selected apps and reflecting which are routed.
func (t *tray) syncApps(st ipc.Status) {
	selected := map[string]bool{}
	for _, a := range st.Apps {
		selected[a] = true
	}
	set := map[string]bool{}
	for _, a := range st.RunningApps {
		set[a] = true
	}
	for a := range selected {
		set[a] = true
	}
	for _, name := range sortedKeys(set) {
		if name == "" || name == t.selfExe || hiddenApps[name] {
			continue
		}
		t.ensureAppItem(name, selected[name])
	}

	t.mu.Lock()
	items := make(map[string]*systray.MenuItem, len(t.appItems))
	for k, v := range t.appItems {
		items[k] = v
	}
	t.mu.Unlock()
	for name, item := range items {
		if selected[name] {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
}

func (t *tray) ensureAppItem(name string, checked bool) {
	t.mu.Lock()
	if _, ok := t.appItems[name]; ok {
		t.mu.Unlock()
		return
	}
	item := t.mApps.AddSubMenuItemCheckbox(name, "Route "+name+" through the tunnel", checked)
	t.appItems[name] = item
	t.mu.Unlock()
	go func() {
		for range item.ClickedCh {
			t.toggleApp(name)
		}
	}()
}

func (t *tray) toggleApp(name string) {
	t.mu.Lock()
	sel := map[string]bool{}
	for _, a := range t.cur.Apps {
		sel[a] = true
	}
	if sel[name] {
		delete(sel, name)
	} else {
		sel[name] = true
	}
	apps := sortedKeys(sel)
	t.mu.Unlock()
	if st, ok := command(ipc.Request{Cmd: ipc.CmdSetApps, Apps: apps}); ok {
		log.Printf("tray: routed apps -> %v", apps)
		t.apply(st)
	}
}

func (t *tray) toggleTunnel() {
	t.mu.Lock()
	state, hasCfg := t.cur.State, t.cur.HasConfig
	t.mu.Unlock()
	var req ipc.Request
	switch state {
	case ipc.StateConnected, ipc.StateConnecting:
		req = ipc.Request{Cmd: ipc.CmdDisconnect}
	default:
		if !hasCfg {
			log.Printf("tray: no config to connect; import one first")
			return
		}
		req = ipc.Request{Cmd: ipc.CmdConnect}
	}
	if st, ok := command(req); ok {
		t.apply(st)
	}
}

func (t *tray) importConfig() {
	path, err := filedialog.Open("Select AmneziaWG config")
	if err != nil {
		log.Printf("import: dialog: %v", err)
		return
	}
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("import: read %s: %v", path, err)
		return
	}
	st, ok := command(ipc.Request{Cmd: ipc.CmdImport, Data: string(data)})
	if !ok {
		return
	}
	log.Printf("import: sent config (%d bytes)", len(data))
	t.apply(st)
}

// toggleService starts or stops the background engine via the SCM using the start/stop right granted at install (no UAC); no-op if the service isn't installed.
// toggleService turns fortochka fully off — it clears the system proxy, then removes the service, our WinDivert driver and the firewall rule, and closes the tray, so no fortochka process is left running. The imported config is kept, so relaunching the exe brings everything back.
func (t *tray) toggleService() {
	if !serviceInstalled() {
		log.Printf("tray: service not installed — install it first")
		return
	}
	t.mu.Lock()
	up := t.serviceUp
	t.mu.Unlock()
	if up {
		_ = sysproxy.Disable() // drop the PAC before the engine goes away so HTTP isn't left pointing at a dead proxy
		t.mu.Lock()
		t.proxyOn = false
		t.mu.Unlock()
		log.Printf("tray: turning fortochka off — removing service and closing tray")
		launchElevated("-uninstall")
		systray.Quit()
		return
	}
	if err := startEngineService(); err != nil {
		log.Printf("tray: start service: %v", err)
		return
	}
	log.Printf("tray: engine service starting")
}

// toggleServiceAutostart flips the service's boot auto-start; the running LocalSystem service reconfigures itself (no UAC), so it must be installed and running.
func (t *tray) toggleServiceAutostart() {
	if !serviceInstalled() {
		log.Printf("tray: service not installed")
		return
	}
	t.mu.Lock()
	want := !t.cur.AutostartOn
	up := t.serviceUp
	t.mu.Unlock()
	if !up {
		log.Printf("tray: start the engine before changing its autostart")
		return
	}
	if st, ok := command(ipc.Request{Cmd: ipc.CmdSetAutostart, On: want}); ok {
		log.Printf("tray: service autostart -> %v", want)
		t.apply(st)
	}
}

func (t *tray) installEngine() {
	log.Printf("tray: installing engine service (elevation)")
	launchElevated("-install")
}

func (t *tray) setOffline() {
	t.mu.Lock()
	t.lastState = ipc.StateDisconnected
	t.serviceUp = false
	if t.proxyOn {
		_ = sysproxy.Disable()
		t.proxyOn = false
	}
	t.mu.Unlock()
	systray.SetIcon(iconDisconnected)
	systray.SetTooltip("fortochka — engine not running")
	if t.mStatus != nil {
		t.mStatus.SetTitle("Engine off")
	}
	if t.mTunnel != nil {
		t.mTunnel.SetTitle("Connect")
		t.mTunnel.Disable()
	}
	// these all go through the engine over IPC, so grey them out until it's up
	if t.mImport != nil {
		t.mImport.Disable()
	}
	if t.mApps != nil {
		t.mApps.Disable()
	}
	if t.mAddSite != nil {
		t.mAddSite.Disable()
	}
}

func status() (ipc.Status, bool) {
	resp, err := ipc.Call(ipc.Request{Cmd: ipc.CmdStatus})
	if err != nil || resp.Status == nil {
		return ipc.Status{}, false
	}
	return *resp.Status, true
}

func command(req ipc.Request) (ipc.Status, bool) {
	resp, err := ipc.Call(req)
	if err != nil {
		log.Printf("tray: ipc %s: %v", req.Cmd, err)
		return ipc.Status{}, false
	}
	if resp.Error != "" {
		log.Printf("tray: %s: %s", req.Cmd, resp.Error)
	}
	if resp.Status != nil {
		return *resp.Status, true
	}
	return ipc.Status{}, false
}

func iconForName(s string) []byte {
	switch s {
	case ipc.StateConnected:
		return iconConnected
	case ipc.StateConnecting:
		return iconConnecting
	default:
		return iconDisconnected
	}
}

func stateText(s string) string {
	switch s {
	case ipc.StateConnected:
		return "connected"
	case ipc.StateConnecting:
		return "connecting…"
	default:
		return "not connected"
	}
}

// headerLabel is the non-clickable status line at the top of the menu.
func headerLabel(st ipc.Status) string {
	switch st.State {
	case ipc.StateConnected:
		return "Connected"
	case ipc.StateConnecting:
		return "Connecting…"
	default:
		if !st.HasConfig {
			return "No config imported"
		}
		return "Disconnected"
	}
}

func tunnelLabel(st ipc.Status) string {
	switch st.State {
	case ipc.StateConnected:
		return "Disconnect"
	case ipc.StateConnecting:
		return "Connecting…"
	default:
		return "Connect"
	}
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setupTrayLogging() (*logMux, *os.File) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	dir := paths.DataDir()
	if dir == "" {
		mux := newLogMux(os.Stderr)
		log.SetOutput(mux)
		return mux, nil
	}
	path := filepath.Join(dir, "fortochka-tray.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5*1024*1024 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		mux := newLogMux(os.Stderr)
		log.SetOutput(mux)
		log.Printf("logging: cannot open %s: %v", path, err)
		return mux, nil
	}
	mux := newLogMux(f, os.Stderr)
	log.SetOutput(mux)
	log.Printf("========== fortochka tray session start (log: %s) ==========", path)
	return mux, f
}

func openFolder(dir string) {
	if err := exec.Command("explorer.exe", dir).Start(); err != nil {
		log.Printf("tray: open folder: %v", err)
	}
}

func openEditor(path string) {
	if err := exec.Command("notepad.exe", path).Start(); err != nil {
		log.Printf("tray: open editor: %v", err)
	}
}
