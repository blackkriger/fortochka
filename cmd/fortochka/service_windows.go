//go:build windows

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"fortochka/internal/autostart"
	"fortochka/internal/config"
	"fortochka/internal/daemon"
	"fortochka/internal/ipc"
	"fortochka/internal/paths"
	"fortochka/internal/windivert"
)

const (
	serviceName = "fortochka"
	serviceDesc = "fortochka split-tunnel engine: WireGuard/AmneziaWG tunnel and per-app routing."
)

const errServiceAlreadyRunning = windows.Errno(1056)

type serviceHandler struct{}

func (serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	dir := paths.DataDir()
	if f := setupServiceLogging(dir); f != nil {
		defer f.Close()
	}
	log.Printf("========== fortochka service start ==========")

	if err := windivert.Init(dir); err != nil {
		log.Printf("service: windivert init: %v", err)
	}
	if err := config.EnsureDefault(filepath.Join(dir, "fortochka.yaml")); err != nil {
		log.Printf("service: write default config: %v", err)
	}

	d, err := daemon.New(loadServiceConfig(dir), dir)
	if err != nil {
		log.Printf("service: engine start failed: %v", err)
		changes <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	defer d.Close()

	srv, err := ipc.Serve(makeHandler(d))
	if err != nil {
		log.Printf("service: ipc serve failed: %v", err)
		changes <- svc.Status{State: svc.Stopped}
		return true, 1
	}
	defer srv.Close()

	changes <- svc.Status{State: svc.Running, Accepts: accepts}
	log.Printf("service: running")

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			log.Printf("service: stop requested")
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		default:
			log.Printf("service: unexpected control %d", req.Cmd)
		}
	}
	return false, 0
}

func runService() {
	if err := svc.Run(serviceName, serviceHandler{}); err != nil {
		log.Fatalf("service run: %v", err)
	}
}

const (
	maxLogSize  = 20 * 1024 * 1024
	maxLogFiles = 2 // fortochka.log.1 and .2, so a day of history survives without unbounded growth
)

// rotatingLog keeps the log bounded while the service runs. Rotating only at startup was not enough: the service is meant to run for weeks, so the file grew until someone restarted it.
type rotatingLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func (w *rotatingLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return len(p), nil // pretend success: a logging problem must never break the engine
	}
	if w.size+int64(len(p)) > maxLogSize {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingLog) rotate() {
	w.f.Close()
	for i := maxLogFiles; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", w.path, i)
		if i == maxLogFiles {
			_ = os.Remove(older)
			continue
		}
		_ = os.Rename(older, fmt.Sprintf("%s.%d", w.path, i+1))
	}
	_ = os.Rename(w.path, w.path+".1")
	w.f, w.size = nil, 0
	if f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		w.f = f
	}
}

func (w *rotatingLog) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}

func setupServiceLogging(dir string) io.Closer {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	path := filepath.Join(dir, "fortochka.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil
	}
	w := &rotatingLog{path: path, f: f}
	if fi, err := f.Stat(); err == nil {
		w.size = fi.Size()
	}
	log.SetOutput(w)
	return w
}

func loadServiceConfig(dir string) *config.Config {
	p := filepath.Join(dir, "fortochka.yaml")
	if c, err := config.Load(p); err == nil {
		log.Printf("service: config loaded from %s", p)
		return c
	} else {
		log.Printf("service: config %s: %v — using defaults", p, err)
	}
	return config.Default()
}

// doInstall installs (or repairs) and starts the service, grants the user start/stop rights, and clears leftover tray autostart, self-elevating first if needed.
func doInstall() error {
	if !isAdmin() {
		launchElevated("-install")
		return nil
	}
	dir := paths.DataDir()
	if f := setupServiceLogging(dir); f != nil {
		defer f.Close()
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	migrateOldData(dir)
	if err := installService(exe); err != nil {
		return err
	}
	grantDataDirAccess(dir)
	grantServiceControl()   // let the non-elevated tray start/stop the service
	_ = autostart.Disable() // the tray no longer auto-starts; clear old Run key / task
	log.Printf("install: done")
	return nil
}

// migrateOldData copies tunnel, state and rules from the old single-exe per-user dir to the shared data dir so upgrades keep them; best effort, never overwrites.
func migrateOldData(newDir string) {
	base, err := os.UserConfigDir()
	if err != nil {
		return
	}
	oldDir := filepath.Join(base, "fortochka")
	for _, name := range []string{"tunnel.conf", "state.json", "rules.txt"} {
		dst := filepath.Join(newDir, name)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(oldDir, name))
		if err != nil {
			continue
		}
		if err := os.WriteFile(dst, data, 0o644); err == nil {
			log.Printf("install: migrated %s from %s", name, oldDir)
		}
	}
}

// grantDataDirAccess gives the built-in Users group (S-1-5-32-545) inherited Modify on the LocalSystem-owned data dir so the non-elevated tray can read logs and edit rules.txt.
func grantDataDirAccess(dir string) {
	cmd := exec.Command("icacls", dir, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	_ = cmd.Run()
}

// doUninstall removes the running parts of fortochka — the service, the WinDivert driver we loaded, the firewall rule, the tray autostart and any old first-run marker — but keeps the data dir (imported config, rules, state) so a later re-launch just works without re-importing. The exe ships in releases and is the user's to delete.
func doUninstall() error {
	if !isAdmin() {
		launchElevated("-uninstall")
		return nil
	}
	uninstallService()      // clean stop (closes WinDivert) then delete
	removeWinDivertDriver() // our leftover driver, only if nothing else still holds it
	removeFirewallRule()    // belt-and-suspenders
	_ = autostart.Disable() // tray Run key + any leftover scheduled task
	removeMarker()          // old first-run marker from earlier builds
	log.Printf("uninstall: service removed, data kept for next launch")
	return nil
}

func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd
}

// removeWinDivertDriver stops+deletes the WinDivert kernel driver, but only the instance we loaded (its .sys under our data dir) and only if nothing else still holds a handle — sc stop fails while in use, so a running zapret sharing WinDivert is left untouched.
func removeWinDivertDriver() {
	out, err := hiddenCmd("sc.exe", "qc", "WinDivert").Output()
	if err != nil {
		return
	}
	if !strings.Contains(strings.ToLower(string(out)), strings.ToLower(paths.DataDir())) {
		return
	}
	if hiddenCmd("sc.exe", "stop", "WinDivert").Run() == nil {
		hiddenCmd("sc.exe", "delete", "WinDivert").Run()
	}
}

func removeFirewallRule() {
	hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=fortochka-redirect").Run()
}

func removeMarker() {
	hiddenCmd("reg.exe", "delete", `HKCU\Software\fortochka`, "/f").Run()
}

func installService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()

	// CreateService uses exepath+args while UpdateConfig uses cfg.BinaryPathName, so set both to make fresh install and repair land on the same "<exe> -service".
	cfg := mgr.Config{
		DisplayName:    "fortochka",
		Description:    serviceDesc,
		StartType:      mgr.StartAutomatic,
		BinaryPathName: fmt.Sprintf("%s -service", windows.EscapeArg(exe)),
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, exe, cfg, "-service")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		log.Printf("service installed")
	} else {
		// Running a newer build in place has to actually take over: repointing the config alone would leave the previous binary running, still holding its file, while the log claims the upgrade happened.
		// EqualFold because Windows paths are case-insensitive: the same binary reached through differently-cased text is not an upgrade.
		if cur, cerr := s.Config(); cerr == nil && !strings.EqualFold(cur.BinaryPathName, cfg.BinaryPathName) {
			log.Printf("service: replacing %s", cur.BinaryPathName)
			stopAndWait(s)
		}
		if err := s.UpdateConfig(cfg); err != nil {
			s.Close()
			return fmt.Errorf("update service: %w", err)
		}
		log.Printf("service config updated")
	}
	defer s.Close()

	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)

	if err := s.Start(); err != nil {
		if err == errServiceAlreadyRunning {
			return nil
		}
		return fmt.Errorf("start service: %w", err)
	}
	log.Printf("service started")
	return nil
}

// stopAndWait asks the service to stop and gives it a few seconds, so whatever comes next sees it stopped instead of racing it.
func stopAndWait(s *mgr.Service) {
	if _, err := s.Control(svc.Stop); err != nil {
		return
	}
	for i := 0; i < 25; i++ {
		q, err := s.Query()
		if err != nil || q.State == svc.Stopped {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()

	stopAndWait(s)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	log.Printf("service removed")
	return nil
}

// ensureService makes sure the engine is reachable: if no service is installed at all, it installs one (launching fortochka means the user wants to VPN, which needs the engine); an installed-but-stopped service is left for the user to start from the Engine menu.
func ensureService() bool {
	if ipc.Available() {
		return true
	}
	if serviceInstalled() {
		log.Printf("tray: engine installed but stopped; use Engine ▸ Service to start it")
		return false
	}
	log.Printf("tray: no engine installed — installing")
	launchElevated("-install")
	for i := 0; i < 75; i++ { // up to ~15s for install + service start
		if ipc.Available() {
			log.Printf("tray: engine is up")
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func launchElevated(args string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	var argPtr *uint16
	if args != "" {
		argPtr, _ = windows.UTF16PtrFromString(args)
	}
	if err := windows.ShellExecute(0, verb, exePtr, argPtr, dir, windows.SW_HIDE); err != nil {
		log.Printf("tray: elevate (%s): %v", args, err)
	}
}

// makeHandler wraps the daemon with service-level commands (autostart) and stamps the current SCM StartType into every Status the tray polls.
func makeHandler(d *daemon.Daemon) ipc.Handler {
	return func(req ipc.Request) ipc.Response {
		var resp ipc.Response
		if req.Cmd == ipc.CmdSetAutostart {
			if err := setServiceStartType(req.On); err != nil {
				resp = ipc.Response{Error: err.Error()}
			} else {
				s := d.Status()
				resp = ipc.Response{OK: true, Status: &s}
			}
		} else {
			resp = d.Handle(req)
		}
		if resp.Status != nil {
			resp.Status.AutostartOn = serviceAutostartOn()
		}
		return resp
	}
}

// setServiceStartType flips the service's boot auto-start; as LocalSystem it reconfigures itself with no UAC on the tray side.
func setServiceStartType(auto bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return err
	}
	if auto {
		c.StartType = mgr.StartAutomatic
	} else {
		c.StartType = mgr.StartManual
	}
	return s.UpdateConfig(c)
}

func serviceAutostartOn() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return false
	}
	return c.StartType == mgr.StartAutomatic
}

// grantServiceControl adds only start (RP) + stop (WP) for the built-in Users group (IU) to the service DACL, letting the non-elevated tray toggle the engine without UAC or risking privilege escalation.
func grantServiceControl() {
	out, err := exec.Command("sc.exe", "sdshow", serviceName).Output()
	if err != nil {
		log.Printf("install: sdshow: %v", err)
		return
	}
	sddl := strings.TrimSpace(string(out))
	if !strings.HasPrefix(sddl, "D:") {
		return
	}
	const ace = "(A;;RPWP;;;IU)"
	if strings.Contains(sddl, ace) {
		return
	}
	if i := strings.Index(sddl, "S:"); i >= 0 {
		sddl = sddl[:i] + ace + sddl[i:]
	} else {
		sddl += ace
	}
	cmd := exec.Command("sc.exe", "sdset", serviceName, sddl)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	if err := cmd.Run(); err != nil {
		log.Printf("install: sdset: %v", err)
	}
}

// serviceInstalled reports whether the service is registered; SERVICE_QUERY_STATUS is in the default DACL for interactive users, so no elevation is needed.
func serviceInstalled() bool {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(h)
	return true
}

// startEngineService / stopEngineService are driven by the non-elevated tray via the rights granted in grantServiceControl (no UAC once installed).
func startEngineService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	if err := windows.StartService(h, 0, nil); err != nil && err != errServiceAlreadyRunning {
		return err
	}
	return nil
}

func stopEngineService() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	var status windows.SERVICE_STATUS
	return windows.ControlService(h, windows.SERVICE_CONTROL_STOP, &status)
}
