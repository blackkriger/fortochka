//go:build windows

package main

import (
	"log"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// console is the on-demand log window: allocated the first time the user asks (the app is a GUI with no console at launch), then just hidden/shown.
type console struct {
	mu        sync.Mutex
	mux       *logMux
	allocated bool
	visible   bool
}

func newConsole(mux *logMux) *console { return &console{mux: mux} }

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	user32c              = windows.NewLazySystemDLL("user32.dll")
	procAllocConsole     = kernel32.NewProc("AllocConsole")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procSetConsoleTitle  = kernel32.NewProc("SetConsoleTitleW")
	procShowWindow       = user32c.NewProc("ShowWindow")
	procGetSystemMenu    = user32c.NewProc("GetSystemMenu")
	procDeleteMenu       = user32c.NewProc("DeleteMenu")
)

const (
	swHide  = 0
	swShow  = 5
	scClose = 0xF060
)

func (c *console) toggle() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.allocated {
		if r, _, _ := procAllocConsole.Call(); r == 0 {
			log.Printf("logconsole: AllocConsole failed")
			return
		}
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			log.Printf("logconsole: open CONOUT$: %v", err)
			return
		}
		if p, err := windows.UTF16PtrFromString("fortochka — log"); err == nil {
			procSetConsoleTitle.Call(uintptr(unsafe.Pointer(p)))
		}
		disableConsoleClose() // closing the window must not kill the app
		c.mux.Add(out)
		c.allocated = true
		c.visible = true
		log.Printf("logconsole: attached — live log follows")
		return
	}

	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	if c.visible {
		procShowWindow.Call(hwnd, swHide)
	} else {
		procShowWindow.Call(hwnd, swShow)
	}
	c.visible = !c.visible
}

func disableConsoleClose() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	if hmenu, _, _ := procGetSystemMenu.Call(hwnd, 0); hmenu != 0 {
		procDeleteMenu.Call(hmenu, scClose, 0)
	}
}
