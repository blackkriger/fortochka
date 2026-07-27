// Package ipc is the control channel between the fortochka service and tray: newline-delimited JSON over a local named pipe, with the tray dialing a fresh connection per call.
package ipc

import (
	"bufio"
	"encoding/json"
	"io"
)

// PipeName is the local named pipe the service listens on.
const PipeName = `\\.\pipe\fortochka`

// maxRequest caps a single request so a client can't exhaust service memory with an unbounded line (a real request is a few KB at most).
const maxRequest = 4 << 20

// Tunnel states, mirrored as strings so the tray needs no engine imports.
const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
)

// Commands.
const (
	CmdStatus       = "status"
	CmdConnect      = "connect"
	CmdDisconnect   = "disconnect"
	CmdImport       = "import"       // Data = raw .conf contents
	CmdSetApps      = "setapps"      // Apps = exe base names to route
	CmdSetAutostart = "setautostart" // On = start the service at boot (SCM StartType)
)

type Request struct {
	Cmd  string   `json:"cmd"`
	Apps []string `json:"apps,omitempty"`
	Data string   `json:"data,omitempty"`
	On   bool     `json:"on,omitempty"`
}

type Response struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

// Status is the full engine snapshot the tray renders from.
type Status struct {
	State        string            `json:"state"`
	Endpoint     string            `json:"endpoint"`
	HasConfig    bool              `json:"has_config"`
	TunnelWanted bool              `json:"tunnel_wanted"`
	Apps         []string          `json:"apps"`
	RunningApps  []string          `json:"running_apps"`
	AppNames     map[string]string `json:"app_names,omitempty"` // exe base name → display name
	PACURL       string            `json:"pac_url"`             // for the tray's per-user system proxy
	ProxyAddr    string            `json:"proxy_addr"`          // SOCKS5/HTTP mixed proxy address
	AutostartOn  bool              `json:"autostart_on"`        // service SCM StartType == Automatic
}

// Handler processes one request and returns a response (server side).
type Handler func(Request) Response

// serveConn reads newline-delimited requests off a single connection and writes one response per request until the peer closes.
func serveConn(rw io.ReadWriter, h Handler) {
	r := bufio.NewReader(io.LimitReader(rw, maxRequest))
	w := bufio.NewWriter(rw)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var req Request
			if json.Unmarshal(line, &req) == nil {
				resp := h(req)
				if b, e := json.Marshal(resp); e == nil {
					w.Write(b)
					w.WriteByte('\n')
					w.Flush()
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// call writes one request and reads one response.
func call(rw io.ReadWriter, req Request) (Response, error) {
	b, _ := json.Marshal(req)
	b = append(b, '\n')
	if _, err := rw.Write(b); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(rw).ReadBytes('\n')
	if len(line) == 0 && err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
