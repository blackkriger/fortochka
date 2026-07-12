//go:build windows

package ipc

import (
	"io"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pipeAccessDuplex          = 0x00000003
	pipeTypeByte              = 0x00000000
	pipeUnlimitedInstances    = 255
	pipeBufSize               = 64 * 1024
	fileFlagFirstPipeInstance = 0x00080000
)

// SYSTEM and Administrators get full control; interactive users may read/write so a non-elevated tray can talk to the LocalSystem service.
const pipeSDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

const (
	errFileNotFound     = windows.Errno(2)
	errBrokenPipe       = windows.Errno(109)
	errPipeBusy         = windows.Errno(231)
	errNoData           = windows.Errno(232)
	errPipeNotConnected = windows.Errno(233)
	errPipeConnected    = windows.Errno(535)
)

type pipeConn struct{ h windows.Handle }

func (c *pipeConn) Read(p []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(c.h, p, &done, nil)
	if err != nil {
		if err == errBrokenPipe || err == errPipeNotConnected || err == errNoData {
			return int(done), io.EOF
		}
		return int(done), err
	}
	if done == 0 {
		return 0, io.EOF
	}
	return int(done), nil
}

func (c *pipeConn) Write(p []byte) (int, error) {
	var done uint32
	err := windows.WriteFile(c.h, p, &done, nil)
	return int(done), err
}

func (c *pipeConn) Close() error { return windows.CloseHandle(c.h) }

type pipeServer struct {
	name *uint16
	sa   *windows.SecurityAttributes
	h    Handler
	done chan struct{}
}

// Serve starts a named-pipe server in the background; Close stops accepting new connections. Safe to call once from the service.
func Serve(h Handler) (io.Closer, error) {
	name, err := windows.UTF16PtrFromString(PipeName)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	s := &pipeServer{name: name, sa: sa, h: h, done: make(chan struct{})}
	go s.loop()
	return s, nil
}

func (s *pipeServer) Close() error {
	close(s.done)
	return nil
}

func (s *pipeServer) loop() {
	first := true // the first instance claims the name; refuse to attach to a squatter
	for {
		select {
		case <-s.done:
			return
		default:
		}
		mode := uint32(pipeAccessDuplex)
		if first {
			mode |= fileFlagFirstPipeInstance
		}
		h, err := windows.CreateNamedPipe(s.name,
			mode, pipeTypeByte, pipeUnlimitedInstances,
			pipeBufSize, pipeBufSize, 0, s.sa)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		first = false
		if err := windows.ConnectNamedPipe(h, nil); err != nil && err != errPipeConnected {
			windows.CloseHandle(h)
			continue
		}
		go func(handle windows.Handle) {
			serveConn(&pipeConn{h: handle}, s.h)
			windows.FlushFileBuffers(handle)
			windows.DisconnectNamedPipe(handle)
			windows.CloseHandle(handle)
		}(h)
	}
}

// Dial opens a fresh client connection, retrying briefly on busy (all instances taken) and not-found (the microsecond gap between the server's instances, or two concurrent callers) — capped at ~200ms so polling stays responsive when the service is genuinely down.
func Dial() (io.ReadWriteCloser, error) {
	name, err := windows.UTF16PtrFromString(PipeName)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 5; i++ {
		h, err := windows.CreateFile(name,
			windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			return &pipeConn{h: h}, nil
		}
		if err == errPipeBusy || err == errFileNotFound {
			time.Sleep(40 * time.Millisecond)
			continue
		}
		return nil, err
	}
	return nil, errFileNotFound
}

// Call runs one request/response over a fresh connection.
func Call(req Request) (Response, error) {
	conn, err := Dial()
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	return call(conn, req)
}

// Available reports whether the service pipe is reachable right now.
func Available() bool {
	conn, err := Dial()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
