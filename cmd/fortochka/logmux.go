package main

import (
	"io"
	"sync"
)

// logMux fans log output out to a mutable set of writers, so the live log console can be attached at runtime without disturbing the file writer.
type logMux struct {
	mu sync.Mutex
	ws []io.Writer
}

func newLogMux(ws ...io.Writer) *logMux {
	return &logMux{ws: ws}
}

func (m *logMux) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.ws {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

func (m *logMux) Add(w io.Writer) {
	m.mu.Lock()
	m.ws = append(m.ws, w)
	m.mu.Unlock()
}
