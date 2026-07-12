package wg

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

var ErrNotConnected = errors.New("wireguard: not connected")

type State int

const (
	Disconnected State = iota
	Connecting
	Connected
)

// Manager owns the active tunnel and lets it be (re)configured at runtime (e.g. on a new .conf import), and is safe for the proxy to call DialContext concurrently with Connect.
type Manager struct {
	mu       sync.Mutex
	dev      atomic.Pointer[Device]
	endpoint atomic.Pointer[string]
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Connect(c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dev, err := New(c)
	if err != nil {
		return err
	}
	old := m.dev.Swap(dev)
	ep := c.Endpoint
	m.endpoint.Store(&ep)
	if old != nil {
		old.Close()
	}
	return nil
}

func (m *Manager) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := m.dev.Load()
	if d == nil {
		return nil, ErrNotConnected
	}
	return d.DialContext(ctx, network, address)
}

func (m *Manager) Connected() bool { return m.dev.Load() != nil }

func (m *Manager) State() State {
	d := m.dev.Load()
	if d == nil {
		return Disconnected
	}
	if d.HandshakeOK() {
		return Connected
	}
	return Connecting
}

func (m *Manager) Endpoint() string {
	if s := m.endpoint.Load(); s != nil {
		return *s
	}
	return ""
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d := m.dev.Swap(nil); d != nil {
		d.Close()
	}
}
