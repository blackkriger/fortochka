//go:build !windows

package apptunnel

import (
	"context"
	"net"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Engine struct{ Ready func() bool }

func New(dial Dialer, logf func(string, ...any)) *Engine { return &Engine{} }

func (e *Engine) SetApps(names []string) {}
func (e *Engine) Suspend()               {}
func (e *Engine) Active() bool           { return false }
func (e *Engine) Stop()                  {}

func EnsureFirewallRule() error { return nil }

func RunningNetApps() []string { return nil }

func RunningNetAppsNamed() map[string]string { return nil }
