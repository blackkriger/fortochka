//go:build !windows

package apptunnel

import (
	"context"
	"net"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Engine struct{}

func New(dial Dialer, logf func(string, ...any)) *Engine { return &Engine{} }

func (e *Engine) SetApps(names []string) {}
func (e *Engine) Stop()                  {}

func RunningNetApps() []string { return nil }
