//go:build !windows

package main

type console struct{}

func newConsole(mux *logMux) *console { return &console{} }

func (c *console) toggle() {}
