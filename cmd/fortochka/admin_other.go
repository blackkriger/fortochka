//go:build !windows

package main

func isAdmin() bool     { return true }
func ensureAdmin() bool { return true }
