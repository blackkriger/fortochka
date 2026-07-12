//go:build !windows

package main

import "log"

func runService()               { log.Fatal("service mode is only supported on windows") }
func doInstall() error          { return nil }
func doUninstall() error        { return nil }
func ensureService() bool       { return true }
func startEngineService() error { return nil }
func stopEngineService() error  { return nil }
func serviceInstalled() bool    { return false }
func launchElevated(string)     {}
