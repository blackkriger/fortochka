//go:build !windows

package procnet

func ProcName(pid uint32) string            { return "" }
func TCPPortPID() map[uint16]uint32         { return nil }
func UDPPortPID() map[uint16]uint32         { return nil }
func RunningTCPApps() []string              { return nil }
func ResetAppTCP(names map[string]bool) int { return 0 }
