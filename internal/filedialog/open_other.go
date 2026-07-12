//go:build !windows

package filedialog

func Open(title string) (string, error) { return "", nil }
