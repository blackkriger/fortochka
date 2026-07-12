//go:build !windows

package ipc

import (
	"errors"
	"io"
)

var errUnsupported = errors.New("ipc: named pipe is only supported on windows")

func Serve(h Handler) (io.Closer, error) { return nil, errUnsupported }
func Dial() (io.ReadWriteCloser, error)  { return nil, errUnsupported }
func Call(req Request) (Response, error) { return Response{}, errUnsupported }
func Available() bool                    { return false }
