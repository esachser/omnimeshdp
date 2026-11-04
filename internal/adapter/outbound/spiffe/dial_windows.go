//go:build windows

package spiffe

import (
	"context"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

func getSpireDialer(rawAddr string) (string, func(context.Context, string) (net.Conn, error)) {
	if after, ok := strings.CutPrefix(rawAddr, "npipe://"); ok {
		rawAddr = after
	}
	if after, ok := strings.CutPrefix(rawAddr, "npipe:"); ok {
		rawAddr = after
	}

	if strings.HasPrefix(rawAddr, `\\.\pipe\`) {
		addrToReturn := "passthrough:" + rawAddr
		return addrToReturn, func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, rawAddr)
		}
	} else if strings.HasPrefix(rawAddr, `\\`) {
		addr := strings.TrimPrefix(rawAddr, `\\`)
		address := `\\.\pipe\` + addr
		addrToReturn := "passthrough:" + address
		return addrToReturn, func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, address)
		}
	} else if strings.HasPrefix(rawAddr, "unix://") || strings.HasPrefix(rawAddr, "unix:") {
		address := strings.TrimPrefix(strings.TrimPrefix(rawAddr, "unix://"), "unix:")
		return address, func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}
	}

	address := strings.TrimPrefix(rawAddr, "tcp://")
	return address, nil
}
