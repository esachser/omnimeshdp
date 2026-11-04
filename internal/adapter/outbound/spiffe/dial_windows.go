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

	if strings.HasPrefix(rawAddr, `\\spire-agent\`) {
		address := `\\.\pipe\spire-agent\` + strings.TrimPrefix(rawAddr, `\\spire-agent\`)
		return address, func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, addr)
		}
	} else if strings.HasPrefix(rawAddr, `\\spire-agent-admin`) {
		address := `\\.\pipe\` + strings.TrimPrefix(rawAddr, `\\`)
		return address, func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, addr)
		}
	} else if strings.HasPrefix(rawAddr, `\\.\pipe\`) {
		return rawAddr, func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, addr)
		}
	} else if strings.HasPrefix(rawAddr, `\\`) {
		address := `\\.\pipe\` + strings.TrimPrefix(rawAddr, `\\`)
		return address, func(ctx context.Context, addr string) (net.Conn, error) {
			return winio.DialPipeContext(ctx, addr)
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

