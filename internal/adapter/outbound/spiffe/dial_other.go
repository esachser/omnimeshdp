//go:build !windows

package spiffe

import (
	"context"
	"net"
	"strings"
)

func getSpireDialer(rawAddr string) (string, func(context.Context, string) (net.Conn, error)) {
	if strings.HasPrefix(rawAddr, "unix://") || strings.HasPrefix(rawAddr, "unix:") {
		address := strings.TrimPrefix(strings.TrimPrefix(rawAddr, "unix://"), "unix:")
		return address, func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}
	}
	if strings.HasPrefix(rawAddr, "/") {
		return rawAddr, func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}
	}

	address := strings.TrimPrefix(rawAddr, "tcp://")
	return address, nil
}

