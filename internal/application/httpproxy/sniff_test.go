package httpproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestSniffProtocol_HTTP1AndHTTP2(t *testing.T) {
	t.Run("detects HTTP/2 preface delivered 1 byte at a time", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		peek := NewPeekableConn(serverConn)

		go func() {
			for i := 0; i < len(H2Preface); i++ {
				_, _ = clientConn.Write(H2Preface[i : i+1])
				time.Sleep(time.Millisecond)
			}
		}()

		proto := peek.Sniff(context.Background(), 500*time.Millisecond, 4096)
		if proto != model.ProtocolHTTP2 {
			t.Fatalf("expected ProtocolHTTP2, got %q", proto)
		}

		// All 24 bytes must replay intact.
		got := make([]byte, len(H2Preface))
		if _, err := io.ReadFull(peek, got); err != nil {
			t.Fatalf("failed to read replayed HTTP/2 preface: %v", err)
		}
		if !bytes.Equal(got, H2Preface) {
			t.Fatalf("replayed bytes mismatch: got %q, want %q", got, H2Preface)
		}
	})

	t.Run("detects HTTP/1.1 and HTTP/1.0 request lines", func(t *testing.T) {
		samples := []string{
			"GET /api/v1/items?a=1 HTTP/1.1\r\nHost: svc.mesh\r\n\r\n",
			"POST /submit HTTP/1.0\r\nContent-Length: 0\r\n\r\n",
			"OPTIONS * HTTP/1.1\r\nHost: svc.mesh\r\n\r\n",
		}
		for _, raw := range samples {
			clientConn, serverConn := net.Pipe()
			peek := NewPeekableConn(serverConn)

			go func(payload string) {
				_, _ = clientConn.Write([]byte(payload))
				_ = clientConn.Close()
			}(raw)

			proto := peek.Sniff(context.Background(), 200*time.Millisecond, 4096)
			if proto != model.ProtocolHTTP1 {
				t.Fatalf("expected ProtocolHTTP1 for %q, got %q", raw, proto)
			}
			replayed, err := io.ReadAll(peek)
			if err != nil {
				t.Fatalf("failed reading replayed HTTP/1 payload: %v", err)
			}
			if string(replayed) != raw {
				t.Fatalf("replayed mismatch: got %q, want %q", string(replayed), raw)
			}
			_ = serverConn.Close()
		}
	})
}

func TestSniffProtocol_TLSBinaryAndTimeoutFallback(t *testing.T) {
	t.Run("fast-fails TLS ClientHello well before sniff_timeout", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		peek := NewPeekableConn(serverConn)
		tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01}

		go func() {
			_, _ = clientConn.Write(tlsHello)
		}()

		start := time.Now()
		proto := peek.Sniff(context.Background(), 2*time.Second, 4096)
		elapsed := time.Since(start)
		if proto != model.ProtocolTCP {
			t.Fatalf("expected ProtocolTCP for TLS ClientHello, got %q", proto)
		}
		if elapsed > 300*time.Millisecond {
			t.Fatalf("expected immediate TLS fast-fail, took %v", elapsed)
		}

		got := make([]byte, len(tlsHello))
		if _, err := io.ReadFull(peek, got); err != nil {
			t.Fatalf("failed to read replayed TLS bytes: %v", err)
		}
		if !bytes.Equal(got, tlsHello) {
			t.Fatalf("TLS bytes mismatch: got %x, want %x", got, tlsHello)
		}
	})

	t.Run("falls back to TCP on non-HTTP ASCII, NUL bytes, and oversized line", func(t *testing.T) {
		cases := [][]byte{
			[]byte("SSH-2.0-OpenSSH_9.0\r\n"),
			[]byte("GET /\x00bad HTTP/1.1\r\n"),
			bytes.Repeat([]byte("A"), 128), // exceeds maxBytes=64 without CRLF
		}
		for _, payload := range cases {
			clientConn, serverConn := net.Pipe()
			peek := NewPeekableConn(serverConn)
			go func(p []byte) {
				_, _ = clientConn.Write(p)
				_ = clientConn.Close()
			}(payload)

			proto := peek.Sniff(context.Background(), 200*time.Millisecond, 64)
			if proto != model.ProtocolTCP {
				t.Fatalf("expected ProtocolTCP for %q, got %q", payload, proto)
			}
			got, err := io.ReadAll(peek)
			if err != nil {
				t.Fatalf("read replayed bytes failed: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("replayed bytes mismatch: got %x, want %x", got, payload)
			}
			_ = serverConn.Close()
		}
	})

	t.Run("timeout preserves in-flight bytes sent right after sniff_timeout", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		peek := NewPeekableConn(serverConn)

		// No bytes arrive before the 30ms sniff_timeout.
		proto := peek.Sniff(context.Background(), 30*time.Millisecond, 4096)
		if proto != model.ProtocolTCP {
			t.Fatalf("expected ProtocolTCP on sniff timeout, got %q", proto)
		}

		// Client writes right after sniff timeout expires while sniff pump may still hold in-flight Read.
		latePayload := []byte("LATE_CLIENT_BYTES_12345")
		go func() {
			time.Sleep(15 * time.Millisecond)
			_, _ = clientConn.Write(latePayload)
		}()

		got := make([]byte, len(latePayload))
		if _, err := io.ReadFull(peek, got); err != nil {
			t.Fatalf("failed reading late bytes after sniff timeout: %v", err)
		}
		if !bytes.Equal(got, latePayload) {
			t.Fatalf("late payload mismatch: got %q, want %q", got, latePayload)
		}
	})
}
