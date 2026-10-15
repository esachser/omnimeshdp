package hbone_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
)

func TestHBONETunnelEcho(t *testing.T) {
	// 1. Start a dummy backend TCP echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoListener.Close()

	echoAddr := echoListener.Addr().String()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start HBONE server
	// Pick an available port
	hbListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port for HBONE server: %v", err)
	}
	hbAddr := hbListener.Addr().String()
	_ = hbListener.Close()

	server := hbone.NewServer(hbAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.Start(ctx); err != nil {
			serverErrCh <- err
		}
	}()

	// Allow server time to bind
	time.Sleep(100 * time.Millisecond)

	// 3. Create HBONE client
	client := hbone.NewClient()

	// 4. Create a local pipe simulating an intercepted connection
	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()
	defer proxySide.Close()

	tunnelErrCh := make(chan error, 1)
	go func() {
		err := client.Tunnel(
			ctx,
			proxySide,
			hbAddr,
			echoAddr,
			"test-identity",
		)
		tunnelErrCh <- err
	}()

	// 5. Write data through clientSide and verify echo response
	testPayload := []byte("Hello HBONE Mesh Over HTTP/2!")

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(testPayload)
		writeErrCh <- err
	}()

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("failed to write to tunnel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout writing to tunnel")
	}

	buf := make([]byte, len(testPayload))
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(clientSide, buf)
	if err != nil {
		t.Fatalf("failed to read echoed data from tunnel: %v", err)
	}

	if string(buf[:n]) != string(testPayload) {
		t.Fatalf("echo mismatch: got %q, expected %q", string(buf[:n]), string(testPayload))
	}

	fmt.Println("HBONE HTTP/2 CONNECT tunnel successfully verified!")
}
