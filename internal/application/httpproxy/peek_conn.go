package httpproxy

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

type closeWriter interface {
	CloseWrite() error
}

// PeekableConn wraps a net.Conn and enables deadline-bounded sniffing of initial bytes
// without dropping, duplicating, or reordering unread or in-flight bytes when transitioning
// to either an L7 HTTP proxy or raw L4 TCP passthrough.
//
// It guarantees at most one goroutine calls the underlying Conn.Read at any time, making it
// safe on both OS sockets and pipe/HTTP2-stream-backed net.Conn implementations that do not
// support native Read deadlines.
type PeekableConn struct {
	net.Conn

	mu         sync.Mutex
	buf        []byte
	offset     int
	readErr    error
	pumpActive bool
	stopPump   bool
	notifyCh   chan struct{}
}

// NewPeekableConn wraps conn in a PeekableConn.
func NewPeekableConn(conn net.Conn) *PeekableConn {
	return &PeekableConn{
		Conn:     conn,
		notifyCh: make(chan struct{}),
	}
}

func (c *PeekableConn) signalLocked() {
	if c.notifyCh != nil {
		close(c.notifyCh)
		c.notifyCh = make(chan struct{})
	}
}

func (c *PeekableConn) stopSniffing() {
	c.mu.Lock()
	c.stopPump = true
	c.mu.Unlock()
}

func (c *PeekableConn) readPump(maxBytes int) {
	chunkSize := 4096
	if maxBytes > 0 && maxBytes < chunkSize {
		chunkSize = maxBytes
	}
	tmp := make([]byte, chunkSize)

	for {
		c.mu.Lock()
		if c.stopPump || len(c.buf) >= maxBytes {
			c.pumpActive = false
			c.signalLocked()
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		n, err := c.Conn.Read(tmp)

		c.mu.Lock()
		if n > 0 {
			c.buf = append(c.buf, tmp[:n]...)
		}
		if err != nil {
			c.readErr = err
			c.pumpActive = false
			c.signalLocked()
			c.mu.Unlock()
			return
		}
		c.signalLocked()
		c.mu.Unlock()
	}
}

// Sniff inspects initial client bytes up to maxBytes and timeout to detect cleartext HTTP/1.x
// or HTTP/2 (h2c prior knowledge), falling back to ProtocolTCP on non-HTTP bytes, EOF, or timeout.
func (c *PeekableConn) Sniff(ctx context.Context, timeout time.Duration, maxBytes int) model.HTTPProtocol {
	if maxBytes <= 0 {
		maxBytes = model.DefaultMaxSniffBytes
	}
	if timeout <= 0 {
		timeout = model.DefaultSniffTimeout
	}

	c.mu.Lock()
	c.pumpActive = true
	c.stopPump = false
	c.mu.Unlock()

	go c.readPump(maxBytes)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		c.mu.Lock()
		data := c.buf
		err := c.readErr
		active := c.pumpActive
		ch := c.notifyCh
		c.mu.Unlock()

		if proto, decided := classifyPrefix(data, maxBytes, err != nil || !active); decided {
			c.stopSniffing()
			return proto
		}
		if err != nil || !active {
			c.stopSniffing()
			return model.ProtocolTCP
		}

		select {
		case <-ch:
		case <-timer.C:
			c.stopSniffing()
			return model.ProtocolTCP
		case <-ctx.Done():
			c.stopSniffing()
			return model.ProtocolTCP
		}
	}
}

// Read replays any peeked bytes first, waits cleanly for any single in-flight sniff read
// to drain without racing Conn.Read, and then delegates directly to the underlying Conn.
func (c *PeekableConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		c.mu.Lock()
		if c.offset < len(c.buf) {
			n := copy(p, c.buf[c.offset:])
			c.offset += n
			if c.offset == len(c.buf) {
				c.buf = nil
				c.offset = 0
			}
			c.mu.Unlock()
			return n, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.readErr = nil
			c.mu.Unlock()
			return 0, err
		}
		if c.pumpActive {
			ch := c.notifyCh
			c.mu.Unlock()
			<-ch
			continue
		}
		c.mu.Unlock()

		return c.Conn.Read(p)
	}
}

// CloseWrite forwards TCP half-close when supported by the underlying connection.
func (c *PeekableConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Unwrap returns the underlying net.Conn.
func (c *PeekableConn) Unwrap() net.Conn {
	return c.Conn
}
