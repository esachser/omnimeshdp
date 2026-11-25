package hbone

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// deadlineReader wraps an io.ReadCloser that does not natively support SetReadDeadline
// (such as an HTTP/2 request/response body stream) so it honors net.Conn.SetReadDeadline
// without dropping or reordering in-flight bytes.
type deadlineReader struct {
	src io.ReadCloser

	mu          sync.Mutex
	buf         []byte
	offset      int
	readErr     error
	pumpStarted bool
	closed      bool
	deadline    time.Time
	notifyCh    chan struct{}
}

func newDeadlineReader(src io.ReadCloser) *deadlineReader {
	return &deadlineReader{
		src:      src,
		notifyCh: make(chan struct{}),
	}
}

func (d *deadlineReader) signalLocked() {
	if d.notifyCh != nil {
		close(d.notifyCh)
		d.notifyCh = make(chan struct{})
	}
}

func (d *deadlineReader) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadline = t
	d.signalLocked()
	d.mu.Unlock()
	return nil
}

func (d *deadlineReader) Close() error {
	d.mu.Lock()
	alreadyClosed := d.closed
	d.closed = true
	d.signalLocked()
	d.mu.Unlock()
	if alreadyClosed {
		return nil
	}
	return d.src.Close()
}

func (d *deadlineReader) pump() {
	tmp := make([]byte, 32*1024)
	for {
		n, err := d.src.Read(tmp)
		d.mu.Lock()
		if n > 0 {
			d.buf = append(d.buf, tmp[:n]...)
		}
		if err != nil {
			d.readErr = err
			d.signalLocked()
			d.mu.Unlock()
			return
		}
		d.signalLocked()
		d.mu.Unlock()
	}
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		d.mu.Lock()
		if !d.pumpStarted && !d.closed {
			d.pumpStarted = true
			go d.pump()
		}

		if d.closed {
			d.mu.Unlock()
			return 0, net.ErrClosed
		}

		var remaining time.Duration
		hasDeadline := !d.deadline.IsZero()
		if hasDeadline {
			remaining = time.Until(d.deadline)
			if remaining <= 0 {
				d.mu.Unlock()
				return 0, os.ErrDeadlineExceeded
			}
		}

		if d.offset < len(d.buf) {
			n := copy(p, d.buf[d.offset:])
			d.offset += n
			if d.offset == len(d.buf) {
				d.buf = nil
				d.offset = 0
			}
			d.mu.Unlock()
			return n, nil
		}

		if d.readErr != nil {
			err := d.readErr
			d.mu.Unlock()
			return 0, err
		}

		ch := d.notifyCh
		d.mu.Unlock()

		if !hasDeadline {
			<-ch
			continue
		}

		timer := time.NewTimer(remaining)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
		}
	}
}
