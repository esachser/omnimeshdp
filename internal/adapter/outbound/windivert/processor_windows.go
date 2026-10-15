//go:build windows

package windivert

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/winutils"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"golang.org/x/sys/windows"
)

var _ outbound.PacketProcessor = (*WindivertProcessor)(nil)

// WindivertProcessor intercepts packets via WinDivert and maintains an in-memory NAT translation table.
type WindivertProcessor struct {
	handle   windows.Handle
	running  atomic.Bool
	natTable sync.Map // map[uint16]model.NatEntry: localPort -> NatEntry
	wg       sync.WaitGroup
	filter   string
}

// NewWindivertProcessor creates and initializes a WinDivert packet processor with the provided packet filter.
func NewWindivertProcessor(filter string) (*WindivertProcessor, error) {
	if filter == "" {
		return nil, errors.New("WinDivert filter cannot be empty")
	}

	log.Printf("Attempting to open WinDivert with filter: %q\n", filter)
	h, err := winDivertOpen(filter, LayerNetwork, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open WinDivert handle: %w", err)
	}

	wp := &WindivertProcessor{
		handle: h,
		filter: filter,
	}
	wp.running.Store(true)
	return wp, nil
}

// Run spawns worker goroutines to process packets concurrently.
func (w *WindivertProcessor) Run(ctx context.Context) error {
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	selfPID := int32(os.Getpid())
	log.Printf("Starting WinDivert processor with %d workers (Self PID: %d)...\n", numWorkers, selfPID)

	for i := 0; i < numWorkers; i++ {
		w.wg.Add(1)
		go func(workerID int) {
			defer w.wg.Done()
			w.workerLoop(workerID, selfPID)
		}(i)
	}

	<-ctx.Done()
	return w.Close()
}

func (w *WindivertProcessor) workerLoop(workerID int, selfPID int32) {
	packetBuffer := make([]byte, MTUMax)

	for w.running.Load() {
		var addr Address
		packetLen, err := winDivertRecv(w.handle, packetBuffer, &addr)
		if err != nil {
			if !w.running.Load() {
				break
			}
			log.Printf("[Worker %d] WinDivertRecv error: %v\n", workerID, err)
			break
		}

		start := time.Now()

		var ipHdr *IpHdr
		var tcpHdr *TcpHdr

		if !winDivertHelperParsePacket(packetBuffer, packetLen, &ipHdr, &tcpHdr) {
			// Failed to parse packet, re-inject without modification
			_, _ = winDivertSend(w.handle, packetBuffer, packetLen, &addr)
			continue
		}

		srcPort := bits.ReverseBytes16(tcpHdr.SrcPort)
		dstPort := bits.ReverseBytes16(tcpHdr.DstPort)

		// log.Printf("[Worker %d] Packet received: %v:%d -> %v:%d\n", workerID, bits.ReverseBytes32(ipHdr.SrcAddr), srcPort, bits.ReverseBytes32(ipHdr.DstAddr), dstPort)

		// Handle outbound traffic originating from local applications
		if addr.Outbound() && srcPort != 15001 {
			var pid int32 = -1

			if !tcpHdr.SYN() {
				if val, ok := w.natTable.Load(srcPort); ok {
					entry := val.(model.NatEntry)
					pid = entry.PID
				}
			}

			if pid < 0 {
				if resolvedPID, err := getPIDFromLocalPort(srcPort); err == nil {
					pid = resolvedPID
				}
			}

			// Store entry in NAT state table
			origSrc := bits.ReverseBytes32(ipHdr.SrcAddr)
			origDst := bits.ReverseBytes32(ipHdr.DstAddr)

			w.natTable.Store(srcPort, model.NatEntry{
				OriginalPort:    dstPort,
				OriginalSrcAddr: origSrc,
				OriginalDstAddr: origDst,
				PID:             pid,
			})

			// Ignore traffic produced by this proxy process itself
			if pid <= 0 || pid == selfPID {
				_, _ = winDivertSend(w.handle, packetBuffer, packetLen, &addr)
				continue
			}

			// Hijack packet: redirect destination to 127.0.0.1:15001
			ipHdr.SrcAddr = bits.ReverseBytes32(0x7F000001)
			ipHdr.DstAddr = bits.ReverseBytes32(0x7F000001)
			tcpHdr.DstPort = bits.ReverseBytes16(15001)
			addr.SetLoopback(true)
		} else if srcPort == 15001 {
			// Traffic returning from proxy back to caller: restore original endpoints
			if val, ok := w.natTable.Load(dstPort); ok {
				entry := val.(model.NatEntry)

				tcpHdr.SrcPort = bits.ReverseBytes16(entry.OriginalPort)
				ipHdr.DstAddr = bits.ReverseBytes32(entry.OriginalSrcAddr)
				ipHdr.SrcAddr = bits.ReverseBytes32(entry.OriginalDstAddr)
			}
		}

		// Recalculate packet checksums
		winDivertHelperCalcChecksums(packetBuffer, packetLen, &addr, 0)

		// Re-inject packet
		_, _ = winDivertSend(w.handle, packetBuffer, packetLen, &addr)

		_ = start
	}
}

// GetIdentityByPID resolves process identity using Windows SID.
func (w *WindivertProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	sid, err := winutils.GetUserSIDFromPID(uint32(pid))
	if err != nil {
		return "", false
	}
	return sid, true
}

// GetOriginalPacketInfo looks up original destination and PID from the NAT table by connection port.
func (w *WindivertProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("expected TCPAddr, got %T", addr)
	}

	port := uint16(tcpAddr.Port)
	val, ok := w.natTable.Load(port)
	if !ok {
		return nil, nil
	}

	entry := val.(model.NatEntry)
	return &model.OriginalPacketInfo{
		PID:  uint64(entry.PID),
		IP:   entry.OriginalDstAddr,
		Port: entry.OriginalPort,
	}, nil
}

// Close closes the WinDivert handle and waits for workers to shut down.
func (w *WindivertProcessor) Close() error {
	if !w.running.Swap(false) {
		return nil
	}

	if w.handle != 0 && w.handle != windows.InvalidHandle {
		_ = winDivertClose(w.handle)
		w.handle = windows.InvalidHandle
	}

	w.wg.Wait()
	return nil
}
