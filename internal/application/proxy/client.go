package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/esachser/omnimeshdp/internal/adapter/inbound/hbone"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ inbound.ProxyService = (*ClientSideService)(nil)

// ClientSideService listens for intercepted traffic on 127.0.0.1:15001 and forwards it over HBONE tunnels.
type ClientSideService struct {
	listenAddr      string
	targetHost      string
	packetProcessor outbound.PacketProcessor
	hboneClient     *hbone.Client
}

// NewClientSideService constructs a new ClientSideService.
func NewClientSideService(
	listenAddr string,
	targetHost string,
	processor outbound.PacketProcessor,
) *ClientSideService {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:15001"
	}
	if targetHost == "" {
		if envTarget := os.Getenv("TARGET_HBONE_HOST"); envTarget != "" {
			targetHost = envTarget
		} else {
			targetHost = "192.168.15.57:15008"
		}
	}

	return &ClientSideService{
		listenAddr:      listenAddr,
		targetHost:      targetHost,
		packetProcessor: processor,
		hboneClient:     hbone.NewClient(),
	}
}

// Start begins accepting local connections and tunneling them over HBONE.
func (s *ClientSideService) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind client-side listener on %s: %w", s.listenAddr, err)
	}
	defer ln.Close()

	log.Printf("Proxy HBONE client listening on %s...\n", s.listenAddr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("ClientSideService accept error: %v\n", err)
				continue
			}
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *ClientSideService) handleConnection(ctx context.Context, localConn net.Conn) {
	defer localConn.Close()

	peerAddr := localConn.RemoteAddr()
	var socketHandle uintptr

	// Extract raw socket handle for Windows WFP IOCTL lookup
	if sysConn, ok := localConn.(syscall.Conn); ok {
		if rawConn, err := sysConn.SyscallConn(); err == nil {
			_ = rawConn.Control(func(fd uintptr) {
				socketHandle = fd
			})
		}
	}

	pktInfo, err := s.packetProcessor.GetOriginalPacketInfo(peerAddr, socketHandle)
	if err != nil || pktInfo == nil {
		log.Printf("Could not retrieve original packet info for peer %s: %v\n", peerAddr, err)
		return
	}

	identity, _ := s.packetProcessor.GetIdentityByPID(pktInfo.PID)

	log.Printf(
		"Establishing HBONE tunnel to %s with identity %q for caller on port %s\n",
		s.targetHost,
		identity,
		peerAddr.String(),
	)

	realDest := "172.27.153.78:8000"
	// if pktInfo.IP != 0 && pktInfo.Port != 0 {
	// 	realDest = fmt.Sprintf("%d.%d.%d.%d:%d",
	// 		byte(pktInfo.IP>>24), byte(pktInfo.IP>>16), byte(pktInfo.IP>>8), byte(pktInfo.IP),
	// 		pktInfo.Port,
	// 	)
	// }

	if err := s.hboneClient.Tunnel(ctx, localConn, s.targetHost, realDest, identity); err != nil {
		log.Printf("Tunnel error: %v\n", err)
	}
}
