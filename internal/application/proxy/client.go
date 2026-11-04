package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
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
	mu              sync.RWMutex
	packetProcessor outbound.PacketProcessor
	hboneClient     *hbone.Client
	router          *Router
	svidProvider    outbound.WorkloadSVIDProvider
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

// SetRouter configures the dynamic route table provider.
func (s *ClientSideService) SetRouter(r *Router) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.router = r
}

// SetPacketProcessor updates the packet processor.
func (s *ClientSideService) SetPacketProcessor(p outbound.PacketProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packetProcessor = p
}

// SetWorkloadSVIDProvider configures the provider that fetches SVIDs by calling process PID.
func (s *ClientSideService) SetWorkloadSVIDProvider(p outbound.WorkloadSVIDProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.svidProvider = p
}

// WorkloadSVIDProvider returns the active WorkloadSVIDProvider, or nil if none is configured.
func (s *ClientSideService) WorkloadSVIDProvider() outbound.WorkloadSVIDProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.svidProvider
}

// Start begins accepting local connections and tunneling them over HBONE.
func (s *ClientSideService) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind client-side listener on %s: %w", s.listenAddr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on the provided pre-opened listener.
func (s *ClientSideService) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	log.Printf("Proxy HBONE client listening on %s...\n", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
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

	var identity string
	var clientTLS *tls.Config
	targetHost := s.targetHost
	realDest := "172.27.153.78:8000"

	s.mu.RLock()
	processor := s.packetProcessor
	router := s.router
	svidProv := s.svidProvider
	s.mu.RUnlock()

	if processor != nil {
		pktInfo, err := processor.GetOriginalPacketInfo(peerAddr, socketHandle)
		if err != nil || pktInfo == nil {
			log.Printf("Could not retrieve original packet info for peer %s: %v\n", peerAddr, err)
			return
		}

		// Retrieve SVID using PID of calling process to impersonate the service via mTLS
		if svidProv != nil && pktInfo.PID != 0 {
			tlsCfg, spiffeID, err := svidProv.GetClientTLSConfigByPID(ctx, pktInfo.PID)
			if err != nil {
				log.Printf("Could not retrieve SVID for caller PID %d: %v\n", pktInfo.PID, err)
				return
			}
			clientTLS = tlsCfg
			identity = spiffeID
		} else {
			identity, _ = processor.GetIdentityByPID(pktInfo.PID)
		}

		if pktInfo.IP != 0 {
			destIP := fmt.Sprintf("%d.%d.%d.%d",
				byte(pktInfo.IP>>24), byte(pktInfo.IP>>16), byte(pktInfo.IP>>8), byte(pktInfo.IP),
			)
			realDest = fmt.Sprintf("%s:%d", destIP, pktInfo.Port)

			if router != nil {
				resolved := router.ResolveRoute(destIP, pktInfo.Port, s.targetHost)
				if resolved != nil {
					targetHost = resolved.TargetHost
					realDest = resolved.RealDest
				}
			}
		}
	}

	log.Printf(
		"Establishing HBONE tunnel to %s with identity %q for caller on port %s (destination: %s, mTLS=%v)\n",
		targetHost,
		identity,
		peerAddr.String(),
		realDest,
		clientTLS != nil,
	)

	if err := s.hboneClient.Tunnel(ctx, localConn, targetHost, realDest, identity, clientTLS); err != nil {
		log.Printf("Tunnel error: %v\n", err)
	}
}
