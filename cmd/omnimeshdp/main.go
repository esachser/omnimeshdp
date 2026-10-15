package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	adaptergrpc "github.com/esachser/omnimeshdp/internal/adapter/outbound/grpc"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/spiffe"
	"github.com/esachser/omnimeshdp/internal/application/agent"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
)

func main() {
	useWinDivert := flag.Bool("windivert", false, "Use WinDivert for packet interception")
	useWfp := flag.Bool("wfp", false, "Use Windows Filtering Platform (WFP) driver for packet interception")
	flag.Parse()

	log.Println("Starting OmniMesh DP (Go)...")

	cpServerSVID := os.Getenv("CP_SERVER_SVID")
	if cpServerSVID == "" {
		cpServerSVID = "spiffe://omnimesh.local/ns/omnimesh-system/sa/omnimeshcontrol"
	}
	cpSocketPath := os.Getenv("CP_SOCKET_PATH")
	if cpSocketPath == "" {
		cpSocketPath = "npipe:\\spire-agent\\public\\api"
	}
	// Spiffe
	tlsProvider, err := spiffe.NewSpiffeTLSProvider(context.Background(), cpSocketPath, cpServerSVID)
	if err != nil {
		log.Fatalf("Failed to initialize TLS provider: %v", err)
	}
	defer tlsProvider.Close()

	packetProcessor, err := createPacketProcessor(*useWinDivert, *useWfp)
	if err != nil {
		log.Fatalf("Failed to initialize packet processor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Run Packet Processor
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := packetProcessor.Run(ctx); err != nil {
			log.Printf("Packet processor terminated: %v\n", err)
		}
	}()

	// Run Client Side Proxy (listens on 127.0.0.1:15001)
	clientSide := proxy.NewClientSideService("127.0.0.1:15001", "", packetProcessor)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := clientSide.Start(ctx); err != nil {
			log.Printf("Client side proxy error: %v\n", err)
		}
		log.Println("Finalizado Client Side")
	}()

	// Run Server Side Proxy (listens on 0.0.0.0:15008)
	serverSide := proxy.NewServerSideService("0.0.0.0:15008")
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := serverSide.Start(ctx); err != nil {
			log.Printf("Server side proxy error: %v\n", err)
		}
		log.Println("Finalizado Server Side")
	}()

	// Run Control Plane Agent
	cpAddr := os.Getenv("CONTROL_PLANE_ADDR")
	if cpAddr == "" {
		cpAddr = "https://127.0.0.1:9091"
	}
	grpcClient := adaptergrpc.NewClient(cpAddr, tlsProvider)
	cpAgent := agent.NewControlPlaneAgent(grpcClient)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cpAgent.Start(ctx); err != nil {
			log.Printf("Control plane agent error: %v\n", err)
		}
		log.Println("Finalizado Agent gRPC")
	}()

	// Wait for OS shutdown signal (Ctrl+C / SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	log.Println("Sinal de shutdown recebido. Finalizando...")

	// Cancel context to stop all tasks
	cancel()

	// Wait with timeout
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		log.Println("Client Side, Server Side e Agent gRPC finalizados")
	case <-time.After(10 * time.Second):
		log.Println("Timeout. Forçando shutdown...")
	}

	_ = packetProcessor.Close()
	log.Println("Finalizado OmniMesh DP")
}
