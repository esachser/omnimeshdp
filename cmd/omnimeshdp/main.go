package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/esachser/omnimeshdp/internal/application/orchestrator"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	useWinDivert := flag.Bool("windivert", false, "Use WinDivert for packet interception")
	useWfp := flag.Bool("wfp", false, "Use Windows Filtering Platform (WFP) driver for packet interception")
	flag.Parse()

	log.Println("Starting OmniMesh DP (Go)...")

	// Step 1: Read configuration from file or env
	cfg, err := model.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to read configuration: %v", err)
	}

	// Apply CLI flag overrides if provided
	if *useWinDivert && !*useWfp {
		cfg.Interception.Type = "windivert"
	} else if *useWfp {
		cfg.Interception.Type = "wfp"
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	orch := orchestrator.NewOrchestrator(
		orchestrator.WithConfig(cfg),
		orchestrator.WithProcessorFactory(createPacketProcessor),
	)

	if err := orch.Run(ctx); err != nil {
		log.Fatalf("OmniMesh DP terminated with error: %v", err)
	}

	log.Println("OmniMesh DP shutdown complete.")
}
