//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/filterutil"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/noop"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/wfp"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/windivert"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

func createPacketProcessor(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
	switch interceptionType {
	case "windivert":
		log.Println("Starting with WinDivert...")
		filter, err := filterutil.SubnetsToWinDivertFilter(subnets, internalPort)
		if err != nil {
			return nil, fmt.Errorf("failed to generate WinDivert filter: %w", err)
		}
		return windivert.NewWindivertProcessor(filter)
	case "noop":
		log.Println("Starting with NoOp...")
		return noop.NewNoOpProcessor(), nil
	case "wfp":
		fallthrough
	default:
		log.Println("Starting with WFP...")
		proxyIP := binary.BigEndian.Uint32([]byte{127, 0, 0, 1})
		configs, err := filterutil.SubnetsToWfpConfigs(subnets, proxyIP, internalPort, uint64(os.Getpid()))
		if err != nil {
			return nil, fmt.Errorf("failed to generate WFP configs: %w", err)
		}
		return wfp.NewWfpProcessor(configs)
	}
}
