//go:build !windows

package main

import (
	"log"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/noop"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

func createPacketProcessor(useWinDivert bool, useWfp bool) (outbound.PacketProcessor, error) {
	log.Println("Running on non-Windows system: using NoOpProcessor.")
	return noop.NewNoOpProcessor(), nil
}
