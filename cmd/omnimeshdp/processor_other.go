//go:build !windows && !linux

package main

import (
	"log"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/noop"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

func createPacketProcessor(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
	log.Println("Running on a system without packet interception support: using NoOpProcessor.")
	return noop.NewNoOpProcessor(), nil
}
