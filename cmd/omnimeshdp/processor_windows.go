//go:build windows

package main

import (
	"encoding/binary"
	"log"
	"os"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/wfp"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/windivert"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

func createPacketProcessor(useWinDivert bool, useWfp bool) (outbound.PacketProcessor, error) {
	if useWinDivert && !useWfp {
		log.Println("Iniciando com Windivert...")
		filter := "tcp and outbound and ((remoteAddr >= 10.10.10.0 and remoteAddr <= 10.10.10.255) or (remoteAddr >= 10.10.12.0 and remoteAddr <= 10.10.12.255) or (localAddr == 127.0.0.1 and localPort == 15001))"
		return windivert.NewWindivertProcessor(filter)
	}

	log.Println("Iniciando com WFP...")
	cfg1 := model.ProxyConfig{
		ProxyIP:   binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
		ProxyPort: 15001,
		SelfPID:   uint64(os.Getpid()),
		IPAddr:    binary.BigEndian.Uint32([]byte{10, 10, 10, 0}),
		IPMask:    binary.BigEndian.Uint32([]byte{255, 255, 255, 0}),
	}
	cfg2 := model.ProxyConfig{
		ProxyIP:   binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
		ProxyPort: 15001,
		SelfPID:   uint64(os.Getpid()),
		IPAddr:    binary.BigEndian.Uint32([]byte{10, 10, 12, 0}),
		IPMask:    binary.BigEndian.Uint32([]byte{255, 255, 255, 0}),
	}
	return wfp.NewWfpProcessor([]model.ProxyConfig{cfg1, cfg2})
}
