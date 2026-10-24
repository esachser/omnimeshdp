//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/iptables"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/nftables"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/noop"
	"github.com/esachser/omnimeshdp/internal/adapter/sockmark"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

// createPacketProcessor selects the Linux interception backend.
// "nftables" and "iptables" force a backend, "noop" disables interception and any
// other value ("auto", empty, or Windows-only types) auto-detects: nftables is
// preferred and iptables is used when nftables is missing or fails to apply.
func createPacketProcessor(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
	switch interceptionType {
	case "noop":
		log.Println("Starting with NoOp...")
		return noop.NewNoOpProcessor(), nil
	case "nftables":
		log.Println("Starting with nftables...")
		return nftables.NewNftablesProcessor(subnets, internalPort, sockmark.ProxyMark)
	case "iptables":
		log.Println("Starting with iptables...")
		return iptables.NewIptablesProcessor(subnets, internalPort, sockmark.ProxyMark)
	case "auto", "":
	default:
		log.Printf("Interception type %q is not available on Linux; auto-detecting nftables/iptables.\n", interceptionType)
	}
	return detectPacketProcessor(subnets, internalPort)
}

func detectPacketProcessor(subnets []string, internalPort uint16) (outbound.PacketProcessor, error) {
	var errs []error

	if err := nftables.Available(); err != nil {
		errs = append(errs, fmt.Errorf("nftables unavailable: %w", err))
	} else {
		log.Println("nftables detected, starting with nftables...")
		p, err := nftables.NewNftablesProcessor(subnets, internalPort, sockmark.ProxyMark)
		if err == nil {
			return p, nil
		}
		log.Printf("nftables setup failed, falling back to iptables: %v\n", err)
		errs = append(errs, fmt.Errorf("nftables: %w", err))
	}

	if err := iptables.Available(); err != nil {
		errs = append(errs, fmt.Errorf("iptables unavailable: %w", err))
	} else {
		log.Println("Starting with iptables...")
		p, err := iptables.NewIptablesProcessor(subnets, internalPort, sockmark.ProxyMark)
		if err == nil {
			return p, nil
		}
		errs = append(errs, fmt.Errorf("iptables: %w", err))
	}

	return nil, fmt.Errorf("no usable packet interception backend (run as root or with CAP_NET_ADMIN): %w", errors.Join(errs...))
}
