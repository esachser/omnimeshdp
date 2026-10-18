package filterutil_test

import (
	"encoding/binary"
	"testing"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/filterutil"
)

func TestSubnetsToWinDivertFilter(t *testing.T) {
	subnets := []string{"10.10.10.0/24", "10.10.12.0/24"}
	filter, err := filterutil.SubnetsToWinDivertFilter(subnets, 15001)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "tcp and outbound and (((remoteAddr >= 10.10.10.0 and remoteAddr <= 10.10.10.255) or (remoteAddr >= 10.10.12.0 and remoteAddr <= 10.10.12.255)) or (localAddr == 127.0.0.1 and localPort == 15001))"
	if filter != expected {
		t.Fatalf("expected filter:\n%s\ngot:\n%s", expected, filter)
	}

	// Empty subnets error
	if _, err := filterutil.SubnetsToWinDivertFilter(nil, 15001); err == nil {
		t.Fatalf("expected error for empty subnets")
	}

	// Invalid CIDR error
	if _, err := filterutil.SubnetsToWinDivertFilter([]string{"invalid"}, 15001); err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
}

func TestSubnetsToWfpConfigs(t *testing.T) {
	subnets := []string{"10.10.10.0/24", "10.10.12.0/24"}
	proxyIP := binary.BigEndian.Uint32([]byte{127, 0, 0, 1})
	proxyPort := uint16(15001)
	selfPID := uint64(1234)

	configs, err := filterutil.SubnetsToWfpConfigs(subnets, proxyIP, proxyPort, selfPID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(configs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(configs))
	}

	if configs[0].IPAddr != binary.BigEndian.Uint32([]byte{10, 10, 10, 0}) {
		t.Fatalf("unexpected IPAddr in config 0: %v", configs[0].IPAddr)
	}
	if configs[0].IPMask != binary.BigEndian.Uint32([]byte{255, 255, 255, 0}) {
		t.Fatalf("unexpected IPMask in config 0: %v", configs[0].IPMask)
	}
	if configs[0].ProxyPort != 15001 || configs[0].SelfPID != 1234 {
		t.Fatalf("unexpected ProxyPort or SelfPID in config 0")
	}
}
