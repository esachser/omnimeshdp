package filterutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// SubnetsToWinDivertFilter converts CIDR subnets and an internal proxy port into a WinDivert filter string.
func SubnetsToWinDivertFilter(subnets []string, proxyPort uint16) (string, error) {
	if len(subnets) == 0 {
		return "", errors.New("no subnets provided for WinDivert filter")
	}

	var parts []string
	for _, subnet := range subnets {
		ip, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return "", fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return "", fmt.Errorf("only IPv4 subnets are supported: %q", subnet)
		}

		startIP := ipNet.IP.To4()
		mask := ipNet.Mask
		endIP := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			endIP[i] = startIP[i] | ^mask[i]
		}

		parts = append(parts, fmt.Sprintf("(remoteAddr >= %s and remoteAddr <= %s)", startIP.String(), endIP.String()))
	}

	subnetsClause := strings.Join(parts, " or ")
	filter := fmt.Sprintf("tcp and outbound and ((%s) or (localAddr == 127.0.0.1 and localPort == %d))", subnetsClause, proxyPort)
	return filter, nil
}

// SubnetsToWfpConfigs converts CIDR subnets into WFP ProxyConfig structs.
func SubnetsToWfpConfigs(subnets []string, proxyIP uint32, proxyPort uint16, selfPID uint64) ([]model.ProxyConfig, error) {
	if len(subnets) == 0 {
		return nil, errors.New("no subnets provided for WFP configs")
	}

	var configs []model.ProxyConfig
	for _, subnet := range subnets {
		ip, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("only IPv4 subnets are supported: %q", subnet)
		}

		ipVal := binary.BigEndian.Uint32(ipNet.IP.To4())
		maskVal := binary.BigEndian.Uint32(ipNet.Mask)

		configs = append(configs, model.ProxyConfig{
			ProxyIP:   proxyIP,
			ProxyPort: proxyPort,
			SelfPID:   selfPID,
			IPAddr:    ipVal,
			IPMask:    maskVal,
		})
	}

	return configs, nil
}
