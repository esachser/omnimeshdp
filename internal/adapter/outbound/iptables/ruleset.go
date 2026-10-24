package iptables

import (
	"fmt"
	"net/netip"
	"strings"
)

// ChainName is the nat-table chain owned exclusively by omnimeshdp.
const ChainName = "OMNIMESH_OUTPUT"

// BuildRestoreRules renders an iptables-restore payload for the nat table that
// atomically replaces the contents of ChainName: locally generated TCP traffic
// destined to any of the subnets is redirected to the local proxy port, except
// sockets carrying mark (the proxy's own traffic).
//
// It must be applied with `iptables-restore --noflush`, so other chains are left
// untouched while the ":CHAIN" declaration flushes ChainName in the same commit.
// This makes the payload suitable for both the initial setup and runtime updates.
// An empty subnet list produces a chain that redirects nothing.
func BuildRestoreRules(subnets []netip.Prefix, proxyPort uint16, mark uint32) string {
	var b strings.Builder
	b.WriteString("*nat\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n", ChainName)
	fmt.Fprintf(&b, "-A %s -m mark --mark 0x%x -j RETURN\n", ChainName, mark)
	for _, p := range subnets {
		fmt.Fprintf(&b, "-A %s -d %s -p tcp -j REDIRECT --to-ports %d\n", ChainName, p.String(), proxyPort)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}
