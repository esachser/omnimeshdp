package nftables

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	// TableName is the nftables table (family ip) owned exclusively by omnimeshdp.
	TableName = "omnimesh"

	setName   = "intercept_subnets"
	chainName = "output"

	// chainPriority runs the redirect before the standard dstnat priority (-100), so
	// destinations are matched before other NAT (e.g. kube-proxy service DNAT).
	chainPriority = -110
)

// BuildRuleset renders an nft script that atomically (re)creates the omnimesh table:
// locally generated TCP traffic destined to any of the subnets is redirected to
// the local proxy port, except sockets carrying mark (the proxy's own traffic).
//
// The script is meant for `nft -f -`, which applies it as a single transaction, so
// it is used both for the initial setup and for runtime updates: traffic is always
// matched by either the old or the new ruleset. An empty subnet list produces a
// table with an empty set, i.e. nothing is redirected.
func BuildRuleset(subnets []netip.Prefix, proxyPort uint16, mark uint32) string {
	var b strings.Builder

	// Adding the table first makes the delete succeed even if it doesn't exist yet.
	b.WriteString(DeleteScript())

	fmt.Fprintf(&b, "table ip %s {\n", TableName)
	fmt.Fprintf(&b, "\tset %s {\n", setName)
	b.WriteString("\t\ttype ipv4_addr\n")
	b.WriteString("\t\tflags interval\n")
	if len(subnets) > 0 {
		elems := make([]string, len(subnets))
		for i, p := range subnets {
			elems[i] = p.String()
		}
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
	fmt.Fprintf(&b, "\tchain %s {\n", chainName)
	fmt.Fprintf(&b, "\t\ttype nat hook output priority %d; policy accept;\n", chainPriority)
	fmt.Fprintf(&b, "\t\tmeta mark 0x%08x return\n", mark)
	fmt.Fprintf(&b, "\t\tmeta l4proto tcp ip daddr @%s redirect to :%d\n", setName, proxyPort)
	b.WriteString("\t}\n")
	b.WriteString("}\n")

	return b.String()
}

// DeleteScript renders an nft script that removes the omnimesh table if present.
func DeleteScript() string {
	return fmt.Sprintf("add table ip %[1]s\ndelete table ip %[1]s\n", TableName)
}
