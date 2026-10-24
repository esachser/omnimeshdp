package iptables_test

import (
	"net/netip"
	"testing"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/iptables"
)

func TestBuildRestoreRules(t *testing.T) {
	subnets := []netip.Prefix{
		netip.MustParsePrefix("10.10.10.0/24"),
		netip.MustParsePrefix("10.10.12.0/24"),
	}
	got := iptables.BuildRestoreRules(subnets, 15001, 0x10ED)

	want := `*nat
:OMNIMESH_OUTPUT - [0:0]
-A OMNIMESH_OUTPUT -m mark --mark 0x10ed -j RETURN
-A OMNIMESH_OUTPUT -d 10.10.10.0/24 -p tcp -j REDIRECT --to-ports 15001
-A OMNIMESH_OUTPUT -d 10.10.12.0/24 -p tcp -j REDIRECT --to-ports 15001
COMMIT
`
	if got != want {
		t.Fatalf("unexpected rules:\n%s\nwant:\n%s", got, want)
	}
}

func TestBuildRestoreRules_EmptySubnets(t *testing.T) {
	got := iptables.BuildRestoreRules(nil, 15001, 0x10ED)

	want := `*nat
:OMNIMESH_OUTPUT - [0:0]
-A OMNIMESH_OUTPUT -m mark --mark 0x10ed -j RETURN
COMMIT
`
	if got != want {
		t.Fatalf("unexpected rules:\n%s\nwant:\n%s", got, want)
	}
}
