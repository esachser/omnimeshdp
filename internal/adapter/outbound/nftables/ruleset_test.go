package nftables_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/nftables"
)

func TestBuildRuleset(t *testing.T) {
	subnets := []netip.Prefix{
		netip.MustParsePrefix("10.10.10.0/24"),
		netip.MustParsePrefix("10.10.12.0/24"),
	}
	got := nftables.BuildRuleset(subnets, 15001, 0x10ED)

	want := `add table ip omnimesh
delete table ip omnimesh
table ip omnimesh {
	set intercept_subnets {
		type ipv4_addr
		flags interval
		elements = { 10.10.10.0/24, 10.10.12.0/24 }
	}
	chain output {
		type nat hook output priority -110; policy accept;
		meta mark 0x000010ed return
		meta l4proto tcp ip daddr @intercept_subnets redirect to :15001
	}
}
`
	if got != want {
		t.Fatalf("unexpected ruleset:\n%s\nwant:\n%s", got, want)
	}
}

func TestBuildRuleset_EmptySubnets(t *testing.T) {
	got := nftables.BuildRuleset(nil, 15001, 0x10ED)
	if strings.Contains(got, "elements") {
		t.Fatalf("empty subnet list must not render an elements clause (invalid nft syntax):\n%s", got)
	}
	if !strings.Contains(got, "set intercept_subnets {") {
		t.Fatalf("expected set to be declared even when empty:\n%s", got)
	}
}

func TestDeleteScript(t *testing.T) {
	want := "add table ip omnimesh\ndelete table ip omnimesh\n"
	if got := nftables.DeleteScript(); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
