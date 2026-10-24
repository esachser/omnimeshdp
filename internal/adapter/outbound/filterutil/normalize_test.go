package filterutil_test

import (
	"testing"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/filterutil"
)

func TestNormalizeIPv4Subnets(t *testing.T) {
	got, err := filterutil.NormalizeIPv4Subnets([]string{
		"10.10.12.0/24",
		"10.1.2.3/16", // host bits must be masked
		"10.10.12.128/25", // covered by 10.10.12.0/24
		"10.0.0.0/8", // covers 10.1.0.0/16 and both 10.10.12.x
		"192.168.1.0/24",
		"192.168.1.0/24", // duplicate
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"10.0.0.0/8", "192.168.1.0/24"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestNormalizeIPv4Subnets_Errors(t *testing.T) {
	if _, err := filterutil.NormalizeIPv4Subnets([]string{"invalid"}); err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
	if _, err := filterutil.NormalizeIPv4Subnets([]string{"fd00::/64"}); err == nil {
		t.Fatalf("expected error for IPv6 CIDR")
	}
	got, err := filterutil.NormalizeIPv4Subnets(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty result without error, got %v, %v", got, err)
	}
}
