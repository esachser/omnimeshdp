package filterutil

import (
	"fmt"
	"net/netip"
	"slices"
)

// NormalizeIPv4Subnets parses CIDR subnets and returns a canonical, sorted and
// de-duplicated list of IPv4 prefixes. Host bits are masked out and prefixes that
// are fully covered by another prefix in the list are dropped, so the result never
// contains overlapping ranges (required by nftables interval sets).
// An empty input yields an empty result without error.
func NormalizeIPv4Subnets(subnets []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(subnets))
	for _, subnet := range subnets {
		p, err := netip.ParsePrefix(subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("only IPv4 subnets are supported: %q", subnet)
		}
		prefixes = append(prefixes, p.Masked())
	}

	// Shorter (wider) prefixes first, so covering prefixes are kept before the ones they cover.
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return a.Bits() - b.Bits()
		}
		return a.Addr().Compare(b.Addr())
	})

	result := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		covered := false
		for _, kept := range result {
			if kept.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, p)
		}
	}

	slices.SortFunc(result, func(a, b netip.Prefix) int {
		return a.Addr().Compare(b.Addr())
	})
	return result, nil
}
