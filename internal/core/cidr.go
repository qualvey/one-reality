package core

import (
	"net/netip"
	"strings"
)

// PrioritizeCIDRsByIP stably moves CIDRs containing targetIP to the front.
// CIDRs that do not contain the target IP keep their original relative order.
func PrioritizeCIDRsByIP(cidrs []string, targetIP string) []string {
	target, err := netip.ParseAddr(strings.TrimSpace(targetIP))
	if err != nil {
		return append([]string(nil), cidrs...)
	}
	target = target.Unmap()

	prioritized := make([]string, 0, len(cidrs))
	rest := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(target) {
			prioritized = append(prioritized, cidr)
			continue
		}
		rest = append(rest, cidr)
	}

	return append(prioritized, rest...)
}
