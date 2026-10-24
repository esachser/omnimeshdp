//go:build linux

package nftables

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/filterutil"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/linuxutils"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

const commandTimeout = 10 * time.Second

var (
	_ outbound.PacketProcessor = (*NftablesProcessor)(nil)
	_ outbound.SubnetUpdater   = (*NftablesProcessor)(nil)
)

// NftablesProcessor redirects outbound TCP traffic for the configured subnets to the
// local proxy port using an nftables nat/output chain in a dedicated table.
type NftablesProcessor struct {
	proxyPort uint16
	mark      uint32

	mu      sync.Mutex
	subnets []netip.Prefix
	closed  bool
}

// Available reports whether nftables can be used: the nft binary is installed and
// the kernel answers nf_tables requests from this process (which also requires
// CAP_NET_ADMIN).
func Available() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "nft", "list", "tables").CombinedOutput(); err != nil {
		return fmt.Errorf("nft list tables: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// NewNftablesProcessor installs the redirection rules immediately so that setup
// failures surface at creation time. Traffic carrying mark is never redirected.
func NewNftablesProcessor(subnets []string, proxyPort uint16, mark uint32) (*NftablesProcessor, error) {
	if proxyPort == 0 {
		return nil, errors.New("proxy port cannot be zero")
	}
	prefixes, err := filterutil.NormalizeIPv4Subnets(subnets)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, errors.New("no subnets provided for nftables rules")
	}

	p := &NftablesProcessor{proxyPort: proxyPort, mark: mark}
	if err := p.applyLocked(prefixes); err != nil {
		return nil, err
	}
	return p, nil
}

// Run keeps the rules installed until ctx is cancelled, then removes them.
func (p *NftablesProcessor) Run(ctx context.Context) error {
	p.mu.Lock()
	log.Printf("nftables processor running: redirecting TCP for %v to local port %d (table ip %s).\n",
		p.subnets, p.proxyPort, TableName)
	p.mu.Unlock()

	<-ctx.Done()
	return p.Close()
}

// UpdateSubnets atomically replaces the intercepted subnets. If nft rejects the
// new ruleset the kernel rolls back the transaction and the previous rules stay.
func (p *NftablesProcessor) UpdateSubnets(subnets []string) error {
	prefixes, err := filterutil.NormalizeIPv4Subnets(subnets)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return errors.New("nftables processor is closed")
	}
	if slices.Equal(prefixes, p.subnets) {
		return nil
	}
	if err := p.applyLocked(prefixes); err != nil {
		return err
	}
	log.Printf("nftables processor: intercepted subnets updated to %v\n", prefixes)
	return nil
}

// GetIdentityByPID returns the effective UID of the process.
func (p *NftablesProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return linuxutils.GetIdentityByPID(pid)
}

// GetOriginalPacketInfo returns the pre-redirect destination and owning PID of an accepted connection.
func (p *NftablesProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	return linuxutils.GetOriginalPacketInfo(addr, socket)
}

// Close removes the omnimesh table. It is safe to call multiple times.
func (p *NftablesProcessor) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	if err := runNft(DeleteScript()); err != nil {
		return fmt.Errorf("failed to remove nftables table %s: %w", TableName, err)
	}
	log.Printf("nftables processor: table ip %s removed.\n", TableName)
	return nil
}

// applyLocked installs the ruleset for prefixes. Callers must hold p.mu (or own p exclusively).
func (p *NftablesProcessor) applyLocked(prefixes []netip.Prefix) error {
	if err := runNft(BuildRuleset(prefixes, p.proxyPort, p.mark)); err != nil {
		return fmt.Errorf("failed to apply nftables ruleset: %w", err)
	}
	p.subnets = prefixes
	return nil
}

// runNft feeds script to `nft -f -`, which commits it as a single atomic transaction.
func runNft(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
