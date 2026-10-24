//go:build linux

package iptables

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

const (
	commandTimeout = 10 * time.Second

	// maxJumpCleanup bounds the removal loop for duplicated jump rules.
	maxJumpCleanup = 16
)

var (
	_ outbound.PacketProcessor = (*IptablesProcessor)(nil)
	_ outbound.SubnetUpdater   = (*IptablesProcessor)(nil)
)

// IptablesProcessor redirects outbound TCP traffic for the configured subnets to the
// local proxy port using a dedicated chain in the nat table hooked from OUTPUT.
type IptablesProcessor struct {
	proxyPort   uint16
	mark        uint32
	restoreWait bool // iptables-restore supports --wait (>= 1.6.2)

	mu      sync.Mutex
	subnets []netip.Prefix
	closed  bool
}

// Available reports whether iptables can be used: iptables and iptables-restore are
// installed and the nat table can be read by this process (requires CAP_NET_ADMIN).
func Available() error {
	for _, bin := range []string{"iptables", "iptables-restore"} {
		if _, err := exec.LookPath(bin); err != nil {
			return err
		}
	}
	if _, err := runIptables("-t", "nat", "-S", "OUTPUT"); err != nil {
		return err
	}
	return nil
}

// NewIptablesProcessor installs the redirection rules immediately so that setup
// failures surface at creation time. Traffic carrying mark is never redirected.
func NewIptablesProcessor(subnets []string, proxyPort uint16, mark uint32) (*IptablesProcessor, error) {
	if proxyPort == 0 {
		return nil, errors.New("proxy port cannot be zero")
	}
	prefixes, err := filterutil.NormalizeIPv4Subnets(subnets)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, errors.New("no subnets provided for iptables rules")
	}

	p := &IptablesProcessor{
		proxyPort:   proxyPort,
		mark:        mark,
		restoreWait: restoreSupportsWait(),
	}
	if err := p.applyLocked(prefixes); err != nil {
		return nil, err
	}
	return p, nil
}

// Run keeps the rules installed until ctx is cancelled, then removes them.
func (p *IptablesProcessor) Run(ctx context.Context) error {
	p.mu.Lock()
	log.Printf("iptables processor running: redirecting TCP for %v to local port %d (nat chain %s).\n",
		p.subnets, p.proxyPort, ChainName)
	p.mu.Unlock()

	<-ctx.Done()
	return p.Close()
}

// UpdateSubnets atomically replaces the intercepted subnets. iptables-restore
// commits the whole chain at once; if it fails the previous rules stay in place.
func (p *IptablesProcessor) UpdateSubnets(subnets []string) error {
	prefixes, err := filterutil.NormalizeIPv4Subnets(subnets)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return errors.New("iptables processor is closed")
	}
	if slices.Equal(prefixes, p.subnets) {
		return nil
	}
	if err := p.applyLocked(prefixes); err != nil {
		return err
	}
	log.Printf("iptables processor: intercepted subnets updated to %v\n", prefixes)
	return nil
}

// GetIdentityByPID returns the effective UID of the process.
func (p *IptablesProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return linuxutils.GetIdentityByPID(pid)
}

// GetOriginalPacketInfo returns the pre-redirect destination and owning PID of an accepted connection.
func (p *IptablesProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	return linuxutils.GetOriginalPacketInfo(addr, socket)
}

// Close unhooks and deletes the omnimesh chain. It is safe to call multiple times.
func (p *IptablesProcessor) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	// Remove every jump first (duplicates may exist after external tampering);
	// a chain that is still referenced cannot be deleted.
	for i := 0; i < maxJumpCleanup; i++ {
		args := append([]string{"-t", "nat", "-D", "OUTPUT"}, jumpRuleSpec()...)
		if _, err := runIptables(args...); err != nil {
			break
		}
	}

	var errs []error
	if _, err := runIptables("-t", "nat", "-F", ChainName); err != nil {
		errs = append(errs, err)
	}
	if _, err := runIptables("-t", "nat", "-X", ChainName); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("failed to remove iptables chain %s: %w", ChainName, err)
	}
	log.Printf("iptables processor: nat chain %s removed.\n", ChainName)
	return nil
}

// applyLocked replaces the chain contents and makes sure OUTPUT jumps to it.
// Callers must hold p.mu (or own p exclusively).
func (p *IptablesProcessor) applyLocked(prefixes []netip.Prefix) error {
	if err := p.restore(BuildRestoreRules(prefixes, p.proxyPort, p.mark)); err != nil {
		return fmt.Errorf("failed to apply iptables rules: %w", err)
	}
	if err := ensureJump(); err != nil {
		return fmt.Errorf("failed to hook chain %s into nat OUTPUT: %w", ChainName, err)
	}
	p.subnets = prefixes
	return nil
}

// restore feeds rules to `iptables-restore --noflush`, committing the table atomically.
func (p *IptablesProcessor) restore(rules string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	args := []string{"--noflush"}
	if p.restoreWait {
		args = append(args, "--wait")
	}
	cmd := exec.CommandContext(ctx, "iptables-restore", args...)
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// jumpRuleSpec is the nat/OUTPUT rule (without table and chain) that hooks ChainName.
func jumpRuleSpec() []string {
	return []string{"-p", "tcp", "-j", ChainName}
}

// ensureJump inserts the OUTPUT -> ChainName jump at the top of nat OUTPUT if it is
// missing, so the redirect runs before other NAT rules (e.g. kube-proxy services).
func ensureJump() error {
	check := append([]string{"-t", "nat", "-C", "OUTPUT"}, jumpRuleSpec()...)
	if _, err := runIptables(check...); err == nil {
		return nil
	}
	insert := append([]string{"-t", "nat", "-I", "OUTPUT", "1"}, jumpRuleSpec()...)
	_, err := runIptables(insert...)
	return err
}

// runIptables runs iptables waiting for the xtables lock.
func runIptables(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "iptables", append([]string{"-w"}, args...)...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// restoreSupportsWait detects whether iptables-restore accepts --wait.
func restoreSupportsWait() bool {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// --help exits non-zero on some versions; only the output matters.
	out, _ := exec.CommandContext(ctx, "iptables-restore", "--help").CombinedOutput()
	return strings.Contains(string(out), "--wait")
}
