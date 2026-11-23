package domain

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrCallerNotFound indicates caller information could not be resolved.
	ErrCallerNotFound = errors.New("caller information not found")

	// ErrPacketNotFound indicates the intercepted packet was not found in the state table.
	ErrPacketNotFound = errors.New("packet not found in state table")

	// ErrDriverUnavailable indicates the kernel driver or library could not be opened.
	ErrDriverUnavailable = errors.New("packet interception driver unavailable")

	// ErrTunnelFailed indicates failure to establish an HBONE overlay tunnel.
	ErrTunnelFailed = errors.New("failed to establish HBONE tunnel")

	// ErrInvalidDestination indicates missing or malformed real destination header.
	ErrInvalidDestination = errors.New("invalid or missing destination header")

	// ErrSubnetUpdateUnsupported indicates the active packet processor cannot change intercepted subnets at runtime.
	ErrSubnetUpdateUnsupported = errors.New("packet processor does not support runtime subnet updates")

	// ErrSVIDNotFound indicates that no SVID could be resolved for the calling process.
	ErrSVIDNotFound = errors.New("no SVID found for process")

	// ErrDelegatedIdentityFailed indicates failure to communicate with SPIRE delegated identity API.
	ErrDelegatedIdentityFailed = errors.New("failed to acquire delegated identity from spire")

	// Routing and tunnel failover errors per spec/routing.md
	ErrNoRoute              = errors.New("no route found for destination")
	ErrNoHealthyEndpoints   = errors.New("no healthy endpoints available")
	ErrNoMatchingEndpoints  = errors.New("no endpoints match traffic policy routes")
	ErrNoAvailableEndpoints = errors.New("no untried endpoints remaining")
	ErrBadGateway           = errors.New("peer agent failed to connect to target service (502 Bad Gateway)")
	ErrRetriesExhausted     = errors.New("routing retries exhausted")

	// Startup step errors per spec/run-start.md
	ErrConfigLoadFailed             = errors.New("step 1 failed: could not load configuration")
	ErrSpireConnectionFailed        = errors.New("step 2 failed: could not connect to spire agent for mTLS")
	ErrPortBindFailed               = errors.New("step 3 failed: could not open internal/external ports")
	ErrControlPlaneConnectionFailed = errors.New("step 4 failed: could not connect to control plane")
	ErrInitialScopeSnapshotFailed   = errors.New("step 5 failed: could not receive initial scope snapshot")
	ErrSubnetsConfigFailed          = errors.New("step 6 failed: invalid or missing namespace subnets")
	ErrPacketProcessorInitFailed    = errors.New("step 7 failed: could not configure packet processor filtering")
	ErrDeployServicesFailed         = errors.New("step 8 failed: could not read services to deploy")
	ErrControlPlaneStreamingFailed  = errors.New("step 9 failed: control plane streaming interrupted")
)

// TunnelStatusError represents a non-200 HTTP status returned by a peer agent
// during HBONE CONNECT handshake.
type TunnelStatusError struct {
	StatusCode int
}

// Error implements the error interface.
func (e *TunnelStatusError) Error() string {
	return fmt.Sprintf("%s: status %d", ErrTunnelFailed.Error(), e.StatusCode)
}

// Is allows matching against ErrTunnelFailed and, for HTTP 502, ErrBadGateway.
func (e *TunnelStatusError) Is(target error) bool {
	if target == ErrTunnelFailed {
		return true
	}
	if e.StatusCode == http.StatusBadGateway && target == ErrBadGateway {
		return true
	}
	return false
}

