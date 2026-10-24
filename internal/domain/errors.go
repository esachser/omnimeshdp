package domain

import "errors"

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

	// Startup step errors per spec/run-start.md
	ErrConfigLoadFailed              = errors.New("step 1 failed: could not load configuration")
	ErrSpireConnectionFailed         = errors.New("step 2 failed: could not connect to spire agent for mTLS")
	ErrPortBindFailed                = errors.New("step 3 failed: could not open internal/external ports")
	ErrControlPlaneConnectionFailed  = errors.New("step 4 failed: could not connect to control plane")
	ErrInitialScopeSnapshotFailed    = errors.New("step 5 failed: could not receive initial scope snapshot")
	ErrSubnetsConfigFailed           = errors.New("step 6 failed: invalid or missing namespace subnets")
	ErrPacketProcessorInitFailed     = errors.New("step 7 failed: could not configure packet processor filtering")
	ErrDeployServicesFailed          = errors.New("step 8 failed: could not read services to deploy")
	ErrControlPlaneStreamingFailed   = errors.New("step 9 failed: control plane streaming interrupted")
)

