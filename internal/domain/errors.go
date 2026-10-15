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
)
