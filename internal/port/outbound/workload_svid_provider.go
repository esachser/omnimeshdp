package outbound

import (
	"context"
	"crypto/tls"
)

// WorkloadSVIDProvider provides mTLS configurations for services based on their process ID (impersonating the service).
type WorkloadSVIDProvider interface {
	// GetClientTLSConfigByPID returns an mTLS *tls.Config and SPIFFE ID for the given calling process ID.
	GetClientTLSConfigByPID(ctx context.Context, pid uint64) (*tls.Config, string, error)
}

