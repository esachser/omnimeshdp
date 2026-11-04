package outbound

import (
	"crypto/tls"
)

// TLSConfigProvider provides client mTLS configuration (e.g. for control plane connection).
type TLSConfigProvider interface {
	GetTLSConfig() (*tls.Config, error)
}

// ServerTLSConfigProvider provides server mTLS configuration for receiving inter-agent traffic.
type ServerTLSConfigProvider interface {
	GetServerTLSConfig() (*tls.Config, error)
}
