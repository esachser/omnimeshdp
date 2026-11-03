package model

import (
	"fmt"
	"maps"
	"net"
	"strings"
	"time"
)

// HealthCheckConfig defines the health check probe configuration for a local service.
type HealthCheckConfig struct {
	Type               string            `json:"type"`                          // "TCP", "HTTP", "gRPC"
	Address            string            `json:"address,omitempty"`             // Target address (e.g. "127.0.0.1:8080" or ":8080")
	Port               int               `json:"port,omitempty"`                // Target port (used if Address has no port or is empty)
	Path               string            `json:"path,omitempty"`                // HTTP path (e.g. "/healthz")
	Interval           string            `json:"interval,omitempty"`            // e.g. "5s"
	Timeout            string            `json:"timeout,omitempty"`             // e.g. "2s"
	HealthyThreshold   int               `json:"healthy_threshold,omitempty"`   // consecutive successes before marking healthy
	UnhealthyThreshold int               `json:"unhealthy_threshold,omitempty"` // consecutive failures before marking unhealthy
	Headers            map[string]string `json:"headers,omitempty"`             // Optional HTTP headers
}

// GetProbeType returns the canonical probe type ("TCP", "HTTP", "gRPC").
func (h *HealthCheckConfig) GetProbeType() string {
	if h == nil {
		return "TCP"
	}
	switch strings.ToUpper(strings.TrimSpace(h.Type)) {
	case "HTTP", "HTTPS":
		return "HTTP"
	case "GRPC":
		return "gRPC"
	default:
		return "TCP"
	}
}

// GetInterval returns the check interval, defaulting to 5s if unspecified or invalid.
func (h *HealthCheckConfig) GetInterval() time.Duration {
	if h != nil && h.Interval != "" {
		if d, err := time.ParseDuration(h.Interval); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

// GetTimeout returns the check timeout, defaulting to 2s if unspecified or invalid.
func (h *HealthCheckConfig) GetTimeout() time.Duration {
	if h != nil && h.Timeout != "" {
		if d, err := time.ParseDuration(h.Timeout); err == nil && d > 0 {
			return d
		}
	}
	return 2 * time.Second
}

// GetHealthyThreshold returns consecutive successes required, defaulting to 1.
func (h *HealthCheckConfig) GetHealthyThreshold() int {
	if h != nil && h.HealthyThreshold > 0 {
		return h.HealthyThreshold
	}
	return 1
}

// GetUnhealthyThreshold returns consecutive failures required, defaulting to 2.
func (h *HealthCheckConfig) GetUnhealthyThreshold() int {
	if h != nil && h.UnhealthyThreshold > 0 {
		return h.UnhealthyThreshold
	}
	return 2
}

// GetTargetAddress resolves the host:port to dial.
func (h *HealthCheckConfig) GetTargetAddress() string {
	if h == nil {
		return "127.0.0.1:80"
	}
	addr := strings.TrimSpace(h.Address)
	if addr == "" {
		if h.Port > 0 {
			return fmt.Sprintf("127.0.0.1:%d", h.Port)
		}
		return "127.0.0.1:80"
	}
	// If address already has a port
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	// If address is just a port like ":8080"
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	// Address has no port, but Port is configured
	if h.Port > 0 {
		return fmt.Sprintf("%s:%d", addr, h.Port)
	}
	return addr
}

// Equal checks if two HealthCheckConfigs are identical.
func (h *HealthCheckConfig) Equal(other *HealthCheckConfig) bool {
	if h == other {
		return true
	}
	if h == nil || other == nil {
		return false
	}
	return strings.EqualFold(h.Type, other.Type) &&
		h.Address == other.Address &&
		h.Port == other.Port &&
		h.Path == other.Path &&
		h.Interval == other.Interval &&
		h.Timeout == other.Timeout &&
		h.HealthyThreshold == other.HealthyThreshold &&
		h.UnhealthyThreshold == other.UnhealthyThreshold &&
		maps.Equal(h.Headers, other.Headers)
}

