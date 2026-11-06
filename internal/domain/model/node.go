package model

import (
	"maps"
	"net"
	"strconv"
	"strings"
)

// NodeServiceInfo represents service identification registered by the node.
type NodeServiceInfo struct {
	Namespace   string             `json:"namespace"`
	Name        string             `json:"name"`
	ID          string             `json:"id"`
	Host        string             `json:"host,omitempty"`
	Port        int                `json:"port,omitempty"`
	Labels      map[string]string  `json:"labels"`
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`
}

// Address returns the resolved "host:port" for dialing the local service instance.
func (s NodeServiceInfo) Address() string {
	host := strings.TrimSpace(s.Host)
	if s.Port > 0 {
		if host == "" {
			host = "127.0.0.1"
		}
		if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
			return net.JoinHostPort(h, p)
		}
		return net.JoinHostPort(host, strconv.Itoa(s.Port))
	}
	if host != "" {
		return host
	}
	if s.HealthCheck != nil && (strings.TrimSpace(s.HealthCheck.Address) != "" || s.HealthCheck.Port > 0) {
		return s.HealthCheck.GetTargetAddress()
	}
	return ""
}

// Key returns a unique identifier for the service instance.
func (s NodeServiceInfo) Key() string {
	if s.ID != "" {
		return s.Namespace + "/" + s.Name + "/" + s.ID
	}
	return s.Namespace + "/" + s.Name
}

// Equal checks equality of two NodeServiceInfo objects.
func (s NodeServiceInfo) Equal(other NodeServiceInfo) bool {
	if s.Namespace != other.Namespace || s.Name != other.Name || s.ID != other.ID || s.Host != other.Host || s.Port != other.Port {
		return false
	}
	if !maps.Equal(s.Labels, other.Labels) {
		return false
	}
	return s.HealthCheck.Equal(other.HealthCheck)
}

// NodeRegistration encapsulates node metadata sent to the control plane.
type NodeRegistration struct {
	NodeID   string
	Platform string
	Addr     string
	Labels   map[string]string
	Services []NodeServiceInfo
	Target   string
}
