package model

import "maps"

// NodeServiceInfo represents service identification registered by the node.
type NodeServiceInfo struct {
	Namespace   string             `json:"namespace"`
	Name        string             `json:"name"`
	ID          string             `json:"id"`
	Labels      map[string]string  `json:"labels"`
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`
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
	if s.Namespace != other.Namespace || s.Name != other.Name || s.ID != other.ID {
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
