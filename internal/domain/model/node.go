package model

// NodeServiceInfo represents service identification registered by the node.
type NodeServiceInfo struct {
	Namespace string
	Name      string
	ID        string
	Labels    map[string]string
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
