package model

// ResolvedRoute contains the routing targets determined by the router for HBONE tunneling.
type ResolvedRoute struct {
	TargetHost  string // The HBONE destination node address (e.g. "192.168.1.100:15008")
	RealDest    string // The final endpoint address (e.g. "10.10.10.15:8080")
	ServiceID   string // The target service instance ID (e.g. "sample-1")
	Namespace   string // The destination service namespace
	ServiceName string // The destination service name
}
