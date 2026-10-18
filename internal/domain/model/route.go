package model

// ResolvedRoute contains the routing targets determined by the router for HBONE tunneling.
type ResolvedRoute struct {
	TargetHost string // The HBONE destination node address (e.g. "192.168.1.100:15008")
	RealDest   string // The final endpoint address (e.g. "10.10.10.15:8080")
}
