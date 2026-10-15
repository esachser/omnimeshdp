package model

// OriginalPacketInfo holds the metadata of the original packet prior to interception.
// Layout matches C struct representation:
// - PID: 8 bytes
// - IP: 4 bytes
// - Port: 2 bytes
// - Padding: 2 bytes (total 16 bytes)
type OriginalPacketInfo struct {
	PID  uint64
	IP   uint32
	Port uint16
	_    uint16
}

// NatEntry stores original packet source/destination information in the NAT table.
type NatEntry struct {
	OriginalPort    uint16
	OriginalSrcAddr uint32
	OriginalDstAddr uint32
	PID             int32
}
