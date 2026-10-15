package model

// ProxyConfig represents configuration passed to the kernel WFP driver.
// Memory layout strictly matches C/Rust struct representation (24 bytes):
// - ProxyIP: uint32 (offset 0, 4 bytes)
// - ProxyPort: uint16 (offset 4, 2 bytes)
// - Padding: uint16 (offset 6, 2 bytes)
// - SelfPID: uint64 (offset 8, 8 bytes)
// - IPAddr: uint32 (offset 16, 4 bytes)
// - IPMask: uint32 (offset 20, 4 bytes)
type ProxyConfig struct {
	ProxyIP   uint32
	ProxyPort uint16
	_         uint16 // Explicit padding to ensure 8-byte alignment for SelfPID
	SelfPID   uint64
	IPAddr    uint32
	IPMask    uint32
}
