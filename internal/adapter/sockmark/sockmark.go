// Package sockmark tags sockets opened by the proxy itself with a firewall mark
// (SO_MARK) so that Linux packet processors (nftables/iptables) can exempt the
// proxy's own outbound traffic from redirection and avoid redirect loops.
// On non-Linux platforms marking is a no-op.
package sockmark

// ProxyMark is the SO_MARK value set on every socket dialed by the proxy.
// It avoids bits commonly used by other components (kube-proxy 0x4000/0x8000,
// Cilium 0x0F00, Calico 0xFFFF0000).
const ProxyMark uint32 = 0x10ED
