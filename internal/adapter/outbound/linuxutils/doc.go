// Package linuxutils provides Linux helpers shared by the netfilter-based packet
// processors (nftables, iptables): recovering the pre-NAT destination of redirected
// connections, finding the process that owns a socket and resolving its identity.
//
// The /proc parsers live in untagged files so they can be unit-tested on any OS;
// the syscall-based functions are only built on Linux.
package linuxutils
