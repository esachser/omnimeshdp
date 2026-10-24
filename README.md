# OmniMesh Data Plane (`omnimeshdp`)

This project serves as the **Data Plane** for OmniMesh, implemented in Go. It provides high-performance networking functionality, transparent packet interception, and traffic management across mesh environments.

## Overview

`omnimeshdp` acts as the data plane agent for OmniMesh:
- Intercepts and redirects network traffic using OS-level mechanisms.
- Proxies traffic over HTTP/2 HBONE tunnels (CONNECT method) with SPIFFE/process identity.
- Connects to the OmniMesh Control Plane (`omnimeshcontrol`) via bidirectional gRPC stream to receive scope snapshots and routing updates.
- Designed with strict **Hexagonal Architecture (Ports & Adapters)**.

## Supported Platforms

- **Windows**:
  - **WinDivert**: User-mode packet interception and NAT rewriting via WinDivert.
  - **WFP (Windows Filtering Platform)**: Native kernel-level packet redirection via the `\\.\Omnimesh` driver.
- **Linux**:
  - **nftables**: Redirects outbound TCP for the configured subnets to the internal port via a dedicated `table ip omnimesh` (nat/output, `redirect`).
  - **iptables**: Fallback using a dedicated `OMNIMESH_OUTPUT` chain in the `nat` table, hooked from `OUTPUT`.
  - Original destinations are recovered with `SO_ORIGINAL_DST`; caller identity is the effective UID of the owning process.
  - Rules are replaced atomically (`nft -f` / `iptables-restore --noflush`), so subnets can be updated at runtime.
- **Cross-Platform**:
  - Fallback No-Op processor for compilation and testing on other platforms (e.g. macOS).

## Architecture

```
internal/
├── domain/       # Pure models, entities, value objects & errors
├── port/         # Inbound & outbound contracts (interfaces)
├── application/  # Proxy services and control plane agent orchestration
└── adapter/      # Concrete implementations (WinDivert, WFP, gRPC, HBONE, WinUtils)
```

## Running

### Prerequisites

On Windows with WinDivert:
```powershell
# Set WinDivert DLL path
.\script\prep-env-windows.ps1
```

### Build

```powershell
go build -o bin/omnimeshdp.exe ./cmd/omnimeshdp
```

### Execution

Run as Administrator on Windows:
```powershell
# Default (WFP)
.\bin\omnimeshdp.exe

# With WinDivert
.\bin\omnimeshdp.exe --windivert
```

On Linux, run as root (or with `CAP_NET_ADMIN`; reading other users' `/proc/<pid>/fd` for caller identity also needs root or `CAP_SYS_PTRACE`):
```bash
# Auto-detect: nftables if available, otherwise iptables
sudo ./bin/omnimeshdp

# Force a backend
sudo INTERCEPTION_TYPE=iptables ./bin/omnimeshdp
```

The proxy marks its own outbound sockets with `SO_MARK 0x10ed` (see `internal/adapter/sockmark`) and the rules skip that mark, preventing redirect loops. Rules are removed on shutdown and replaced on the next start if the process crashed.
