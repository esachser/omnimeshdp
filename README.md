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
- **Cross-Platform**:
  - Fallback No-Op processor for compilation and testing on Linux/macOS.

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
