package model

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// AppConfig represents the complete configuration for OmnimeshDP.
type AppConfig struct {
	Spire        SpireConfig        `json:"spire"`
	Listeners    ListenersConfig    `json:"listeners"`
	ControlPlane ControlPlaneConfig `json:"control_plane"`
	Interception InterceptionConfig `json:"interception"`
	Services     []NodeServiceInfo  `json:"services"`
	ServicesFile string             `json:"services_file"`
	ServicesDir  string             `json:"services_dir"`
}

// SpireConfig holds configuration for the SPIFFE/SPIRE workload API agent.
type SpireConfig struct {
	SocketPath string `json:"socket_path"`
	ServerSVID string `json:"server_svid"`
	Disabled   bool   `json:"disabled"`
}

// ListenersConfig holds port/address configuration for local interception and mesh proxying.
type ListenersConfig struct {
	InternalAddr string `json:"internal_addr"`
	ExternalAddr string `json:"external_addr"`
}

// ControlPlaneConfig holds connection information for omnimeshcontrol.
type ControlPlaneConfig struct {
	Address       string            `json:"address"`
	NodeID        string            `json:"node_id"`
	Target        string            `json:"target"`
	Labels        map[string]string `json:"labels"`
	RetryInterval string            `json:"retry_interval"` // Reconnection backoff interval, e.g. "5s"
}

// InterceptionConfig holds packet interception configuration.
type InterceptionConfig struct {
	Type string `json:"type"` // Windows: "wfp", "windivert"; Linux: "auto", "nftables", "iptables"; any: "noop"
}

// DefaultConfig returns default configuration values.
func DefaultConfig() *AppConfig {
	return &AppConfig{
		Spire: SpireConfig{
			SocketPath: "npipe:\\spire-agent\\public\\api",
			ServerSVID: "spiffe://omnimesh.local/ns/omnimesh-system/sa/omnimeshcontrol",
			Disabled:   false,
		},
		Listeners: ListenersConfig{
			InternalAddr: "127.0.0.1:15001",
			ExternalAddr: "0.0.0.0:15008",
		},
		ControlPlane: ControlPlaneConfig{
			Address:       "https://127.0.0.1:9091",
			NodeID:        "node-1",
			Target:        "default",
			RetryInterval: "5s",
		},
		Interception: InterceptionConfig{
			Type: "wfp",
		},
		Services:    make([]NodeServiceInfo, 0),
		ServicesDir: "./services.d/",
	}
}

// LoadConfig loads configuration from an optional file path and merges with environment variables.
func LoadConfig(configPath string) (*AppConfig, error) {
	cfg := DefaultConfig()

	// Check environment variable for config file if not provided
	if configPath == "" {
		configPath = os.Getenv("CONFIG_FILE")
	}

	// 1. Read from configuration file if specified
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %q: %w", configPath, err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %q: %w", configPath, err)
		}
	}

	// 2. Override from environment variables
	if svid := os.Getenv("CP_SERVER_SVID"); svid != "" {
		cfg.Spire.ServerSVID = svid
	}
	if sock := os.Getenv("CP_SOCKET_PATH"); sock != "" {
		cfg.Spire.SocketPath = sock
	}
	if spireDisabled := os.Getenv("SPIRE_DISABLED"); spireDisabled != "" {
		cfg.Spire.Disabled = strings.ToLower(spireDisabled) == "true" || spireDisabled == "1"
	}
	if internalAddr := os.Getenv("INTERNAL_LISTEN_ADDR"); internalAddr != "" {
		cfg.Listeners.InternalAddr = internalAddr
	}
	if externalAddr := os.Getenv("EXTERNAL_LISTEN_ADDR"); externalAddr != "" {
		cfg.Listeners.ExternalAddr = externalAddr
	}
	if cpAddr := os.Getenv("CONTROL_PLANE_ADDR"); cpAddr != "" {
		cfg.ControlPlane.Address = cpAddr
	}
	if nodeID := os.Getenv("NODE_ID"); nodeID != "" {
		cfg.ControlPlane.NodeID = nodeID
	}
	if target := os.Getenv("NETWORK_TARGET"); target != "" {
		cfg.ControlPlane.Target = target
	}
	if cpRetry := os.Getenv("CONTROL_PLANE_RETRY_INTERVAL"); cpRetry != "" {
		cfg.ControlPlane.RetryInterval = cpRetry
	}
	if interceptType := os.Getenv("INTERCEPTION_TYPE"); interceptType != "" {
		cfg.Interception.Type = interceptType
	}
	if svcFile := os.Getenv("SERVICES_FILE"); svcFile != "" {
		cfg.ServicesFile = svcFile
	}
	if svcDir := os.Getenv("SERVICES_DIR"); svcDir != "" {
		cfg.ServicesDir = svcDir
	}

	// 3. Read services file if specified
	if cfg.ServicesFile != "" {
		fileServices, err := ReadServicesFromFile(cfg.ServicesFile)
		if err != nil {
			return nil, err
		}
		cfg.Services = append(cfg.Services, fileServices...)
	}

	// 4. Read services directory if specified
	if cfg.ServicesDir != "" {
		dirServices, err := ReadServicesFromDir(cfg.ServicesDir)
		if err != nil {
			return nil, err
		}
		cfg.Services = MergeServices(cfg.Services, dirServices)
	}

	// 5. Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for correctness.
func (c *AppConfig) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listeners.InternalAddr); err != nil {
		return fmt.Errorf("invalid internal listen address %q: %w", c.Listeners.InternalAddr, err)
	}
	if _, _, err := net.SplitHostPort(c.Listeners.ExternalAddr); err != nil {
		return fmt.Errorf("invalid external listen address %q: %w", c.Listeners.ExternalAddr, err)
	}
	return nil
}
