package model

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// AppConfig represents the complete configuration for OmnimeshDP.
type AppConfig struct {
	Spire         SpireConfig         `json:"spire"`
	Listeners     ListenersConfig     `json:"listeners"`
	ControlPlane  ControlPlaneConfig  `json:"control_plane"`
	Interception  InterceptionConfig  `json:"interception"`
	Routing       RoutingConfig       `json:"routing"`
	HTTP          HTTPConfig          `json:"http"`
	Authorization AuthorizationConfig `json:"authorization"`
	Observability ObservabilityConfig `json:"observability"`
	Services      []NodeServiceInfo   `json:"services"`
	ServicesFile  string              `json:"services_file"`
	ServicesDir   string              `json:"services_dir"`
}

// SpireConfig holds configuration for the SPIFFE/SPIRE workload API agent.
type SpireConfig struct {
	SocketPath      string `json:"socket_path"`
	AdminSocketPath string `json:"admin_socket_path"`
	ServerSVID      string `json:"server_svid"`
	TrustDomain     string `json:"trust_domain"`
	Disabled        bool   `json:"disabled"`
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
		Routing:       DefaultRoutingConfig(),
		HTTP:          DefaultHTTPConfig(),
		Authorization: DefaultAuthorizationConfig(),
		Observability: DefaultObservabilityConfig(),
		Services:      make([]NodeServiceInfo, 0),
		ServicesDir:   "./services.d/",
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
	if adminSock := os.Getenv("SPIRE_ADMIN_SOCKET_PATH"); adminSock != "" {
		cfg.Spire.AdminSocketPath = adminSock
	}
	if td := os.Getenv("SPIRE_TRUST_DOMAIN"); td != "" {
		cfg.Spire.TrustDomain = td
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
	if maxRetriesStr, ok := os.LookupEnv("ROUTING_DEFAULT_MAX_RETRIES"); ok && maxRetriesStr != "" {
		maxRetries, err := strconv.Atoi(strings.TrimSpace(maxRetriesStr))
		if err != nil {
			return nil, fmt.Errorf("invalid ROUTING_DEFAULT_MAX_RETRIES %q: %w", maxRetriesStr, err)
		}
		cfg.Routing.DefaultMaxRetries = maxRetries
	}
	if backoffBase := os.Getenv("ROUTING_DEFAULT_BACKOFF_BASE"); backoffBase != "" {
		cfg.Routing.DefaultBackoffBase = backoffBase
	}
	if backoffMax := os.Getenv("ROUTING_DEFAULT_BACKOFF_MAX"); backoffMax != "" {
		cfg.Routing.DefaultBackoffMax = backoffMax
	}
	if connectTimeout := os.Getenv("ROUTING_CONNECT_TIMEOUT"); connectTimeout != "" {
		cfg.Routing.ConnectTimeout = connectTimeout
	}
	if retryOnConnFail, ok := os.LookupEnv("ROUTING_RETRY_ON_CONNECT_FAILURE"); ok && retryOnConnFail != "" {
		cfg.Routing.RetryOnConnectFailure = parseBoolValue(retryOnConnFail)
	}
	if err := applyHTTPEnvOverrides(&cfg.HTTP); err != nil {
		return nil, err
	}
	applyAuthzEnvOverrides(&cfg.Authorization)
	if err := applyObservabilityEnvOverrides(&cfg.Observability); err != nil {
		return nil, err
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
	if err := c.Routing.Validate(); err != nil {
		return fmt.Errorf("invalid routing configuration: %w", err)
	}
	if err := c.HTTP.Validate(); err != nil {
		return fmt.Errorf("invalid HTTP configuration: %w", err)
	}
	if err := c.Authorization.Validate(); err != nil {
		return fmt.Errorf("invalid authorization configuration: %w", err)
	}
	if err := c.Observability.Validate(); err != nil {
		return fmt.Errorf("invalid observability configuration: %w", err)
	}
	return nil
}

func parseBoolValue(v string) bool {
	trimmed := strings.TrimSpace(v)
	return strings.EqualFold(trimmed, "true") || trimmed == "1"
}

func applyEnvBool(key string, target *bool) {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		*target = parseBoolValue(val)
	}
}

func applyEnvString(key string, target *string) {
	if val := os.Getenv(key); val != "" {
		*target = val
	}
}

func applyEnvInt(key string, target *int) error {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			return fmt.Errorf("invalid %s %q: %w", key, val, err)
		}
		*target = n
	}
	return nil
}

func applyHTTPEnvOverrides(httpCfg *HTTPConfig) error {
	applyEnvBool("HTTP_L7_ENABLED", &httpCfg.Enabled)
	applyEnvBool("HTTP_OUTBOUND_ENABLED", &httpCfg.Outbound.Enabled)
	applyEnvBool("HTTP_INBOUND_ENABLED", &httpCfg.Inbound.Enabled)
	applyEnvString("HTTP_SNIFF_TIMEOUT", &httpCfg.SniffTimeout)
	if err := applyEnvInt("HTTP_MAX_SNIFF_BYTES", &httpCfg.MaxSniffBytes); err != nil {
		return err
	}
	if err := applyEnvInt("HTTP_MAX_HEADER_BYTES", &httpCfg.MaxHeaderBytes); err != nil {
		return err
	}
	applyEnvString("HTTP_IDLE_TIMEOUT", &httpCfg.IdleTimeout)
	applyEnvBool("HTTP_FAIL_OPEN", &httpCfg.FailOpen)

	applyEnvBool("HTTP_TRACING_ENABLED", &httpCfg.Tracing.Enabled)
	applyEnvBool("HTTP_TRACING_GENERATE_TRACEPARENT", &httpCfg.Tracing.GenerateTraceparent)
	applyEnvString("HTTP_TRACING_MODE", &httpCfg.Tracing.TraceparentMode)
	applyEnvBool("HTTP_TRACING_DEFAULT_SAMPLED", &httpCfg.Tracing.DefaultSampled)
	applyEnvBool("HTTP_TRACING_GENERATE_REQUEST_ID", &httpCfg.Tracing.GenerateRequestID)
	applyEnvString("HTTP_TRACING_REQUEST_ID_HEADER", &httpCfg.Tracing.RequestIDHeader)
	applyEnvBool("HTTP_TRACING_ECHO_RESPONSE", &httpCfg.Tracing.EchoResponseHeaders)

	applyEnvBool("HTTP_MESH_HEADERS_ENABLED", &httpCfg.MeshHeaders.Enabled)
	return nil
}

func applyAuthzEnvOverrides(authzCfg *AuthorizationConfig) {
	applyEnvString("AUTHZ_MODE", &authzCfg.Mode)
	applyEnvString("AUTHZ_NAMESPACE_DEFAULT_ISOLATION", &authzCfg.NamespaceDefaultIsolation)
	if val, ok := os.LookupEnv("AUTHZ_ALLOW_UNVERIFIED_IDENTITY"); ok && strings.TrimSpace(val) != "" {
		parsed := parseBoolValue(val)
		authzCfg.AllowUnverifiedIdentity = &parsed
	}
	applyEnvBool("AUTHZ_ENFORCE_L7", &authzCfg.EnforceL7)
	applyEnvString("AUTHZ_TRUST_DOMAIN", &authzCfg.TrustDomain)
	applyEnvBool("AUTHZ_AUDIT_LOG_ALLOWS", &authzCfg.AuditLogAllows)
}

func applyObservabilityEnvOverrides(obsCfg *ObservabilityConfig) error {
	applyEnvBool("OBSERVABILITY_METRICS_ENABLED", &obsCfg.Metrics.Enabled)
	applyEnvString("OBSERVABILITY_METRICS_ENDPOINT", &obsCfg.Metrics.Endpoint)
	applyEnvString("OBSERVABILITY_METRICS_PATH", &obsCfg.Metrics.Path)
	applyEnvString("OBSERVABILITY_METRICS_EXPORT_INTERVAL", &obsCfg.Metrics.ExportInterval)
	applyEnvBool("OBSERVABILITY_METRICS_COMBINED_REQUEST_ENABLED", &obsCfg.Metrics.CombinedRequestMetric.Enabled)

	if ep := firstNonEmptyEnv("OBSERVABILITY_METRICS_OTLP_ENDPOINT"); ep != "" {
		proto := normalizeOTLPProtocol(firstNonEmptyEnv("OBSERVABILITY_METRICS_OTLP_PROTOCOL"))
		insecure := parseOptionalEnvBool("OBSERVABILITY_METRICS_OTLP_INSECURE")
		upsertOTLPExporter(&obsCfg.Metrics.Exporters, proto, ep, insecure)
	}

	applyEnvBool("OBSERVABILITY_TRACES_ENABLED", &obsCfg.Traces.Enabled)
	if sampler := firstNonEmptyEnv("OBSERVABILITY_TRACES_SAMPLER", "OTEL_TRACES_SAMPLER"); sampler != "" {
		obsCfg.Traces.Sampler = sampler
	}
	if rateStr := firstNonEmptyEnv("OBSERVABILITY_TRACES_SAMPLE_RATE", "OTEL_TRACES_SAMPLER_ARG"); rateStr != "" {
		rate, err := strconv.ParseFloat(strings.TrimSpace(rateStr), 64)
		if err != nil {
			return fmt.Errorf("invalid trace sample rate %q: %w", rateStr, err)
		}
		obsCfg.Traces.SampleRate = rate
	}
	applyEnvBool("OBSERVABILITY_TRACES_ALWAYS_SAMPLE_ERRORS", &obsCfg.Traces.AlwaysSampleErrors)
	if err := applyEnvInt("OBSERVABILITY_TRACES_MAX_ERROR_TRACES_PER_SEC", &obsCfg.Traces.MaxErrorTracesPerSec); err != nil {
		return err
	}

	if ep := firstNonEmptyEnv(
		"OBSERVABILITY_TRACES_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
	); ep != "" {
		proto := normalizeOTLPProtocol(firstNonEmptyEnv(
			"OBSERVABILITY_TRACES_OTLP_PROTOCOL",
			"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
			"OTEL_EXPORTER_OTLP_PROTOCOL",
		))
		insecure := parseOptionalEnvBool("OBSERVABILITY_TRACES_OTLP_INSECURE")
		upsertOTLPExporter(&obsCfg.Traces.Exporters, proto, ep, insecure)
	}

	if svcName := firstNonEmptyEnv("OBSERVABILITY_SERVICE_NAME", "OTEL_SERVICE_NAME"); svcName != "" {
		obsCfg.Resource.ServiceName = svcName
	}
	applyEnvString("OBSERVABILITY_SERVICE_NAMESPACE", &obsCfg.Resource.ServiceNamespace)
	applyEnvString("OBSERVABILITY_DEPLOYMENT_ENVIRONMENT", &obsCfg.Resource.DeploymentEnvironment)

	return nil
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func parseOptionalEnvBool(key string) *bool {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		parsed := parseBoolValue(val)
		return &parsed
	}
	return nil
}

func normalizeOTLPProtocol(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "http", "http/protobuf", "otlp-http":
		return "otlp-http"
	default:
		return "otlp-grpc"
	}
}

func upsertOTLPExporter(exporters *[]TelemetryExporterConfig, typ, target string, insecure *bool) {
	for i := range *exporters {
		existingType := strings.ToLower(strings.TrimSpace((*exporters)[i].Type))
		if existingType == "otlp-grpc" || existingType == "otlp-http" {
			(*exporters)[i].Type = typ
			(*exporters)[i].Target = target
			if insecure != nil {
				(*exporters)[i].Insecure = *insecure
			}
			return
		}
	}
	exp := TelemetryExporterConfig{
		Type:   typ,
		Target: target,
	}
	if insecure != nil {
		exp.Insecure = *insecure
	}
	*exporters = append(*exporters, exp)
}
