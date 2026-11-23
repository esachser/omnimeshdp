package model

import (
	"fmt"
	"time"
)

const (
	// DefaultMaxRetries is the default number of retry attempts after an initial routing failure.
	DefaultMaxRetries = 3
	// DefaultBackoffBase is the default initial backoff duration between routing retries.
	DefaultBackoffBase = 0 * time.Millisecond
	// DefaultBackoffMax is the default maximum backoff duration between routing retries.
	DefaultBackoffMax = 500 * time.Millisecond
	// DefaultConnectTimeout is the default per-attempt HBONE CONNECT handshake timeout.
	DefaultConnectTimeout = 5 * time.Second
)

// EndpointKey uniquely identifies a candidate service endpoint across route groups.
type EndpointKey struct {
	NodeID    string
	RouteName string
	Addr      string
}

// ResolvedRoute contains the routing targets determined by the router for HBONE tunneling.
type ResolvedRoute struct {
	TargetHost  string      // The HBONE destination node address (e.g. "192.168.1.100:15008")
	RealDest    string      // The final endpoint address (e.g. "10.10.10.15:8080")
	ServiceID   string      // The target service instance ID (e.g. "sample-1")
	NodeID      string      // The target node ID (e.g. "node-2")
	Namespace   string      // The destination service namespace
	ServiceName string      // The destination service name
	EndpointKey EndpointKey // Canonical key identifying the selected endpoint
}

// RetryConfig holds effective per-connection retry settings resolved from TrafficPolicy and AppConfig.
type RetryConfig struct {
	MaxRetries         int
	BackoffBase        time.Duration
	BackoffMax         time.Duration
	ConnectTimeout     time.Duration
	RetryOnConnectFail bool
	RetryOn5xx         bool
}

// RoutingConfig configures default data-plane routing and retry behavior when not
// overridden by a Control Plane TrafficPolicy.
type RoutingConfig struct {
	DefaultMaxRetries     int    `json:"default_max_retries"`
	DefaultBackoffBase    string `json:"default_backoff_base"`
	DefaultBackoffMax     string `json:"default_backoff_max"`
	ConnectTimeout        string `json:"connect_timeout"`
	RetryOnConnectFailure bool   `json:"retry_on_connect_failure,omitempty"`
}

// DefaultRoutingConfig returns the default data-plane routing configuration per spec/routing.md.
func DefaultRoutingConfig() RoutingConfig {
	return RoutingConfig{
		DefaultMaxRetries:     DefaultMaxRetries,
		DefaultBackoffBase:    "0ms",
		DefaultBackoffMax:     "500ms",
		ConnectTimeout:        "5s",
		RetryOnConnectFailure: false,
	}
}

// Validate validates the routing configuration values.
func (r RoutingConfig) Validate() error {
	_, err := r.ToRetryConfig()
	return err
}

// ToRetryConfig parses and validates RoutingConfig into a normalized RetryConfig.
func (r RoutingConfig) ToRetryConfig() (RetryConfig, error) {
	if r.DefaultMaxRetries < 0 {
		return RetryConfig{}, fmt.Errorf("default_max_retries must be >= 0, got %d", r.DefaultMaxRetries)
	}

	backoffBase := DefaultBackoffBase
	if r.DefaultBackoffBase != "" {
		d, err := time.ParseDuration(r.DefaultBackoffBase)
		if err != nil {
			return RetryConfig{}, fmt.Errorf("invalid default_backoff_base %q: %w", r.DefaultBackoffBase, err)
		}
		if d < 0 {
			return RetryConfig{}, fmt.Errorf("default_backoff_base must be >= 0, got %v", d)
		}
		backoffBase = d
	}

	backoffMax := DefaultBackoffMax
	if r.DefaultBackoffMax != "" {
		d, err := time.ParseDuration(r.DefaultBackoffMax)
		if err != nil {
			return RetryConfig{}, fmt.Errorf("invalid default_backoff_max %q: %w", r.DefaultBackoffMax, err)
		}
		if d < 0 {
			return RetryConfig{}, fmt.Errorf("default_backoff_max must be >= 0, got %v", d)
		}
		backoffMax = d
	}

	if backoffMax < backoffBase {
		return RetryConfig{}, fmt.Errorf("default_backoff_max (%v) must be >= default_backoff_base (%v)", backoffMax, backoffBase)
	}

	if r.ConnectTimeout == "" {
		return RetryConfig{}, fmt.Errorf("connect_timeout must be > 0")
	}
	connectTimeout, err := time.ParseDuration(r.ConnectTimeout)
	if err != nil {
		return RetryConfig{}, fmt.Errorf("invalid connect_timeout %q: %w", r.ConnectTimeout, err)
	}
	if connectTimeout <= 0 {
		return RetryConfig{}, fmt.Errorf("connect_timeout must be > 0, got %v", connectTimeout)
	}

	return RetryConfig{
		MaxRetries:         r.DefaultMaxRetries,
		BackoffBase:        backoffBase,
		BackoffMax:         backoffMax,
		ConnectTimeout:     connectTimeout,
		RetryOnConnectFail: r.RetryOnConnectFailure,
	}, nil
}
