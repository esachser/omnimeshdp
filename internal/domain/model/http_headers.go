package model

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
	"golang.org/x/net/http/httpguts"
)

// TrafficDirection identifies whether traffic is passing through the source (outbound)
// or destination (inbound) data plane proxy.
type TrafficDirection string

const (
	DirectionOutbound TrafficDirection = "outbound"
	DirectionInbound  TrafficDirection = "inbound"
)

// HTTPProtocol represents the effective or detected L7 protocol for a connection.
type HTTPProtocol string

const (
	ProtocolAuto  HTTPProtocol = "auto"
	ProtocolTCP   HTTPProtocol = "tcp"
	ProtocolHTTP  HTTPProtocol = "http"
	ProtocolHTTP1 HTTPProtocol = "http1"
	ProtocolHTTP2 HTTPProtocol = "http2"
)

const (
	// DefaultSniffTimeout is the maximum duration to wait for initial client bytes during protocol detection.
	DefaultSniffTimeout = 100 * time.Millisecond
	// MaxAllowedSniffTimeout bounds configured sniff timeouts to protect server-speaks-first protocols.
	MaxAllowedSniffTimeout = 5 * time.Second
	// DefaultMaxSniffBytes is the maximum initial bytes inspected while sniffing HTTP/1.1 vs HTTP/2.
	DefaultMaxSniffBytes = 4096
	// DefaultMaxHeaderBytes limits HTTP header sizes parsed by the L7 proxy.
	DefaultMaxHeaderBytes = 65536
)

// NormalizeProtocol maps Control Plane or local service protocol strings into a canonical HTTPProtocol.
func NormalizeProtocol(raw string) HTTPProtocol {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return ProtocolAuto
	case "tcp":
		return ProtocolTCP
	case "http":
		return ProtocolHTTP
	case "http1", "http/1.0", "http/1.1", "http1.1":
		return ProtocolHTTP1
	case "http2", "http/2", "h2c", "grpc", "grpc-web":
		return ProtocolHTTP2
	default:
		return ProtocolAuto
	}
}

// ConnectionMeta carries connection-level mesh identity and routing context into the L7 HTTP pipeline.
type ConnectionMeta struct {
	Direction       TrafficDirection
	ConfiguredProto HTTPProtocol
	DetectedProto   HTTPProtocol
	SourceNodeID    string
	DestNodeID      string
	CallerIdentity  string
	CallerVerified  bool
	SourceAddr      string
	DestAddr        string
	Namespace       string
	ServiceName     string
	NodeServiceID   string
	ServiceLabels   map[string]string
}

// TraceContext stores parsed W3C Trace Context fields for a single HTTP request.
type TraceContext struct {
	Version          byte
	TraceID          [16]byte
	ParentID         [8]byte
	IncomingParentID [8]byte
	TraceFlags       byte
	TraceState       string
	Valid            bool
	Incoming         bool
	Generated        bool
}

// TraceIDHex returns the 32-character lowercase hex W3C trace ID, or "" if invalid.
func (t TraceContext) TraceIDHex() string {
	if !t.Valid {
		return ""
	}
	return hex.EncodeToString(t.TraceID[:])
}

// ParentIDHex returns the 16-character lowercase hex W3C parent/span ID, or "" if invalid.
func (t TraceContext) ParentIDHex() string {
	if !t.Valid {
		return ""
	}
	return hex.EncodeToString(t.ParentID[:])
}

// FormatTraceparent encodes the W3C traceparent header value, or "" if invalid.
func (t TraceContext) FormatTraceparent() string {
	if !t.Valid {
		return ""
	}
	return fmt.Sprintf("%02x-%s-%s-%02x",
		t.Version,
		hex.EncodeToString(t.TraceID[:]),
		hex.EncodeToString(t.ParentID[:]),
		t.TraceFlags,
	)
}

// HTTPRequestContext represents an in-flight HTTP/1.1 or HTTP/2 request passed to HeaderInterceptors.
type HTTPRequestContext struct {
	Method        string
	URL           *url.URL
	Host          string
	ProtoMajor    int
	ProtoMinor    int
	Headers       http.Header
	Trailers      http.Header
	ContentLength int64
	StartTime     time.Time

	TraceContext TraceContext
	RequestID    string
	Attributes   map[string]any
}

// HTTPResponseContext represents an upstream HTTP/1.1 or HTTP/2 response passed to HeaderInterceptors.
type HTTPResponseContext struct {
	StatusCode int
	ProtoMajor int
	ProtoMinor int
	Headers    http.Header
	Trailers   http.Header
	Duration   time.Duration
	BytesIn    int64
	BytesOut   int64
}

// DirectionToggleConfig enables or disables L7 HTTP inspection for a traffic direction.
type DirectionToggleConfig struct {
	Enabled bool `json:"enabled"`
}

// TracingConfig configures W3C traceparent/tracestate and x-request-id inspection/injection.
type TracingConfig struct {
	Enabled             bool   `json:"enabled"`
	GenerateTraceparent bool   `json:"generate_traceparent"`
	TraceparentMode     string `json:"traceparent_mode"` // "preserve" or "new_span"
	DefaultSampled      bool   `json:"default_sampled"`
	GenerateRequestID   bool   `json:"generate_request_id"`
	RequestIDHeader     string `json:"request_id_header"`
	EchoResponseHeaders bool   `json:"echo_response_headers"`
}

// MeshHeadersConfig configures anti-spoofing sanitization and authoritative OmniMesh metadata injection.
type MeshHeadersConfig struct {
	Enabled                 bool   `json:"enabled"`
	StripPrefixOnInbound    string `json:"strip_prefix_on_inbound"`
	StripUntrustedOutbound  bool   `json:"strip_untrusted_on_outbound"`
	AllowUnverifiedIdentity *bool  `json:"allow_unverified_identity,omitempty"`
	InjectCallerIdentity    bool   `json:"inject_caller_identity"`
	InjectSourceNode        bool   `json:"inject_source_node"`
	InjectDestNode          bool   `json:"inject_dest_node"`
	InjectDestService       bool   `json:"inject_dest_service"`
	InjectNodeServiceID     bool   `json:"inject_node_service_id"`
	InjectXForwardedFor     bool   `json:"inject_x_forwarded_for"`
}

// ShouldAllowUnverifiedIdentity resolves whether unverified caller identities may be stamped,
// defaulting to spireDisabled when AllowUnverifiedIdentity is not explicitly set.
func (m MeshHeadersConfig) ShouldAllowUnverifiedIdentity(spireDisabled bool) bool {
	if m.AllowUnverifiedIdentity != nil {
		return *m.AllowUnverifiedIdentity
	}
	return spireDisabled
}

// RuleMatch specifies optional predicates that must all match for a HeaderRule to execute.
type RuleMatch struct {
	Namespaces   []string          `json:"namespaces,omitempty"`
	Services     []string          `json:"services,omitempty"`
	Methods      []string          `json:"methods,omitempty"`
	PathPrefix   string            `json:"path_prefix,omitempty"`
	HeaderExists string            `json:"header_exists,omitempty"`
	HeaderEquals map[string]string `json:"header_equals,omitempty"`
}

// HeaderRule defines a declarative header mutation rule.
type HeaderRule struct {
	Name      string    `json:"name"`
	Phase     string    `json:"phase"`     // "request" or "response"
	Direction string    `json:"direction"` // "both", "outbound", "inbound", or ""
	Action    string    `json:"action"`    // "set", "add", "set_if_absent", "append", "remove"
	Header    string    `json:"header"`
	Value     string    `json:"value,omitempty"`
	Match     RuleMatch `json:"match,omitempty"`
}

// HTTPConfig configures HTTP/1.1 and HTTP/2 L7 header inspection and injection.
type HTTPConfig struct {
	Enabled        bool                  `json:"enabled"`
	Outbound       DirectionToggleConfig `json:"outbound"`
	Inbound        DirectionToggleConfig `json:"inbound"`
	SniffTimeout   string                `json:"sniff_timeout"`
	MaxSniffBytes  int                   `json:"max_sniff_bytes"`
	MaxHeaderBytes int                   `json:"max_header_bytes"`
	IdleTimeout    string                `json:"idle_timeout"`
	FailOpen       bool                  `json:"fail_open"`
	Tracing        TracingConfig         `json:"tracing"`
	MeshHeaders    MeshHeadersConfig     `json:"mesh_headers"`
	Rules          []HeaderRule          `json:"rules,omitempty"`
}

// DefaultHTTPConfig returns the default HTTP L7 inspection/injection configuration.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Enabled:        true,
		Outbound:       DirectionToggleConfig{Enabled: true},
		Inbound:        DirectionToggleConfig{Enabled: true},
		SniffTimeout:   "100ms",
		MaxSniffBytes:  DefaultMaxSniffBytes,
		MaxHeaderBytes: DefaultMaxHeaderBytes,
		IdleTimeout:    "0s",
		FailOpen:       false,
		Tracing: TracingConfig{
			Enabled:             true,
			GenerateTraceparent: true,
			TraceparentMode:     "preserve",
			DefaultSampled:      true,
			GenerateRequestID:   true,
			RequestIDHeader:     "x-request-id",
			EchoResponseHeaders: false,
		},
		MeshHeaders: MeshHeadersConfig{
			Enabled:                true,
			StripPrefixOnInbound:   "x-omnimesh-",
			StripUntrustedOutbound: true,
			InjectCallerIdentity:   true,
			InjectSourceNode:       true,
			InjectDestNode:         true,
			InjectDestService:      true,
			InjectNodeServiceID:    true,
			InjectXForwardedFor:    false,
		},
	}
}

// ParsedSniffTimeout returns the validated sniff timeout duration (defaulting if empty).
func (c HTTPConfig) ParsedSniffTimeout() (time.Duration, error) {
	if strings.TrimSpace(c.SniffTimeout) == "" {
		return DefaultSniffTimeout, nil
	}
	d, err := time.ParseDuration(c.SniffTimeout)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid sniff_timeout %q: %w", domain.ErrInvalidHTTPConfig, c.SniffTimeout, err)
	}
	if d <= 0 || d > MaxAllowedSniffTimeout {
		return 0, fmt.Errorf("%w: sniff_timeout must be > 0 and <= %s, got %v", domain.ErrInvalidHTTPConfig, MaxAllowedSniffTimeout, d)
	}
	return d, nil
}

// ParsedIdleTimeout returns the validated HTTP connection idle timeout duration.
func (c HTTPConfig) ParsedIdleTimeout() (time.Duration, error) {
	if strings.TrimSpace(c.IdleTimeout) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.IdleTimeout)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid idle_timeout %q: %w", domain.ErrInvalidHTTPConfig, c.IdleTimeout, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%w: idle_timeout must be >= 0, got %v", domain.ErrInvalidHTTPConfig, d)
	}
	return d, nil
}

// Validate checks HTTPConfig, TracingConfig, MeshHeadersConfig, and HeaderRules for correctness and safety.
func (c HTTPConfig) Validate() error {
	if _, err := c.ParsedSniffTimeout(); err != nil {
		return err
	}
	if c.MaxSniffBytes < 64 || c.MaxSniffBytes > 65536 {
		return fmt.Errorf("%w: max_sniff_bytes must be between 64 and 65536, got %d", domain.ErrInvalidHTTPConfig, c.MaxSniffBytes)
	}
	if c.MaxHeaderBytes < 4096 || c.MaxHeaderBytes > 1048576 {
		return fmt.Errorf("%w: max_header_bytes must be between 4096 and 1048576, got %d", domain.ErrInvalidHTTPConfig, c.MaxHeaderBytes)
	}
	if _, err := c.ParsedIdleTimeout(); err != nil {
		return err
	}

	if err := c.Tracing.validate(); err != nil {
		return err
	}
	if err := c.MeshHeaders.validate(); err != nil {
		return err
	}
	for i, rule := range c.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule[%d] (%s): %w", i, rule.Name, err)
		}
	}
	return nil
}

func (t TracingConfig) validate() error {
	mode := strings.ToLower(strings.TrimSpace(t.TraceparentMode))
	if mode == "" {
		mode = "preserve"
	}
	if mode != "preserve" && mode != "new_span" {
		return fmt.Errorf("%w: tracing.traceparent_mode must be \"preserve\" or \"new_span\", got %q", domain.ErrInvalidHTTPConfig, t.TraceparentMode)
	}
	reqIDHeader := strings.TrimSpace(t.RequestIDHeader)
	if reqIDHeader == "" {
		reqIDHeader = "x-request-id"
	}
	if err := ValidateHeaderName(reqIDHeader); err != nil {
		return fmt.Errorf("%w: tracing.request_id_header %w", domain.ErrInvalidHTTPConfig, err)
	}
	return nil
}

func (m MeshHeadersConfig) validate() error {
	if m.StripPrefixOnInbound == "" {
		return nil
	}
	if err := ValidateHeaderName(m.StripPrefixOnInbound); err != nil {
		return fmt.Errorf("%w: mesh_headers.strip_prefix_on_inbound %w", domain.ErrInvalidHTTPConfig, err)
	}
	if m.StripPrefixOnInbound != strings.ToLower(m.StripPrefixOnInbound) {
		return fmt.Errorf("%w: mesh_headers.strip_prefix_on_inbound must be lowercase, got %q", domain.ErrInvalidHTTPConfig, m.StripPrefixOnInbound)
	}
	return nil
}

// Validate checks a single HeaderRule for valid phase, direction, action, target header safety, and CR/LF safety.
func (r HeaderRule) Validate() error {
	switch strings.ToLower(strings.TrimSpace(r.Phase)) {
	case "request", "response":
	default:
		return fmt.Errorf("%w: phase must be \"request\" or \"response\", got %q", domain.ErrInvalidHTTPConfig, r.Phase)
	}

	switch strings.ToLower(strings.TrimSpace(r.Direction)) {
	case "", "both", "outbound", "inbound":
	default:
		return fmt.Errorf("%w: direction must be \"both\", \"outbound\", \"inbound\", or empty, got %q", domain.ErrInvalidHTTPConfig, r.Direction)
	}

	action := strings.ToLower(strings.TrimSpace(r.Action))
	switch action {
	case "set", "add", "set_if_absent", "append", "remove":
	default:
		return fmt.Errorf("%w: unsupported action %q", domain.ErrInvalidHTTPConfig, r.Action)
	}

	if err := ValidateMutableHeaderName(r.Header); err != nil {
		return err
	}

	if action != "remove" {
		if ContainsUnsafeHeaderChars(r.Value) || !httpguts.ValidHeaderFieldValue(r.Value) {
			return fmt.Errorf("%w: unsafe or invalid characters in header value for %q", domain.ErrInvalidHeader, r.Header)
		}
	}

	if r.Match.HeaderExists != "" {
		if err := ValidateHeaderName(r.Match.HeaderExists); err != nil {
			return fmt.Errorf("match.header_exists: %w", err)
		}
	}
	for k := range r.Match.HeaderEquals {
		if err := ValidateHeaderName(k); err != nil {
			return fmt.Errorf("match.header_equals key %q: %w", k, err)
		}
	}
	return nil
}

// ValidateHeaderName verifies that name is a valid non-empty RFC 9110 field-name token.
func ValidateHeaderName(name string) error {
	if name == "" || strings.HasPrefix(name, ":") || !httpguts.ValidHeaderFieldName(name) {
		return fmt.Errorf("%w: invalid header name %q", domain.ErrInvalidHeader, name)
	}
	return nil
}

// ValidateMutableHeaderName validates name as an HTTP header and rejects framing-critical headers.
func ValidateMutableHeaderName(name string) error {
	if err := ValidateHeaderName(name); err != nil {
		return err
	}
	if IsForbiddenHeader(name) {
		return fmt.Errorf("%w: header %q is framing-critical and cannot be modified by rules", domain.ErrInvalidHeader, name)
	}
	return nil
}

// IsForbiddenHeader reports whether name is a pseudo-header or framing-critical header.
func IsForbiddenHeader(name string) bool {
	if strings.HasPrefix(name, ":") {
		return true
	}
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "te", "upgrade",
		"connection", "keep-alive", "proxy-connection", "host":
		return true
	default:
		return false
	}
}

// ContainsUnsafeHeaderChars reports whether val contains CR, LF, or NUL bytes.
func ContainsUnsafeHeaderChars(val string) bool {
	return strings.ContainsAny(val, "\r\n\x00")
}

// SanitizeHeaderValue strips CR, LF, and NUL bytes from a header value.
func SanitizeHeaderValue(val string) string {
	if !ContainsUnsafeHeaderChars(val) {
		return val
	}
	var b strings.Builder
	b.Grow(len(val))
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case '\r', '\n', '\x00':
		default:
			b.WriteByte(val[i])
		}
	}
	return b.String()
}
