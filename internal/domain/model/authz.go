package model

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
)

// AuthzMode defines the global authorization enforcement posture of the data plane.
type AuthzMode string

const (
	// AuthzModeStrict enforces zero-trust default-deny: traffic requires an explicit ALLOW
	// or same-namespace open isolation, and explicit DENY always takes precedence.
	AuthzModeStrict AuthzMode = "strict"
	// AuthzModePermissive logs missing policies but allows traffic unless explicitly denied.
	AuthzModePermissive AuthzMode = "permissive"
	// AuthzModeDryRun evaluates policies normally and logs what would be denied, but allows all traffic.
	AuthzModeDryRun AuthzMode = "dry_run"
	// AuthzModeDisabled bypasses authorization enforcement completely.
	AuthzModeDisabled AuthzMode = "disabled"
)

// ParseAuthzMode parses a global authorization mode string.
func ParseAuthzMode(raw string) (AuthzMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "strict":
		return AuthzModeStrict, true
	case "permissive":
		return AuthzModePermissive, true
	case "dry_run", "dry-run", "dryrun":
		return AuthzModeDryRun, true
	case "disabled":
		return AuthzModeDisabled, true
	default:
		return "", false
	}
}

// AuthzAction specifies whether a policy allows, denies, or dry-runs matching traffic.
type AuthzAction string

const (
	AuthzActionAllow  AuthzAction = "allow"
	AuthzActionDeny   AuthzAction = "deny"
	AuthzActionDryRun AuthzAction = "dry_run"
)

// ParseAuthzAction parses a policy action string (case-insensitive).
func ParseAuthzAction(raw string) (AuthzAction, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "allow":
		return AuthzActionAllow, true
	case "deny":
		return AuthzActionDeny, true
	case "dry_run", "dry-run", "dryrun":
		return AuthzActionDryRun, true
	default:
		return "", false
	}
}

// NamespaceIsolation controls intra-namespace default authorization when no explicit policy matches.
type NamespaceIsolation string

const (
	NamespaceIsolationStrict NamespaceIsolation = "strict"
	NamespaceIsolationOpen   NamespaceIsolation = "open"
)

// ParseNamespaceIsolation parses a namespace isolation mode string.
func ParseNamespaceIsolation(raw string) (NamespaceIsolation, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "strict":
		return NamespaceIsolationStrict, true
	case "open":
		return NamespaceIsolationOpen, true
	default:
		return "", false
	}
}

// AuthzLayer identifies whether authorization is evaluated at L4 connection setup or L7 request handling.
type AuthzLayer string

const (
	AuthzLayerL4 AuthzLayer = "l4"
	AuthzLayerL7 AuthzLayer = "l7"
)

// AuthzReason classifies why an authorization decision was reached.
type AuthzReason string

const (
	AuthzReasonExplicitAllow           AuthzReason = "explicit_allow"
	AuthzReasonExplicitAllowL7Deferred AuthzReason = "explicit_allow_l7_deferred"
	AuthzReasonNamespaceOpen           AuthzReason = "namespace_open"
	AuthzReasonExplicitDeny            AuthzReason = "explicit_deny"
	AuthzReasonNoPolicy                AuthzReason = "no_policy"
	AuthzReasonL7Mismatch              AuthzReason = "l7_mismatch"
	AuthzReasonUnauthenticated         AuthzReason = "unauthenticated"
	AuthzReasonInvalidIdentity         AuthzReason = "invalid_identity"
	AuthzReasonL7Required              AuthzReason = "l7_required"
	AuthzReasonDryRunPolicy            AuthzReason = "dry_run_policy"
	AuthzReasonPermissiveDefault       AuthzReason = "permissive_default"
	AuthzReasonDisabled                AuthzReason = "disabled"
)

// SPIFFEIdentity holds the parsed components of a SPIFFE URI.
type SPIFFEIdentity struct {
	Raw         string
	TrustDomain string
	Path        string
	Namespace   string
	ServiceName string
	IsWorkload  bool
}

// ParseSPIFFEIdentity parses and validates a SPIFFE URI according to the SPIFFE ID specification
// and extracts workload (namespace, service) from canonical /ns/<namespace>/sa/<service-name> paths.
func ParseSPIFFEIdentity(raw string) (SPIFFEIdentity, bool) {
	const prefix = "spiffe://"
	if !strings.HasPrefix(raw, prefix) {
		return SPIFFEIdentity{}, false
	}
	if strings.ContainsAny(raw, "?#\r\n\x00 \t") {
		return SPIFFEIdentity{}, false
	}

	rest := raw[len(prefix):]
	if rest == "" {
		return SPIFFEIdentity{}, false
	}

	var td, p string
	if idx := strings.IndexByte(rest, '/'); idx == -1 {
		td = rest
		p = ""
	} else {
		td = rest[:idx]
		p = rest[idx:]
	}

	if !isValidTrustDomain(td) {
		return SPIFFEIdentity{}, false
	}

	id := SPIFFEIdentity{
		Raw:         raw,
		TrustDomain: td,
		Path:        p,
	}

	if p == "" {
		return id, true
	}

	if strings.HasSuffix(p, "/") {
		return SPIFFEIdentity{}, false
	}

	segments := strings.Split(p[1:], "/")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return SPIFFEIdentity{}, false
		}
	}

	if len(segments) == 4 && segments[0] == "ns" && segments[2] == "sa" {
		id.Namespace = segments[1]
		id.ServiceName = segments[3]
		id.IsWorkload = true
	}

	return id, true
}

func isValidTrustDomain(td string) bool {
	if len(td) == 0 || len(td) > 255 {
		return false
	}
	for i := 0; i < len(td); i++ {
		c := td[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isPunct := c == '.' || c == '-' || c == '_'
		if !isLower && !isDigit && !isPunct {
			return false
		}
	}
	return true
}

// AuthzSelector selects source or destination workloads by identity, namespace, name, and labels.
type AuthzSelector struct {
	SpiffeID    string            `json:"spiffe_id,omitempty"`
	TrustDomain string            `json:"trust_domain,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Name        string            `json:"name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// HTTPAuthzRule restricts L7 HTTP requests matching this rule.
type HTTPAuthzRule struct {
	Methods      []string          `json:"methods,omitempty"`
	PathPrefixes []string          `json:"path_prefixes,omitempty"`
	PathExact    []string          `json:"path_exact,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// GRPCAuthzRule restricts L7 gRPC requests matching this rule.
type GRPCAuthzRule struct {
	Services []string `json:"services,omitempty"`
	Methods  []string `json:"methods,omitempty"`
}

// AuthzRule represents an L7 authorization rule (HTTP or gRPC).
type AuthzRule struct {
	HTTP *HTTPAuthzRule `json:"http,omitempty"`
	GRPC *GRPCAuthzRule `json:"grpc,omitempty"`
}

// AuthzPolicy is the normalized domain representation of an authorization policy.
type AuthzPolicy struct {
	Name             string
	Namespace        string
	Action           AuthzAction
	Source           AuthzSelector
	Destination      AuthzSelector
	DestinationPorts []int
	Rules            []AuthzRule
	ValidFrom        *time.Time
	ValidUntil       *time.Time
}

// LocalAuthzPolicy is the JSON-serializable configuration form of an AuthorizationPolicy
// (used for local bootstrap/fallback rules in AppConfig.Authorization.LocalPolicies).
type LocalAuthzPolicy struct {
	Name        string        `json:"name"`
	Namespace   string        `json:"namespace,omitempty"`
	Action      string        `json:"action"`
	Source      AuthzSelector `json:"source"`
	Destination AuthzSelector `json:"destination"`
	Ports       []int         `json:"ports,omitempty"`
	Rules       []AuthzRule   `json:"rules,omitempty"`
	ValidFrom   string        `json:"valid_from,omitempty"`
	ValidUntil  string        `json:"valid_until,omitempty"`
}

// ToPolicy validates and converts a LocalAuthzPolicy into a domain AuthzPolicy.
func (l LocalAuthzPolicy) ToPolicy() (AuthzPolicy, error) {
	name := strings.TrimSpace(l.Name)
	if name == "" {
		return AuthzPolicy{}, fmt.Errorf("%w: local policy name is required", domain.ErrInvalidAuthzConfig)
	}

	action, ok := ParseAuthzAction(l.Action)
	if !ok {
		return AuthzPolicy{}, fmt.Errorf("%w: policy %q has invalid action %q", domain.ErrInvalidAuthzConfig, name, l.Action)
	}

	if l.Source.SpiffeID != "" {
		if _, ok := ParseSPIFFEIdentity(l.Source.SpiffeID); !ok {
			return AuthzPolicy{}, fmt.Errorf("%w: policy %q has invalid source spiffe_id %q", domain.ErrInvalidAuthzConfig, name, l.Source.SpiffeID)
		}
	}
	if l.Source.TrustDomain != "" && !isValidTrustDomain(l.Source.TrustDomain) {
		return AuthzPolicy{}, fmt.Errorf("%w: policy %q has invalid source trust_domain %q", domain.ErrInvalidAuthzConfig, name, l.Source.TrustDomain)
	}
	if l.Destination.SpiffeID != "" {
		if _, ok := ParseSPIFFEIdentity(l.Destination.SpiffeID); !ok {
			return AuthzPolicy{}, fmt.Errorf("%w: policy %q has invalid destination spiffe_id %q", domain.ErrInvalidAuthzConfig, name, l.Destination.SpiffeID)
		}
	}
	if l.Destination.TrustDomain != "" && !isValidTrustDomain(l.Destination.TrustDomain) {
		return AuthzPolicy{}, fmt.Errorf("%w: policy %q has invalid destination trust_domain %q", domain.ErrInvalidAuthzConfig, name, l.Destination.TrustDomain)
	}

	for _, port := range l.Ports {
		if port < 1 || port > 65535 {
			return AuthzPolicy{}, fmt.Errorf("%w: policy %q has invalid port %d (must be 1..65535)", domain.ErrInvalidAuthzConfig, name, port)
		}
	}

	for i, rule := range l.Rules {
		if rule.HTTP == nil && rule.GRPC == nil {
			return AuthzPolicy{}, fmt.Errorf("%w: policy %q rule[%d] must specify http or grpc", domain.ErrInvalidAuthzConfig, name, i)
		}
		if rule.HTTP != nil {
			for k := range rule.HTTP.Headers {
				if err := ValidateHeaderName(k); err != nil {
					return AuthzPolicy{}, fmt.Errorf("%w: policy %q rule[%d] header %w", domain.ErrInvalidAuthzConfig, name, i, err)
				}
			}
		}
	}

	var validFrom, validUntil *time.Time
	if strings.TrimSpace(l.ValidFrom) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(l.ValidFrom))
		if err != nil {
			return AuthzPolicy{}, fmt.Errorf("%w: policy %q invalid valid_from %q: %v", domain.ErrInvalidAuthzConfig, name, l.ValidFrom, err)
		}
		validFrom = &t
	}
	if strings.TrimSpace(l.ValidUntil) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(l.ValidUntil))
		if err != nil {
			return AuthzPolicy{}, fmt.Errorf("%w: policy %q invalid valid_until %q: %v", domain.ErrInvalidAuthzConfig, name, l.ValidUntil, err)
		}
		validUntil = &t
	}
	if validFrom != nil && validUntil != nil && validFrom.After(*validUntil) {
		return AuthzPolicy{}, fmt.Errorf("%w: policy %q valid_from (%s) must be <= valid_until (%s)", domain.ErrInvalidAuthzConfig, name, l.ValidFrom, l.ValidUntil)
	}

	return AuthzPolicy{
		Name:             name,
		Namespace:        strings.TrimSpace(l.Namespace),
		Action:           action,
		Source:           l.Source,
		Destination:      l.Destination,
		DestinationPorts: append([]int(nil), l.Ports...),
		Rules:            append([]AuthzRule(nil), l.Rules...),
		ValidFrom:        validFrom,
		ValidUntil:       validUntil,
	}, nil
}

// HTTPAuthzAttributes carries L7 HTTP or gRPC request metadata evaluated by Authorizer.AuthorizeHTTP.
type HTTPAuthzAttributes struct {
	Method      string
	Path        string
	Headers     http.Header
	IsGRPC      bool
	GRPCService string
	GRPCMethod  string
	TraceID     string
	RequestID   string
}

// AuthzRequest describes an incoming L4 connection or L7 request to be authorized.
type AuthzRequest struct {
	Layer              AuthzLayer
	CallerIdentity     string
	CallerVerified     bool
	SourceNodeID       string
	SourceAddr         string
	SourceLabels       map[string]string
	DestNamespace      string
	DestServiceName    string
	DestNodeServiceID  string
	DestMeshIP         string
	DestPort           int
	DestProtocol       string
	DestLabels         map[string]string
	InboundL7Available bool
	HTTP               *HTTPAuthzAttributes
}

// AuthzDecision represents the outcome of evaluating an AuthzRequest.
type AuthzDecision struct {
	Allowed                 bool
	DryRun                  bool
	WouldDeny               bool
	RequiresL7              bool
	Reason                  AuthzReason
	MatchedPolicy           string
	Mode                    AuthzMode
	SourceIdentity          SPIFFEIdentity
	ResolvedDestNamespace   string
	ResolvedDestServiceName string
	ResolvedProtocol        string
	EvaluationDuration      time.Duration
}

// AuthzStats is a point-in-time snapshot of authorization engine counters.
type AuthzStats struct {
	AllowedTotal               uint64
	DeniedTotal                uint64
	DryRunWouldDenyTotal       uint64
	PermissiveAllowTotal       uint64
	DeniedNoPolicyTotal        uint64
	DeniedExplicitTotal        uint64
	DeniedL7MismatchTotal      uint64
	DeniedUnauthenticatedTotal uint64
	DeniedL7RequiredTotal      uint64
	PoliciesCached             int
}

// AuthorizationConfig configures data plane authorization enforcement per spec/authorization.md.
type AuthorizationConfig struct {
	Mode                      string             `json:"mode"`
	NamespaceDefaultIsolation string             `json:"namespace_default_isolation"`
	AllowUnverifiedIdentity   *bool              `json:"allow_unverified_identity,omitempty"`
	EnforceL7                 bool               `json:"enforce_l7"`
	TrustDomain               string             `json:"trust_domain,omitempty"`
	AuditLogAllows            bool               `json:"audit_log_allows"`
	LocalPolicies             []LocalAuthzPolicy `json:"local_policies,omitempty"`
}

// DefaultAuthorizationConfig returns the default zero-trust authorization configuration.
func DefaultAuthorizationConfig() AuthorizationConfig {
	return AuthorizationConfig{
		Mode:                      string(AuthzModeStrict),
		NamespaceDefaultIsolation: string(NamespaceIsolationStrict),
		EnforceL7:                 true,
		AuditLogAllows:            false,
	}
}

// NormalizedMode returns the canonical AuthzMode, defaulting empty strings to strict.
func (c AuthorizationConfig) NormalizedMode() AuthzMode {
	if mode, ok := ParseAuthzMode(c.Mode); ok {
		return mode
	}
	return AuthzModeStrict
}

// NormalizedNamespaceDefaultIsolation returns the canonical default NamespaceIsolation.
func (c AuthorizationConfig) NormalizedNamespaceDefaultIsolation() NamespaceIsolation {
	if iso, ok := ParseNamespaceIsolation(c.NamespaceDefaultIsolation); ok {
		return iso
	}
	return NamespaceIsolationStrict
}

// ShouldAllowUnverifiedIdentity resolves whether unverified caller identities are permitted,
// defaulting to spireDisabled unless explicitly overridden by AllowUnverifiedIdentity.
func (c AuthorizationConfig) ShouldAllowUnverifiedIdentity(spireDisabled bool) bool {
	if c.AllowUnverifiedIdentity != nil {
		return *c.AllowUnverifiedIdentity
	}
	return spireDisabled
}

// Validate checks AuthorizationConfig fields and any configured LocalPolicies.
func (c AuthorizationConfig) Validate() error {
	if _, ok := ParseAuthzMode(c.Mode); !ok {
		return fmt.Errorf("%w: mode must be \"strict\", \"permissive\", \"dry_run\", or \"disabled\", got %q",
			domain.ErrInvalidAuthzConfig, c.Mode)
	}
	if _, ok := ParseNamespaceIsolation(c.NamespaceDefaultIsolation); !ok {
		return fmt.Errorf("%w: namespace_default_isolation must be \"strict\" or \"open\", got %q",
			domain.ErrInvalidAuthzConfig, c.NamespaceDefaultIsolation)
	}
	if strings.TrimSpace(c.TrustDomain) != "" && !isValidTrustDomain(strings.TrimSpace(c.TrustDomain)) {
		return fmt.Errorf("%w: invalid trust_domain %q", domain.ErrInvalidAuthzConfig, c.TrustDomain)
	}
	for i, lp := range c.LocalPolicies {
		if _, err := lp.ToPolicy(); err != nil {
			return fmt.Errorf("local_policies[%d]: %w", i, err)
		}
	}
	return nil
}
