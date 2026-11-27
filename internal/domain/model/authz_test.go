package model_test

import (
	"testing"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestParseSPIFFEIdentity(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantOK     bool
		wantTD     string
		wantNS     string
		wantSvc    string
		wantWorkld bool
	}{
		{
			name:       "canonical workload SPIFFE ID",
			raw:        "spiffe://omnimesh.local/ns/production/sa/order-service",
			wantOK:     true,
			wantTD:     "omnimesh.local",
			wantNS:     "production",
			wantSvc:    "order-service",
			wantWorkld: true,
		},
		{
			name:       "non-workload agent SPIFFE ID",
			raw:        "spiffe://omnimesh.corp/spire/agent/k8s/node-1",
			wantOK:     true,
			wantTD:     "omnimesh.corp",
			wantWorkld: false,
		},
		{
			name:       "trust domain only",
			raw:        "spiffe://partner.corp",
			wantOK:     true,
			wantTD:     "partner.corp",
			wantWorkld: false,
		},
		{name: "empty string", raw: "", wantOK: false},
		{name: "wrong scheme", raw: "https://omnimesh.local/ns/prod/sa/app", wantOK: false},
		{name: "missing trust domain", raw: "spiffe:///ns/prod/sa/app", wantOK: false},
		{name: "uppercase trust domain", raw: "spiffe://Omnimesh.Local/ns/prod/sa/app", wantOK: false},
		{name: "query string rejected", raw: "spiffe://omnimesh.local/ns/prod/sa/app?x=1", wantOK: false},
		{name: "fragment rejected", raw: "spiffe://omnimesh.local/ns/prod/sa/app#frag", wantOK: false},
		{name: "dot-dot segment rejected", raw: "spiffe://omnimesh.local/ns/../sa/app", wantOK: false},
		{name: "dot segment rejected", raw: "spiffe://omnimesh.local/ns/./sa/app", wantOK: false},
		{name: "empty segment rejected", raw: "spiffe://omnimesh.local/ns//sa/app", wantOK: false},
		{name: "trailing slash rejected", raw: "spiffe://omnimesh.local/ns/prod/sa/app/", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := model.ParseSPIFFEIdentity(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ParseSPIFFEIdentity(%q) ok=%v, want %v (got=%+v)", tc.raw, ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.TrustDomain != tc.wantTD {
				t.Errorf("TrustDomain=%q, want %q", got.TrustDomain, tc.wantTD)
			}
			if got.IsWorkload != tc.wantWorkld {
				t.Errorf("IsWorkload=%v, want %v", got.IsWorkload, tc.wantWorkld)
			}
			if got.Namespace != tc.wantNS || got.ServiceName != tc.wantSvc {
				t.Errorf("Namespace/ServiceName=%q/%q, want %q/%q", got.Namespace, got.ServiceName, tc.wantNS, tc.wantSvc)
			}
		})
	}
}

func TestAuthorizationConfigValidationAndDefaults(t *testing.T) {
	def := model.DefaultAuthorizationConfig()
	if err := def.Validate(); err != nil {
		t.Fatalf("default authz config should be valid: %v", err)
	}
	if def.NormalizedMode() != model.AuthzModeStrict {
		t.Fatalf("expected default mode strict, got %q", def.NormalizedMode())
	}
	if def.NormalizedNamespaceDefaultIsolation() != model.NamespaceIsolationStrict {
		t.Fatalf("expected default isolation strict, got %q", def.NormalizedNamespaceDefaultIsolation())
	}
	if def.ShouldAllowUnverifiedIdentity(false) {
		t.Fatalf("expected allow_unverified=false when spire enabled")
	}
	if !def.ShouldAllowUnverifiedIdentity(true) {
		t.Fatalf("expected allow_unverified=true fallback when spire disabled")
	}
	explicitFalse := false
	def.AllowUnverifiedIdentity = &explicitFalse
	if def.ShouldAllowUnverifiedIdentity(true) {
		t.Fatalf("expected explicit allow_unverified=false to override spire disabled")
	}

	badCases := []struct {
		name string
		cfg  model.AuthorizationConfig
	}{
		{
			name: "invalid mode",
			cfg:  model.AuthorizationConfig{Mode: "yolo"},
		},
		{
			name: "invalid isolation",
			cfg:  model.AuthorizationConfig{Mode: "strict", NamespaceDefaultIsolation: "wide"},
		},
		{
			name: "invalid trust domain",
			cfg:  model.AuthorizationConfig{Mode: "strict", TrustDomain: "BadDomain"},
		},
		{
			name: "local policy missing name",
			cfg: model.AuthorizationConfig{
				Mode: "strict",
				LocalPolicies: []model.LocalAuthzPolicy{
					{Action: "allow"},
				},
			},
		},
		{
			name: "local policy invalid action",
			cfg: model.AuthorizationConfig{
				Mode: "strict",
				LocalPolicies: []model.LocalAuthzPolicy{
					{Name: "p1", Action: "drop"},
				},
			},
		},
		{
			name: "local policy invalid port",
			cfg: model.AuthorizationConfig{
				Mode: "strict",
				LocalPolicies: []model.LocalAuthzPolicy{
					{Name: "p1", Action: "allow", Ports: []int{70000}},
				},
			},
		},
		{
			name: "local policy invalid valid_from",
			cfg: model.AuthorizationConfig{
				Mode: "strict",
				LocalPolicies: []model.LocalAuthzPolicy{
					{Name: "p1", Action: "allow", ValidFrom: "not-a-timestamp"},
				},
			},
		},
		{
			name: "local policy valid_from after valid_until",
			cfg: model.AuthorizationConfig{
				Mode: "strict",
				LocalPolicies: []model.LocalAuthzPolicy{
					{
						Name:       "p1",
						Action:     "allow",
						ValidFrom:  "2026-05-02T00:00:00Z",
						ValidUntil: "2026-05-01T00:00:00Z",
					},
				},
			},
		},
		{
			name: "local policy invalid header name",
			cfg: model.AuthorizationConfig{
				Mode: "strict",
				LocalPolicies: []model.LocalAuthzPolicy{
					{
						Name:   "p1",
						Action: "allow",
						Rules: []model.AuthzRule{
							{HTTP: &model.HTTPAuthzRule{Headers: map[string]string{":authority": "bad"}}},
						},
					},
				},
			},
		},
	}

	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}
