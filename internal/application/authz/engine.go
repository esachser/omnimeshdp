package authz

import (
	"context"
	"log"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/inbound"
)

var (
	_ inbound.Authorizer         = (*Engine)(nil)
	_ inbound.AuthzPolicyUpdater = (*Engine)(nil)
)

type serviceKey struct {
	namespace string
	name      string
}

type policyKey struct {
	namespace string
	name      string
}

type serviceNodeKey struct {
	namespace string
	name      string
	nodeID    string
}

type rawAuthzState struct {
	cpPolicies    map[policyKey]*omnimeshv1.AuthzPolicyInfo
	localPolicies []model.AuthzPolicy
	namespaces    map[string]*omnimeshv1.NamespaceInfo
	servicesByIP  map[string]*omnimeshv1.ServiceInfo
	servicesByID  map[serviceKey]*omnimeshv1.ServiceInfo
	routes        map[serviceKey][]*omnimeshv1.NodeEndpointInfo
}

func newRawAuthzState(localPolicies []model.AuthzPolicy) *rawAuthzState {
	return &rawAuthzState{
		cpPolicies:    make(map[policyKey]*omnimeshv1.AuthzPolicyInfo),
		localPolicies: slices.Clone(localPolicies),
		namespaces:    make(map[string]*omnimeshv1.NamespaceInfo),
		servicesByIP:  make(map[string]*omnimeshv1.ServiceInfo),
		servicesByID:  make(map[serviceKey]*omnimeshv1.ServiceInfo),
		routes:        make(map[serviceKey][]*omnimeshv1.NodeEndpointInfo),
	}
}

func (s *rawAuthzState) clone() *rawAuthzState {
	cp := newRawAuthzState(s.localPolicies)
	if s == nil {
		return cp
	}
	for k, v := range s.cpPolicies {
		cp.cpPolicies[k] = v
	}
	for k, v := range s.namespaces {
		cp.namespaces[k] = v
	}
	for k, v := range s.servicesByIP {
		cp.servicesByIP[k] = v
	}
	for k, v := range s.servicesByID {
		cp.servicesByID[k] = v
	}
	for k, v := range s.routes {
		cp.routes[k] = slices.Clone(v)
	}
	return cp
}

func authzPolicyMapKey(p *omnimeshv1.AuthzPolicyInfo) policyKey {
	if p == nil {
		return policyKey{}
	}
	return policyKey{namespace: p.Namespace, name: p.Name}
}

func (s *rawAuthzState) upsertService(svc *omnimeshv1.ServiceInfo) {
	if svc == nil {
		return
	}
	sk := serviceKey{namespace: svc.Namespace, name: svc.Name}
	if svc.Namespace != "" || svc.Name != "" {
		for ip, existing := range s.servicesByIP {
			if existing.Namespace == svc.Namespace && existing.Name == svc.Name && ip != svc.MeshAddr {
				delete(s.servicesByIP, ip)
			}
		}
		s.servicesByID[sk] = svc
	}
	if svc.MeshAddr != "" {
		s.servicesByIP[svc.MeshAddr] = svc
	}
}

func (s *rawAuthzState) removeService(svc *omnimeshv1.ServiceInfo) {
	if svc == nil {
		return
	}
	if svc.MeshAddr != "" {
		delete(s.servicesByIP, svc.MeshAddr)
	}
	if svc.Namespace != "" || svc.Name != "" {
		delete(s.servicesByID, serviceKey{namespace: svc.Namespace, name: svc.Name})
		for ip, existing := range s.servicesByIP {
			if existing.Namespace == svc.Namespace && existing.Name == svc.Name {
				delete(s.servicesByIP, ip)
			}
		}
	}
}

func (s *rawAuthzState) upsertRoute(route *omnimeshv1.RouteInfo) {
	if route == nil {
		return
	}
	sk := serviceKey{namespace: route.Namespace, name: route.ServiceName}
	endpoints := s.routes[sk]
	for _, ep := range route.TargetNodes {
		if ep == nil {
			continue
		}
		endpoints = upsertTargetEndpoint(endpoints, ep)
	}
	s.routes[sk] = endpoints
}

func (s *rawAuthzState) removeRoute(route *omnimeshv1.RouteInfo) {
	if route == nil {
		return
	}
	sk := serviceKey{namespace: route.Namespace, name: route.ServiceName}
	endpoints, ok := s.routes[sk]
	if !ok {
		return
	}
	if len(route.TargetNodes) == 0 {
		delete(s.routes, sk)
		return
	}
	remaining := removeTargetEndpoints(endpoints, route.TargetNodes)
	if len(remaining) == 0 {
		delete(s.routes, sk)
	} else {
		s.routes[sk] = remaining
	}
}

func sameTargetEndpoint(a, b *omnimeshv1.NodeEndpointInfo) bool {
	if a == nil || b == nil {
		return false
	}
	if a.RouteName != "" && b.RouteName != "" {
		return a.RouteName == b.RouteName && (a.NodeId == "" || b.NodeId == "" || a.NodeId == b.NodeId)
	}
	if a.NodeId != "" && b.NodeId != "" {
		return a.NodeId == b.NodeId
	}
	if a.NodeId == "" && b.NodeId == "" && a.RouteName == "" && b.RouteName == "" {
		return a.Addr != "" && a.Addr == b.Addr
	}
	return false
}

func upsertTargetEndpoint(endpoints []*omnimeshv1.NodeEndpointInfo, candidate *omnimeshv1.NodeEndpointInfo) []*omnimeshv1.NodeEndpointInfo {
	for i, existing := range endpoints {
		if sameTargetEndpoint(existing, candidate) {
			endpoints[i] = candidate
			return endpoints
		}
	}
	return append(endpoints, candidate)
}

func removeTargetEndpoints(endpoints []*omnimeshv1.NodeEndpointInfo, toRemove []*omnimeshv1.NodeEndpointInfo) []*omnimeshv1.NodeEndpointInfo {
	if len(endpoints) == 0 || len(toRemove) == 0 {
		return endpoints
	}
	out := make([]*omnimeshv1.NodeEndpointInfo, 0, len(endpoints))
	for _, existing := range endpoints {
		matched := false
		for _, rem := range toRemove {
			if sameTargetEndpoint(existing, rem) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, existing)
		}
	}
	return out
}

type compiledSelector struct {
	spiffeID    string
	trustDomain string
	namespace   string
	name        string
	labels      map[string]string
}

type compiledHeaderMatch struct {
	key   string
	value string
}

type compiledHTTPRule struct {
	methods      map[string]struct{}
	pathExact    map[string]struct{}
	pathPrefixes []string
	headers      []compiledHeaderMatch
}

type compiledGRPCRule struct {
	services   map[string]struct{}
	anyService bool
	methods    map[string]struct{}
	anyMethod  bool
}

type compiledRule struct {
	httpRule *compiledHTTPRule
	grpcRule *compiledGRPCRule
}

type compiledPolicy struct {
	name       string
	namespace  string
	fullName   string
	action     model.AuthzAction
	source     compiledSelector
	dest       compiledSelector
	ports      []int
	rules      []compiledRule
	hasL7      bool
	validFrom  *time.Time
	validUntil *time.Time
}

type policyBuckets struct {
	exactDest          map[serviceKey][]*compiledPolicy
	nsWildcardDest     map[string][]*compiledPolicy
	globalWildcardDest []*compiledPolicy
}

func newPolicyBuckets() policyBuckets {
	return policyBuckets{
		exactDest:      make(map[serviceKey][]*compiledPolicy),
		nsWildcardDest: make(map[string][]*compiledPolicy),
	}
}

func (b *policyBuckets) add(p *compiledPolicy) {
	ns := p.dest.namespace
	name := p.dest.name
	if ns == "" || ns == "*" {
		b.globalWildcardDest = append(b.globalWildcardDest, p)
		return
	}
	if name == "" || name == "*" {
		b.nsWildcardDest[ns] = append(b.nsWildcardDest[ns], p)
		return
	}
	sk := serviceKey{namespace: ns, name: name}
	b.exactDest[sk] = append(b.exactDest[sk], p)
}

func (b *policyBuckets) sortAll() {
	sortPolicies := func(list []*compiledPolicy) {
		slices.SortFunc(list, func(a, b *compiledPolicy) int {
			if c := strings.Compare(a.namespace, b.namespace); c != 0 {
				return c
			}
			return strings.Compare(a.name, b.name)
		})
	}
	for _, list := range b.exactDest {
		sortPolicies(list)
	}
	for _, list := range b.nsWildcardDest {
		sortPolicies(list)
	}
	sortPolicies(b.globalWildcardDest)
}

type compiledServiceMeta struct {
	namespace string
	name      string
	protocol  string
	port      int
}

type authzSnapshot struct {
	deny               policyBuckets
	allow              policyBuckets
	dryRun             policyBuckets
	namespaceIsolation map[string]model.NamespaceIsolation
	servicesByIP       map[string]compiledServiceMeta
	servicesByID       map[serviceKey]compiledServiceMeta
	sourceLabelsByNode map[serviceNodeKey][]map[string]string
	sourceLabelsBySvc  map[serviceKey][]map[string]string
	policyCount        int
}

// EngineOption configures an authorization Engine.
type EngineOption func(*Engine)

// WithTrustDomain overrides the local SPIFFE trust domain used to scope workload selectors.
func WithTrustDomain(td string) EngineOption {
	return func(e *Engine) {
		e.trustDomain = strings.TrimSpace(td)
	}
}

// WithAllowUnverifiedIdentity overrides whether unverified caller identities are permitted.
func WithAllowUnverifiedIdentity(allow bool) EngineOption {
	return func(e *Engine) {
		e.allowUnverified = allow
	}
}

// WithObserver registers an AuthzDecisionObserver invoked on every authorization decision.
func WithObserver(obs inbound.AuthzDecisionObserver) EngineOption {
	return func(e *Engine) {
		e.observer = obs
	}
}

// WithClock overrides the clock used for temporal policy evaluation (ValidFrom/ValidUntil).
func WithClock(nowFn func() time.Time) EngineOption {
	return func(e *Engine) {
		if nowFn != nil {
			e.nowFn = nowFn
		}
	}
}

// Engine evaluates L4 and L7 SPIFFE-based authorization policies using an immutable,
// lock-free atomic snapshot compiled from Control Plane updates and local config.
type Engine struct {
	mode             model.AuthzMode
	defaultIsolation model.NamespaceIsolation
	trustDomain      string
	allowUnverified  bool
	enforceL7        bool
	auditLogAllows   bool
	observer         inbound.AuthzDecisionObserver
	nowFn            func() time.Time

	updateMu sync.Mutex
	state    *rawAuthzState
	snapshot atomic.Pointer[authzSnapshot]

	allowedTotal               atomic.Uint64
	deniedTotal                atomic.Uint64
	dryRunWouldDenyTotal       atomic.Uint64
	permissiveAllowTotal       atomic.Uint64
	deniedNoPolicyTotal        atomic.Uint64
	deniedExplicitTotal        atomic.Uint64
	deniedL7MismatchTotal      atomic.Uint64
	deniedUnauthenticatedTotal atomic.Uint64
	deniedL7RequiredTotal      atomic.Uint64
}

// NewEngine constructs and compiles an authorization Engine from cfg and opts.
func NewEngine(cfg model.AuthorizationConfig, opts ...EngineOption) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	localPolicies := make([]model.AuthzPolicy, 0, len(cfg.LocalPolicies))
	for _, lp := range cfg.LocalPolicies {
		p, err := lp.ToPolicy()
		if err != nil {
			return nil, err
		}
		localPolicies = append(localPolicies, p)
	}

	e := &Engine{
		mode:             cfg.NormalizedMode(),
		defaultIsolation: cfg.NormalizedNamespaceDefaultIsolation(),
		trustDomain:      strings.TrimSpace(cfg.TrustDomain),
		enforceL7:        cfg.EnforceL7,
		auditLogAllows:   cfg.AuditLogAllows,
		nowFn:            time.Now,
		state:            newRawAuthzState(localPolicies),
	}
	if cfg.AllowUnverifiedIdentity != nil {
		e.allowUnverified = *cfg.AllowUnverifiedIdentity
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}

	e.publishLocked()
	return e, nil
}

// SetLocalPolicies replaces the local fallback policies and republishes the snapshot.
func (e *Engine) SetLocalPolicies(policies []model.AuthzPolicy) {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()

	if e.state == nil {
		e.state = newRawAuthzState(policies)
	} else {
		e.state.localPolicies = slices.Clone(policies)
	}
	e.publishLocked()
}

// ApplySnapshot replaces all Control Plane authorization state with snapshot and publishes it atomically.
func (e *Engine) ApplySnapshot(snapshot *omnimeshv1.ScopeSnapshot) {
	if snapshot == nil {
		return
	}

	e.updateMu.Lock()
	defer e.updateMu.Unlock()

	var localPolicies []model.AuthzPolicy
	if e.state != nil {
		localPolicies = e.state.localPolicies
	}
	next := newRawAuthzState(localPolicies)

	for _, ap := range snapshot.AuthzPolicies {
		if ap != nil {
			next.cpPolicies[authzPolicyMapKey(ap)] = ap
		}
	}
	for _, ns := range snapshot.Namespaces {
		if ns != nil && strings.TrimSpace(ns.Name) != "" {
			next.namespaces[strings.TrimSpace(ns.Name)] = ns
		}
	}
	for _, svc := range snapshot.Services {
		next.upsertService(svc)
	}
	for _, route := range snapshot.Routes {
		next.upsertRoute(route)
	}

	e.state = next
	e.publishLocked()
}

// ApplyUpdate incrementally applies a Control Plane ScopeUpdate and republishes the snapshot atomically.
func (e *Engine) ApplyUpdate(update *omnimeshv1.ScopeUpdate) {
	if update == nil {
		return
	}

	e.updateMu.Lock()
	defer e.updateMu.Unlock()

	next := e.state.clone()
	switch update.Type {
	case omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE:
		for _, ap := range update.AuthzPolicies {
			if ap != nil {
				delete(next.cpPolicies, authzPolicyMapKey(ap))
			}
		}
		for _, ns := range update.Namespaces {
			if ns != nil && strings.TrimSpace(ns.Name) != "" {
				delete(next.namespaces, strings.TrimSpace(ns.Name))
			}
		}
		for _, svc := range update.Services {
			next.removeService(svc)
		}
		for _, route := range update.Routes {
			next.removeRoute(route)
		}
	default: // ADD or MODIFY
		for _, ap := range update.AuthzPolicies {
			if ap != nil {
				next.cpPolicies[authzPolicyMapKey(ap)] = ap
			}
		}
		for _, ns := range update.Namespaces {
			if ns != nil && strings.TrimSpace(ns.Name) != "" {
				next.namespaces[strings.TrimSpace(ns.Name)] = ns
			}
		}
		for _, svc := range update.Services {
			next.upsertService(svc)
		}
		for _, route := range update.Routes {
			next.upsertRoute(route)
		}
	}

	e.state = next
	e.publishLocked()
}

func (e *Engine) publishLocked() {
	snap := compileSnapshot(e.state)
	e.snapshot.Store(snap)
}

func compileSnapshot(state *rawAuthzState) *authzSnapshot {
	snap := &authzSnapshot{
		deny:               newPolicyBuckets(),
		allow:              newPolicyBuckets(),
		dryRun:             newPolicyBuckets(),
		namespaceIsolation: make(map[string]model.NamespaceIsolation),
		servicesByIP:       make(map[string]compiledServiceMeta),
		servicesByID:       make(map[serviceKey]compiledServiceMeta),
		sourceLabelsByNode: make(map[serviceNodeKey][]map[string]string),
		sourceLabelsBySvc:  make(map[serviceKey][]map[string]string),
	}
	if state == nil {
		return snap
	}

	addCompiled := func(cp *compiledPolicy) {
		if cp == nil {
			return
		}
		snap.policyCount++
		switch cp.action {
		case model.AuthzActionDeny:
			snap.deny.add(cp)
		case model.AuthzActionDryRun:
			snap.dryRun.add(cp)
		default:
			snap.allow.add(cp)
		}
	}

	for _, lp := range state.localPolicies {
		addCompiled(compileDomainPolicy(lp))
	}
	for _, ap := range state.cpPolicies {
		if ap == nil {
			continue
		}
		action, ok := model.ParseAuthzAction(ap.Action)
		if !ok {
			log.Printf("[Authz] ignoring policy %s/%s with unknown action %q\n", ap.Namespace, ap.Name, ap.Action)
			continue
		}
		dp := model.AuthzPolicy{
			Name:        ap.Name,
			Namespace:   ap.Namespace,
			Action:      action,
			Source:      protoSelectorToModel(ap.Source),
			Destination: protoSelectorToModel(ap.Destination),
		}
		addCompiled(compileDomainPolicy(dp))
	}

	snap.deny.sortAll()
	snap.allow.sortAll()
	snap.dryRun.sortAll()

	for name, ns := range state.namespaces {
		if ns == nil {
			continue
		}
		iso, ok := model.ParseNamespaceIsolation(ns.Isolation)
		if !ok {
			iso = model.NamespaceIsolationStrict
		}
		snap.namespaceIsolation[name] = iso
	}

	for ip, svc := range state.servicesByIP {
		if svc == nil {
			continue
		}
		meta := compiledServiceMeta{
			namespace: svc.Namespace,
			name:      svc.Name,
			protocol:  strings.ToLower(strings.TrimSpace(svc.Protocol)),
			port:      int(svc.Port),
		}
		snap.servicesByIP[ip] = meta
	}
	for sk, svc := range state.servicesByID {
		if svc == nil {
			continue
		}
		snap.servicesByID[sk] = compiledServiceMeta{
			namespace: svc.Namespace,
			name:      svc.Name,
			protocol:  strings.ToLower(strings.TrimSpace(svc.Protocol)),
			port:      int(svc.Port),
		}
	}

	for sk, endpoints := range state.routes {
		for _, ep := range endpoints {
			if ep == nil || len(ep.Labels) == 0 {
				continue
			}
			snap.sourceLabelsBySvc[sk] = append(snap.sourceLabelsBySvc[sk], ep.Labels)
			if ep.NodeId != "" {
				nk := serviceNodeKey{namespace: sk.namespace, name: sk.name, nodeID: ep.NodeId}
				snap.sourceLabelsByNode[nk] = append(snap.sourceLabelsByNode[nk], ep.Labels)
			}
		}
	}

	return snap
}

func protoSelectorToModel(sel *omnimeshv1.SelectorInfo) model.AuthzSelector {
	if sel == nil {
		return model.AuthzSelector{}
	}
	return model.AuthzSelector{
		Namespace: sel.Namespace,
		Name:      sel.Name,
		Labels:    sel.Labels,
	}
}

func compileDomainPolicy(p model.AuthzPolicy) *compiledPolicy {
	fullName := p.Name
	if p.Namespace != "" && !strings.HasPrefix(p.Name, p.Namespace+"/") {
		fullName = p.Namespace + "/" + p.Name
	}

	destSel := compileSelector(p.Destination)
	// If a local policy targets destination by SpiffeID without explicit namespace/name,
	// extract workload namespace/name so destination bucketing can index it in O(1).
	if destSel.namespace == "" && destSel.name == "" && destSel.spiffeID != "" {
		if id, ok := model.ParseSPIFFEIdentity(destSel.spiffeID); ok && id.IsWorkload {
			destSel.namespace = id.Namespace
			destSel.name = id.ServiceName
		}
	}

	cp := &compiledPolicy{
		name:       p.Name,
		namespace:  p.Namespace,
		fullName:   fullName,
		action:     p.Action,
		source:     compileSelector(p.Source),
		dest:       destSel,
		ports:      slices.Clone(p.DestinationPorts),
		validFrom:  p.ValidFrom,
		validUntil: p.ValidUntil,
	}

	for _, r := range p.Rules {
		cr := compileRule(r)
		if cr.httpRule != nil || cr.grpcRule != nil {
			cp.rules = append(cp.rules, cr)
		}
	}
	cp.hasL7 = len(cp.rules) > 0
	return cp
}

func compileSelector(s model.AuthzSelector) compiledSelector {
	return compiledSelector{
		spiffeID:    strings.TrimSpace(s.SpiffeID),
		trustDomain: strings.ToLower(strings.TrimSpace(s.TrustDomain)),
		namespace:   strings.TrimSpace(s.Namespace),
		name:        strings.TrimSpace(s.Name),
		labels:      s.Labels,
	}
}

func compileRule(r model.AuthzRule) compiledRule {
	var out compiledRule
	if r.HTTP != nil {
		hr := &compiledHTTPRule{}
		if len(r.HTTP.Methods) > 0 {
			hr.methods = make(map[string]struct{}, len(r.HTTP.Methods))
			for _, m := range r.HTTP.Methods {
				if trimmed := strings.ToUpper(strings.TrimSpace(m)); trimmed != "" {
					hr.methods[trimmed] = struct{}{}
				}
			}
		}
		if len(r.HTTP.PathExact) > 0 {
			hr.pathExact = make(map[string]struct{}, len(r.HTTP.PathExact))
			for _, p := range r.HTTP.PathExact {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					hr.pathExact[trimmed] = struct{}{}
				}
			}
		}
		for _, p := range r.HTTP.PathPrefixes {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				hr.pathPrefixes = append(hr.pathPrefixes, trimmed)
			}
		}
		for k, v := range r.HTTP.Headers {
			hr.headers = append(hr.headers, compiledHeaderMatch{
				key:   http.CanonicalHeaderKey(k),
				value: v,
			})
		}
		out.httpRule = hr
	}
	if r.GRPC != nil {
		gr := &compiledGRPCRule{
			services: make(map[string]struct{}, len(r.GRPC.Services)),
			methods:  make(map[string]struct{}, len(r.GRPC.Methods)),
		}
		if len(r.GRPC.Services) == 0 {
			gr.anyService = true
		} else {
			for _, svc := range r.GRPC.Services {
				trimmed := strings.TrimSpace(svc)
				if trimmed == "*" {
					gr.anyService = true
				} else if trimmed != "" {
					gr.services[trimmed] = struct{}{}
				}
			}
		}
		if len(r.GRPC.Methods) == 0 {
			gr.anyMethod = true
		} else {
			for _, m := range r.GRPC.Methods {
				trimmed := strings.TrimSpace(m)
				if trimmed == "*" {
					gr.anyMethod = true
				} else if trimmed != "" {
					gr.methods[trimmed] = struct{}{}
				}
			}
		}
		out.grpcRule = gr
	}
	return out
}

// AuthorizeConnection evaluates L4 connection-level authorization before dialing the local target workload.
func (e *Engine) AuthorizeConnection(ctx context.Context, req model.AuthzRequest) model.AuthzDecision {
	req.Layer = model.AuthzLayerL4
	return e.evaluate(ctx, req)
}

// AuthorizeHTTP evaluates L7 HTTP/gRPC request-level authorization inside the L7 HTTP proxy pipeline.
func (e *Engine) AuthorizeHTTP(ctx context.Context, req model.AuthzRequest) model.AuthzDecision {
	req.Layer = model.AuthzLayerL7
	return e.evaluate(ctx, req)
}

// PolicyCount returns the number of policies in the active compiled snapshot.
func (e *Engine) PolicyCount() int {
	snap := e.snapshot.Load()
	if snap == nil {
		return 0
	}
	return snap.policyCount
}

// Stats returns a point-in-time snapshot of authorization counters.
func (e *Engine) Stats() model.AuthzStats {
	return model.AuthzStats{
		AllowedTotal:               e.allowedTotal.Load(),
		DeniedTotal:                e.deniedTotal.Load(),
		DryRunWouldDenyTotal:       e.dryRunWouldDenyTotal.Load(),
		PermissiveAllowTotal:       e.permissiveAllowTotal.Load(),
		DeniedNoPolicyTotal:        e.deniedNoPolicyTotal.Load(),
		DeniedExplicitTotal:        e.deniedExplicitTotal.Load(),
		DeniedL7MismatchTotal:      e.deniedL7MismatchTotal.Load(),
		DeniedUnauthenticatedTotal: e.deniedUnauthenticatedTotal.Load(),
		DeniedL7RequiredTotal:      e.deniedL7RequiredTotal.Load(),
		PoliciesCached:             e.PolicyCount(),
	}
}

func (e *Engine) evaluate(ctx context.Context, req model.AuthzRequest) model.AuthzDecision {
	snap := e.snapshot.Load()
	if snap == nil {
		snap = compileSnapshot(nil)
	}

	destNS, destName, destProto, destPort := resolveDestinationMeta(snap, req)
	effectiveProto := model.NormalizeProtocol(destProto)

	// 1. Disabled mode bypasses authorization evaluation completely.
	if e.mode == model.AuthzModeDisabled {
		decision := model.AuthzDecision{
			Allowed:                 true,
			Reason:                  model.AuthzReasonDisabled,
			Mode:                    e.mode,
			ResolvedDestNamespace:   destNS,
			ResolvedDestServiceName: destName,
			ResolvedProtocol:        destProto,
		}
		e.finalizeDecision(ctx, req, decision)
		return decision
	}

	// 2. Identity verification and SPIFFE URI parsing.
	if !req.CallerVerified && !e.allowUnverified {
		decision := e.modeOutcomeForDenied(model.AuthzReasonUnauthenticated, "", model.SPIFFEIdentity{}, destNS, destName, destProto)
		e.finalizeDecision(ctx, req, decision)
		return decision
	}

	callerID, ok := model.ParseSPIFFEIdentity(req.CallerIdentity)
	if !ok {
		decision := e.modeOutcomeForDenied(model.AuthzReasonInvalidIdentity, "", model.SPIFFEIdentity{}, destNS, destName, destProto)
		e.finalizeDecision(ctx, req, decision)
		return decision
	}

	now := e.nowFn()
	l7Available := e.enforceL7 && req.InboundL7Available && effectiveProto != model.ProtocolTCP

	// 3. Explicit DENY policies (evaluated first).
	hasMatchingL7Deny := false
	denyMatched := e.findDenyMatch(snap, callerID, req, destNS, destName, destPort, now, &hasMatchingL7Deny)
	if denyMatched != nil {
		var decision model.AuthzDecision
		if e.mode == model.AuthzModeDryRun {
			decision = model.AuthzDecision{
				Allowed:                 true,
				DryRun:                  true,
				WouldDeny:               true,
				Reason:                  model.AuthzReasonExplicitDeny,
				MatchedPolicy:           denyMatched.fullName,
				Mode:                    e.mode,
				SourceIdentity:          callerID,
				ResolvedDestNamespace:   destNS,
				ResolvedDestServiceName: destName,
				ResolvedProtocol:        destProto,
			}
		} else {
			decision = model.AuthzDecision{
				Allowed:                 false,
				Reason:                  model.AuthzReasonExplicitDeny,
				MatchedPolicy:           denyMatched.fullName,
				Mode:                    e.mode,
				SourceIdentity:          callerID,
				ResolvedDestNamespace:   destNS,
				ResolvedDestServiceName: destName,
				ResolvedProtocol:        destProto,
			}
		}
		e.finalizeDecision(ctx, req, decision)
		return decision
	}

	// 4. Explicit ALLOW policies.
	l7Mismatch := false
	l7RequiredDenied := false
	allowMatched, allowRequiresL7 := e.findAllowMatch(
		snap, callerID, req, destNS, destName, destPort, now,
		l7Available, hasMatchingL7Deny, &l7Mismatch, &l7RequiredDenied,
	)
	if allowMatched != nil {
		reason := model.AuthzReasonExplicitAllow
		if allowRequiresL7 && allowMatched.hasL7 && req.Layer == model.AuthzLayerL4 {
			reason = model.AuthzReasonExplicitAllowL7Deferred
		}
		decision := model.AuthzDecision{
			Allowed:                 true,
			RequiresL7:              allowRequiresL7,
			Reason:                  reason,
			MatchedPolicy:           allowMatched.fullName,
			Mode:                    e.mode,
			SourceIdentity:          callerID,
			ResolvedDestNamespace:   destNS,
			ResolvedDestServiceName: destName,
			ResolvedProtocol:        destProto,
		}
		e.finalizeDecision(ctx, req, decision)
		return decision
	}

	// 5. Namespace isolation ("open" permits same-namespace, same-trust-domain traffic).
	if e.isSameNamespaceOpen(snap, callerID, destNS) {
		if req.Layer == model.AuthzLayerL4 && hasMatchingL7Deny && !l7Available {
			l7RequiredDenied = true
		} else {
			decision := model.AuthzDecision{
				Allowed:                 true,
				RequiresL7:              hasMatchingL7Deny && req.Layer == model.AuthzLayerL4,
				Reason:                  model.AuthzReasonNamespaceOpen,
				Mode:                    e.mode,
				SourceIdentity:          callerID,
				ResolvedDestNamespace:   destNS,
				ResolvedDestServiceName: destName,
				ResolvedProtocol:        destProto,
			}
			e.finalizeDecision(ctx, req, decision)
			return decision
		}
	}

	// 6. Policy-level DRY_RUN rules.
	if dryMatched := e.findDryRunMatch(snap, callerID, req, destNS, destName, destPort, now); dryMatched != nil {
		decision := model.AuthzDecision{
			Allowed:                 true,
			DryRun:                  true,
			WouldDeny:               true,
			RequiresL7:              req.Layer == model.AuthzLayerL4 && (dryMatched.hasL7 || hasMatchingL7Deny),
			Reason:                  model.AuthzReasonDryRunPolicy,
			MatchedPolicy:           dryMatched.fullName,
			Mode:                    e.mode,
			SourceIdentity:          callerID,
			ResolvedDestNamespace:   destNS,
			ResolvedDestServiceName: destName,
			ResolvedProtocol:        destProto,
		}
		e.finalizeDecision(ctx, req, decision)
		return decision
	}

	// 7. Default-deny / mode fallback.
	reason := model.AuthzReasonNoPolicy
	if l7RequiredDenied {
		reason = model.AuthzReasonL7Required
	} else if l7Mismatch {
		reason = model.AuthzReasonL7Mismatch
	}
	decision := e.modeOutcomeForDenied(reason, "", callerID, destNS, destName, destProto)
	e.finalizeDecision(ctx, req, decision)
	return decision
}

func resolveDestinationMeta(snap *authzSnapshot, req model.AuthzRequest) (ns, name, proto string, port int) {
	ns = strings.TrimSpace(req.DestNamespace)
	name = strings.TrimSpace(req.DestServiceName)
	proto = strings.ToLower(strings.TrimSpace(req.DestProtocol))
	port = req.DestPort

	if (ns == "" || name == "") && req.DestMeshIP != "" {
		if svc, ok := snap.servicesByIP[req.DestMeshIP]; ok {
			if ns == "" {
				ns = svc.namespace
			}
			if name == "" {
				name = svc.name
			}
			if proto == "" || proto == "auto" {
				proto = svc.protocol
			}
			if port == 0 {
				port = svc.port
			}
		}
	}
	if ns != "" && name != "" {
		if svc, ok := snap.servicesByID[serviceKey{namespace: ns, name: name}]; ok {
			if proto == "" || proto == "auto" {
				proto = svc.protocol
			}
			if port == 0 {
				port = svc.port
			}
		}
	}
	return ns, name, proto, port
}

func (e *Engine) modeOutcomeForDenied(
	reason model.AuthzReason,
	matchedPolicy string,
	callerID model.SPIFFEIdentity,
	destNS, destName, destProto string,
) model.AuthzDecision {
	switch e.mode {
	case model.AuthzModePermissive:
		return model.AuthzDecision{
			Allowed:                 true,
			Reason:                  model.AuthzReasonPermissiveDefault,
			MatchedPolicy:           matchedPolicy,
			Mode:                    e.mode,
			SourceIdentity:          callerID,
			ResolvedDestNamespace:   destNS,
			ResolvedDestServiceName: destName,
			ResolvedProtocol:        destProto,
		}
	case model.AuthzModeDryRun:
		return model.AuthzDecision{
			Allowed:                 true,
			DryRun:                  true,
			WouldDeny:               true,
			Reason:                  reason,
			MatchedPolicy:           matchedPolicy,
			Mode:                    e.mode,
			SourceIdentity:          callerID,
			ResolvedDestNamespace:   destNS,
			ResolvedDestServiceName: destName,
			ResolvedProtocol:        destProto,
		}
	default:
		return model.AuthzDecision{
			Allowed:                 false,
			Reason:                  reason,
			MatchedPolicy:           matchedPolicy,
			Mode:                    e.mode,
			SourceIdentity:          callerID,
			ResolvedDestNamespace:   destNS,
			ResolvedDestServiceName: destName,
			ResolvedProtocol:        destProto,
		}
	}
}

func (e *Engine) findDenyMatch(
	snap *authzSnapshot,
	caller model.SPIFFEIdentity,
	req model.AuthzRequest,
	destNS, destName string,
	destPort int,
	now time.Time,
	hasMatchingL7Deny *bool,
) *compiledPolicy {
	var matched *compiledPolicy
	visitBucketList := func(list []*compiledPolicy) bool {
		for _, p := range list {
			if !p.isActive(now) || !p.matchesL4(snap, caller, req, destNS, destName, destPort, e.trustDomain) {
				continue
			}
			if req.Layer == model.AuthzLayerL4 {
				if !p.hasL7 {
					matched = p
					return true
				}
				*hasMatchingL7Deny = true
				continue
			}
			if !p.hasL7 || p.matchesL7(req.HTTP) {
				matched = p
				return true
			}
		}
		return false
	}

	visitPolicyBuckets(&snap.deny, destNS, destName, visitBucketList)
	return matched
}

func (e *Engine) findAllowMatch(
	snap *authzSnapshot,
	caller model.SPIFFEIdentity,
	req model.AuthzRequest,
	destNS, destName string,
	destPort int,
	now time.Time,
	l7Available bool,
	hasMatchingL7Deny bool,
	l7Mismatch *bool,
	l7RequiredDenied *bool,
) (*compiledPolicy, bool) {
	var matched *compiledPolicy
	requiresL7 := false

	visitBucketList := func(list []*compiledPolicy) bool {
		for _, p := range list {
			if !p.isActive(now) || !p.matchesL4(snap, caller, req, destNS, destName, destPort, e.trustDomain) {
				continue
			}
			if req.Layer == model.AuthzLayerL4 {
				if !p.hasL7 {
					if hasMatchingL7Deny && !l7Available {
						*l7RequiredDenied = true
						continue
					}
					matched = p
					requiresL7 = hasMatchingL7Deny
					return true
				}
				if !l7Available {
					*l7RequiredDenied = true
					continue
				}
				matched = p
				requiresL7 = true
				return true
			}
			if !p.hasL7 || p.matchesL7(req.HTTP) {
				matched = p
				return true
			}
			*l7Mismatch = true
		}
		return false
	}

	visitPolicyBuckets(&snap.allow, destNS, destName, visitBucketList)
	return matched, requiresL7
}

func (e *Engine) findDryRunMatch(
	snap *authzSnapshot,
	caller model.SPIFFEIdentity,
	req model.AuthzRequest,
	destNS, destName string,
	destPort int,
	now time.Time,
) *compiledPolicy {
	var matched *compiledPolicy
	visitBucketList := func(list []*compiledPolicy) bool {
		for _, p := range list {
			if !p.isActive(now) || !p.matchesL4(snap, caller, req, destNS, destName, destPort, e.trustDomain) {
				continue
			}
			if req.Layer == model.AuthzLayerL7 && p.hasL7 && !p.matchesL7(req.HTTP) {
				continue
			}
			matched = p
			return true
		}
		return false
	}

	visitPolicyBuckets(&snap.dryRun, destNS, destName, visitBucketList)
	return matched
}

func visitPolicyBuckets(b *policyBuckets, destNS, destName string, fn func([]*compiledPolicy) bool) {
	if destNS != "" && destName != "" {
		if list := b.exactDest[serviceKey{namespace: destNS, name: destName}]; len(list) > 0 {
			if fn(list) {
				return
			}
		}
	}
	if destNS != "" {
		if list := b.nsWildcardDest[destNS]; len(list) > 0 {
			if fn(list) {
				return
			}
		}
	}
	if len(b.globalWildcardDest) > 0 {
		fn(b.globalWildcardDest)
	}
}

func (e *Engine) isSameNamespaceOpen(snap *authzSnapshot, caller model.SPIFFEIdentity, destNS string) bool {
	if destNS == "" || !caller.IsWorkload || caller.Namespace != destNS {
		return false
	}
	if e.trustDomain != "" && caller.TrustDomain != e.trustDomain {
		return false
	}
	iso, ok := snap.namespaceIsolation[destNS]
	if !ok {
		iso = e.defaultIsolation
	}
	return iso == model.NamespaceIsolationOpen
}

func (p *compiledPolicy) isActive(now time.Time) bool {
	if p.validFrom != nil && now.Before(*p.validFrom) {
		return false
	}
	if p.validUntil != nil && !now.Before(*p.validUntil) {
		return false
	}
	return true
}

func (p *compiledPolicy) matchesL4(
	snap *authzSnapshot,
	caller model.SPIFFEIdentity,
	req model.AuthzRequest,
	destNS, destName string,
	destPort int,
	engineTrustDomain string,
) bool {
	if !matchesSourceSelector(snap, p.source, caller, req, engineTrustDomain) {
		return false
	}
	if !matchesDestSelector(p.dest, destNS, destName, req.DestLabels) {
		return false
	}
	if len(p.ports) > 0 {
		if destPort <= 0 || !slices.Contains(p.ports, destPort) {
			return false
		}
	}
	return true
}

func matchesSourceSelector(
	snap *authzSnapshot,
	sel compiledSelector,
	caller model.SPIFFEIdentity,
	req model.AuthzRequest,
	engineTrustDomain string,
) bool {
	if sel.spiffeID != "" {
		if caller.Raw != sel.spiffeID {
			return false
		}
	} else if sel.trustDomain != "" {
		if caller.TrustDomain != sel.trustDomain {
			return false
		}
	} else if engineTrustDomain != "" && caller.TrustDomain != engineTrustDomain {
		return false
	}

	if sel.namespace != "" && sel.namespace != "*" {
		if !caller.IsWorkload || caller.Namespace != sel.namespace {
			return false
		}
	}
	if sel.name != "" && sel.name != "*" {
		if !caller.IsWorkload || caller.ServiceName != sel.name {
			return false
		}
	}

	if len(sel.labels) > 0 {
		if len(req.SourceLabels) > 0 {
			if !labelsMatch(req.SourceLabels, sel.labels) {
				return false
			}
		} else {
			if !caller.IsWorkload {
				return false
			}
			var candidates []map[string]string
			if req.SourceNodeID != "" {
				candidates = snap.sourceLabelsByNode[serviceNodeKey{
					namespace: caller.Namespace,
					name:      caller.ServiceName,
					nodeID:    req.SourceNodeID,
				}]
			}
			if len(candidates) == 0 {
				candidates = snap.sourceLabelsBySvc[serviceKey{
					namespace: caller.Namespace,
					name:      caller.ServiceName,
				}]
			}
			if !anyLabelSetMatches(candidates, sel.labels) {
				return false
			}
		}
	}

	return true
}

func matchesDestSelector(sel compiledSelector, destNS, destName string, destLabels map[string]string) bool {
	if sel.namespace != "" && sel.namespace != "*" && sel.namespace != destNS {
		return false
	}
	if sel.name != "" && sel.name != "*" && sel.name != destName {
		return false
	}
	if len(sel.labels) > 0 && !labelsMatch(destLabels, sel.labels) {
		return false
	}
	return true
}

func anyLabelSetMatches(candidates []map[string]string, required map[string]string) bool {
	for _, c := range candidates {
		if labelsMatch(c, required) {
			return true
		}
	}
	return false
}

func labelsMatch(actual, required map[string]string) bool {
	if len(required) == 0 {
		return true
	}
	if len(actual) < len(required) {
		return false
	}
	for k, v := range required {
		if av, ok := actual[k]; !ok || av != v {
			return false
		}
	}
	return true
}

func (p *compiledPolicy) matchesL7(attrs *model.HTTPAuthzAttributes) bool {
	if attrs == nil {
		return false
	}
	for i := range p.rules {
		if p.rules[i].matches(attrs) {
			return true
		}
	}
	return false
}

func (r *compiledRule) matches(attrs *model.HTTPAuthzAttributes) bool {
	if r.httpRule != nil && !r.httpRule.matches(attrs) {
		return false
	}
	if r.grpcRule != nil && !r.grpcRule.matches(attrs) {
		return false
	}
	return r.httpRule != nil || r.grpcRule != nil
}

func (hr *compiledHTTPRule) matches(attrs *model.HTTPAuthzAttributes) bool {
	if len(hr.methods) > 0 {
		if _, ok := hr.methods[strings.ToUpper(attrs.Method)]; !ok {
			return false
		}
	}

	if len(hr.pathExact) > 0 || len(hr.pathPrefixes) > 0 {
		normPath := normalizeAuthzPath(attrs.Path)
		matchedPath := false
		if _, ok := hr.pathExact[normPath]; ok {
			matchedPath = true
		}
		if !matchedPath {
			for _, prefix := range hr.pathPrefixes {
				if strings.HasPrefix(normPath, prefix) {
					matchedPath = true
					break
				}
			}
		}
		if !matchedPath {
			return false
		}
	}

	for _, hm := range hr.headers {
		if attrs.Headers == nil || attrs.Headers.Get(hm.key) != hm.value {
			return false
		}
	}
	return true
}

func (gr *compiledGRPCRule) matches(attrs *model.HTTPAuthzAttributes) bool {
	if !attrs.IsGRPC {
		return false
	}
	if !gr.anyService {
		if _, ok := gr.services[attrs.GRPCService]; !ok {
			return false
		}
	}
	if !gr.anyMethod {
		if _, ok := gr.methods[attrs.GRPCMethod]; !ok {
			return false
		}
	}
	return true
}

// normalizeAuthzPath strips query/fragment components and resolves "." / ".." segments
// so path-traversal tricks such as /api/v1/public/../admin cannot bypass prefix rules.
func normalizeAuthzPath(raw string) string {
	if raw == "" {
		return "/"
	}
	if idx := strings.IndexAny(raw, "?#"); idx != -1 {
		raw = raw[:idx]
	}
	if raw == "" {
		return "/"
	}
	hadTrailingSlash := strings.HasSuffix(raw, "/")
	cleaned := path.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	if hadTrailingSlash && cleaned != "/" && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

func (e *Engine) finalizeDecision(ctx context.Context, req model.AuthzRequest, decision model.AuthzDecision) {
	if decision.Allowed {
		e.allowedTotal.Add(1)
		if decision.DryRun && decision.WouldDeny {
			e.dryRunWouldDenyTotal.Add(1)
		}
		if decision.Reason == model.AuthzReasonPermissiveDefault {
			e.permissiveAllowTotal.Add(1)
		}
	} else {
		e.deniedTotal.Add(1)
		switch decision.Reason {
		case model.AuthzReasonExplicitDeny:
			e.deniedExplicitTotal.Add(1)
		case model.AuthzReasonL7Mismatch:
			e.deniedL7MismatchTotal.Add(1)
		case model.AuthzReasonUnauthenticated, model.AuthzReasonInvalidIdentity:
			e.deniedUnauthenticatedTotal.Add(1)
		case model.AuthzReasonL7Required:
			e.deniedL7RequiredTotal.Add(1)
		default:
			e.deniedNoPolicyTotal.Add(1)
		}
	}

	e.emitAuditLog(req, decision)
	if e.observer != nil {
		e.observer.OnAuthzDecision(ctx, req, decision)
	}
}

func (e *Engine) emitAuditLog(req model.AuthzRequest, decision model.AuthzDecision) {
	destSvc := decision.ResolvedDestServiceName
	if decision.ResolvedDestNamespace != "" && decision.ResolvedDestServiceName != "" {
		destSvc = decision.ResolvedDestNamespace + "/" + decision.ResolvedDestServiceName
	}

	traceID := ""
	requestID := ""
	method := ""
	reqPath := ""
	if req.HTTP != nil {
		traceID = req.HTTP.TraceID
		requestID = req.HTTP.RequestID
		method = req.HTTP.Method
		reqPath = req.HTTP.Path
	}

	if !decision.Allowed {
		log.Printf("[Authz] event=authz.denied layer=%s mode=%s reason=%s policy=%q caller=%q verified=%v source_node=%q dest_service=%q dest_port=%d method=%s path=%q trace_id=%s request_id=%s\n",
			req.Layer, decision.Mode, decision.Reason, decision.MatchedPolicy,
			req.CallerIdentity, req.CallerVerified, req.SourceNodeID, destSvc, req.DestPort,
			method, reqPath, traceID, requestID)
		return
	}

	if decision.DryRun && decision.WouldDeny {
		log.Printf("[Authz] event=authz.dry_run.would_deny layer=%s mode=%s reason=%s policy=%q caller=%q verified=%v source_node=%q dest_service=%q dest_port=%d method=%s path=%q trace_id=%s request_id=%s\n",
			req.Layer, decision.Mode, decision.Reason, decision.MatchedPolicy,
			req.CallerIdentity, req.CallerVerified, req.SourceNodeID, destSvc, req.DestPort,
			method, reqPath, traceID, requestID)
		return
	}

	if decision.Reason == model.AuthzReasonPermissiveDefault {
		log.Printf("[Authz] event=authz.permissive.allow layer=%s mode=%s reason=%s caller=%q verified=%v dest_service=%q dest_port=%d\n",
			req.Layer, decision.Mode, decision.Reason, req.CallerIdentity, req.CallerVerified, destSvc, req.DestPort)
		return
	}

	if e.auditLogAllows {
		log.Printf("[Authz] event=authz.allowed layer=%s mode=%s reason=%s policy=%q caller=%q dest_service=%q dest_port=%d method=%s path=%q trace_id=%s request_id=%s\n",
			req.Layer, decision.Mode, decision.Reason, decision.MatchedPolicy,
			req.CallerIdentity, destSvc, req.DestPort, method, reqPath, traceID, requestID)
	}
}
