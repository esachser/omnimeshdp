package proxy

import (
	"log"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

/*
Control-path vs. data-path routing design (spec/routing.md):
- Control path (ApplySnapshot, ApplyUpdate, SetNodeInfo, SetRoutingConfig) is serialized
  by updateMu, mutates routeConfig, pre-compiles an immutable routeSnapshot (filtering
  unhealthy/draining endpoints, resolving TargetHost, matching TrafficPolicy routes, and
  pre-computing cumulative weights), and publishes it via atomic.Pointer[routeSnapshot].
- Data path (ResolveRouteIPv4, ResolveRouteWithExclusions, ResolveRoute) performs a single
  lock-free atomic.Pointer.Load() with O(1) service lookup, uniform random default selection
  via math/rand/v2, and zero-allocation exclusion filtering during retries.
*/

type serviceKey struct {
	namespace string
	name      string
}

type policyKey struct {
	namespace string
	name      string
}

type healthKey struct {
	namespace   string
	serviceName string
	nodeID      string
	routeName   string
}

type rrTrackerKey struct {
	namespace   string
	serviceName string
	groupIdx    int
}

// routeConfig stores raw Control Plane state used by the control path to compile snapshots.
type routeConfig struct {
	services        map[string]*omnimeshv1.ServiceInfo            // key: destination IP (MeshAddr)
	routes          map[serviceKey][]*omnimeshv1.NodeEndpointInfo // key: {namespace, serviceName} -> TargetNodes
	trafficPolicies map[policyKey]*omnimeshv1.TrafficPolicyInfo   // key: {namespace, name}
	endpointHealth  map[healthKey]omnimeshv1.EndpointHealthStatus // key: {namespace, serviceName, nodeID, routeName}
	nodes           map[string]*omnimeshv1.NodeEndpointInfo       // key: nodeID -> endpoint metadata
	targetAddresses map[string]string                             // key: target name -> targetAddress
	namespaces      map[string]*omnimeshv1.NamespaceInfo          // key: namespace name
}

func newRouteConfig() *routeConfig {
	return &routeConfig{
		services:        make(map[string]*omnimeshv1.ServiceInfo),
		routes:          make(map[serviceKey][]*omnimeshv1.NodeEndpointInfo),
		trafficPolicies: make(map[policyKey]*omnimeshv1.TrafficPolicyInfo),
		endpointHealth:  make(map[healthKey]omnimeshv1.EndpointHealthStatus),
		nodes:           make(map[string]*omnimeshv1.NodeEndpointInfo),
		targetAddresses: make(map[string]string),
		namespaces:      make(map[string]*omnimeshv1.NamespaceInfo),
	}
}

func (c *routeConfig) clone() *routeConfig {
	cp := newRouteConfig()
	if c == nil {
		return cp
	}
	for k, v := range c.services {
		cp.services[k] = v
	}
	for sk, endpoints := range c.routes {
		cp.routes[sk] = slices.Clone(endpoints)
	}
	for k, v := range c.trafficPolicies {
		cp.trafficPolicies[k] = v
	}
	for k, v := range c.endpointHealth {
		cp.endpointHealth[k] = v
	}
	for k, v := range c.nodes {
		cp.nodes[k] = v
	}
	for k, v := range c.targetAddresses {
		cp.targetAddresses[k] = v
	}
	for k, v := range c.namespaces {
		cp.namespaces[k] = v
	}
	return cp
}

func (c *routeConfig) addService(svc *omnimeshv1.ServiceInfo) {
	if svc == nil {
		return
	}
	if svc.Namespace != "" || svc.Name != "" {
		for ip, existing := range c.services {
			if existing.Namespace == svc.Namespace && existing.Name == svc.Name && ip != svc.MeshAddr {
				delete(c.services, ip)
			}
		}
	}
	if svc.MeshAddr != "" {
		c.services[svc.MeshAddr] = svc
	}
}

func (c *routeConfig) removeService(svc *omnimeshv1.ServiceInfo) {
	if svc == nil {
		return
	}
	if svc.MeshAddr != "" {
		delete(c.services, svc.MeshAddr)
	}
	if svc.Namespace != "" || svc.Name != "" {
		for ip, existing := range c.services {
			if existing.Namespace == svc.Namespace && existing.Name == svc.Name {
				delete(c.services, ip)
			}
		}
	}
}

func (c *routeConfig) addRoute(route *omnimeshv1.RouteInfo) {
	if route == nil {
		return
	}
	sk := serviceKey{namespace: route.Namespace, name: route.ServiceName}
	endpoints := c.routes[sk]
	for _, targetNode := range route.TargetNodes {
		if targetNode == nil {
			continue
		}
		endpoints = upsertTargetNode(endpoints, targetNode)
		if targetNode.NodeId != "" {
			if existing, exists := c.nodes[targetNode.NodeId]; !exists || targetNode.TargetAddress != "" || existing.TargetAddress == "" {
				c.nodes[targetNode.NodeId] = targetNode
			}
		}
		if targetNode.Target != "" && targetNode.TargetAddress != "" {
			c.targetAddresses[targetNode.Target] = targetNode.TargetAddress
		}
	}
	c.routes[sk] = endpoints
}

func (c *routeConfig) removeRoute(route *omnimeshv1.RouteInfo) {
	if route == nil {
		return
	}
	sk := serviceKey{namespace: route.Namespace, name: route.ServiceName}
	endpoints, ok := c.routes[sk]
	if !ok {
		return
	}
	if len(route.TargetNodes) == 0 {
		delete(c.routes, sk)
		return
	}
	remaining := removeTargetNodes(endpoints, route.TargetNodes)
	if len(remaining) == 0 {
		delete(c.routes, sk)
	} else {
		c.routes[sk] = remaining
	}
}

func policyMapKey(p *omnimeshv1.TrafficPolicyInfo) policyKey {
	if p == nil {
		return policyKey{}
	}
	ns := p.Namespace
	if ns == "" {
		ns = p.TargetServiceNamespace
	}
	name := p.Name
	if name == "" {
		name = p.TargetServiceNamespace + "/" + p.TargetServiceName
	}
	return policyKey{namespace: ns, name: name}
}

func (c *routeConfig) addTrafficPolicy(p *omnimeshv1.TrafficPolicyInfo) {
	if p == nil {
		return
	}
	c.trafficPolicies[policyMapKey(p)] = p
}

func (c *routeConfig) removeTrafficPolicy(p *omnimeshv1.TrafficPolicyInfo) {
	if p == nil {
		return
	}
	if p.Name != "" {
		delete(c.trafficPolicies, policyMapKey(p))
		return
	}
	targetNS := p.TargetServiceNamespace
	if targetNS == "" {
		targetNS = p.Namespace
	}
	for k, existing := range c.trafficPolicies {
		exTargetNS := existing.TargetServiceNamespace
		if exTargetNS == "" {
			exTargetNS = existing.Namespace
		}
		if exTargetNS == targetNS && existing.TargetServiceName == p.TargetServiceName {
			delete(c.trafficPolicies, k)
		}
	}
}

func (c *routeConfig) addEndpointHealth(h *omnimeshv1.EndpointHealthInfo) {
	if h == nil {
		return
	}
	hk := healthKey{
		namespace:   h.Namespace,
		serviceName: h.ServiceName,
		nodeID:      h.NodeId,
		routeName:   h.RouteName,
	}
	c.endpointHealth[hk] = h.Status
}

func (c *routeConfig) removeEndpointHealth(h *omnimeshv1.EndpointHealthInfo) {
	if h == nil {
		return
	}
	if h.NodeId == "" && h.RouteName == "" {
		for k := range c.endpointHealth {
			if k.namespace == h.Namespace && k.serviceName == h.ServiceName {
				delete(c.endpointHealth, k)
			}
		}
		return
	}
	if h.RouteName == "" {
		for k := range c.endpointHealth {
			if k.namespace == h.Namespace && k.serviceName == h.ServiceName && k.nodeID == h.NodeId {
				delete(c.endpointHealth, k)
			}
		}
		return
	}
	delete(c.endpointHealth, healthKey{
		namespace:   h.Namespace,
		serviceName: h.ServiceName,
		nodeID:      h.NodeId,
		routeName:   h.RouteName,
	})
}

func (c *routeConfig) resolveEndpointHealth(namespace, serviceName string, ep *omnimeshv1.NodeEndpointInfo) omnimeshv1.EndpointHealthStatus {
	if ep == nil || len(c.endpointHealth) == 0 {
		return omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNSPECIFIED
	}
	if st, ok := c.endpointHealth[healthKey{namespace: namespace, serviceName: serviceName, nodeID: ep.NodeId, routeName: ep.RouteName}]; ok {
		return st
	}
	if ep.RouteName != "" {
		if st, ok := c.endpointHealth[healthKey{namespace: namespace, serviceName: serviceName, routeName: ep.RouteName}]; ok {
			return st
		}
	}
	if ep.NodeId != "" {
		if st, ok := c.endpointHealth[healthKey{namespace: namespace, serviceName: serviceName, nodeID: ep.NodeId}]; ok {
			return st
		}
	}
	if ep.Addr != "" {
		if ep.NodeId != "" {
			if st, ok := c.endpointHealth[healthKey{namespace: namespace, serviceName: serviceName, nodeID: ep.NodeId, routeName: ep.Addr}]; ok {
				return st
			}
		}
		if st, ok := c.endpointHealth[healthKey{namespace: namespace, serviceName: serviceName, routeName: ep.Addr}]; ok {
			return st
		}
	}
	if ep.RouteName == "" && serviceName != "" {
		if st, ok := c.endpointHealth[healthKey{namespace: namespace, serviceName: serviceName, nodeID: ep.NodeId, routeName: serviceName}]; ok {
			return st
		}
	}
	return omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNSPECIFIED
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

func upsertTargetNode(endpoints []*omnimeshv1.NodeEndpointInfo, candidate *omnimeshv1.NodeEndpointInfo) []*omnimeshv1.NodeEndpointInfo {
	for i, existing := range endpoints {
		if sameTargetEndpoint(existing, candidate) {
			endpoints[i] = candidate
			return endpoints
		}
	}
	return append(endpoints, candidate)
}

func removeTargetNodes(endpoints []*omnimeshv1.NodeEndpointInfo, toRemove []*omnimeshv1.NodeEndpointInfo) []*omnimeshv1.NodeEndpointInfo {
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

func (c *routeConfig) resolveLocalTargetAddress(nodeID, nodeTarget, explicitTargetAddr string) string {
	if explicitTargetAddr != "" {
		return explicitTargetAddr
	}
	if nodeID != "" {
		if localNode, ok := c.nodes[nodeID]; ok && localNode != nil {
			if localNode.TargetAddress != "" {
				return localNode.TargetAddress
			}
			if localNode.Target != "" {
				if addr := c.targetAddresses[localNode.Target]; addr != "" {
					return addr
				}
			}
		}
	}
	if nodeTarget != "" {
		if addr := c.targetAddresses[nodeTarget]; addr != "" {
			return addr
		}
	}
	return ""
}

func namespaceKey(ns *omnimeshv1.NamespaceInfo) string {
	if ns == nil {
		return ""
	}
	if name := strings.TrimSpace(ns.Name); name != "" {
		return name
	}
	if cidr := strings.TrimSpace(ns.Cidr); cidr != "" {
		return cidr
	}
	return strings.Join(ns.Subnets, ",")
}

func extractNamespaceSubnets(ns *omnimeshv1.NamespaceInfo) []string {
	if ns == nil {
		return nil
	}
	var out []string
	for _, s := range ns.Subnets {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		if cidr := strings.TrimSpace(ns.Cidr); cidr != "" {
			out = append(out, cidr)
		}
	}
	return out
}

type compiledEndpoint struct {
	key         model.EndpointKey
	nodeID      string
	routeName   string
	targetHost  string
	activeConns *atomic.Int64
}

type compiledRouteGroup struct {
	weight    int32
	endpoints []*compiledEndpoint
	rrCounter *atomic.Uint64
}

type compiledServicePlan struct {
	namespace        string
	serviceName      string
	meshAddr         string
	protocol         string
	defaultPort      int32
	defaultRealDest  string
	algorithm        omnimeshv1.LoadBalancerAlgorithm
	retry            model.RetryConfig
	rawEndpointCount int
	hasTrafficRules  bool
	allEndpoints     []*compiledEndpoint
	groups           []*compiledRouteGroup
	cumWeights       []int64
	totalWeight      int64
	rrCounter        *atomic.Uint64
}

type routeSnapshot struct {
	plansByIP      map[string]*compiledServicePlan
	plansByIPv4    map[uint32]*compiledServicePlan
	endpointsByKey map[model.EndpointKey]*compiledEndpoint
	namespaces     []*omnimeshv1.NamespaceInfo
	subnets        []string
	defaultRetry   model.RetryConfig
}

func emptySnapshot(defaultRetry model.RetryConfig) *routeSnapshot {
	return &routeSnapshot{
		plansByIP:      make(map[string]*compiledServicePlan),
		plansByIPv4:    make(map[uint32]*compiledServicePlan),
		endpointsByKey: make(map[model.EndpointKey]*compiledEndpoint),
		defaultRetry:   defaultRetry,
	}
}

// Router maintains mesh routing tables derived from ScopeSnapshot and ScopeUpdate messages.
// Reads on the data path are lock-free via atomic snapshot swaps.
type Router struct {
	updateMu      sync.Mutex
	config        *routeConfig
	snapshot      atomic.Pointer[routeSnapshot]
	nodeID        string
	target        string
	targetAddress string
	defaultRetry  model.RetryConfig

	trackerMu    sync.RWMutex
	connTrackers map[model.EndpointKey]*atomic.Int64
	rrTrackers   map[rrTrackerKey]*atomic.Uint64
}

// NewRouter creates a new thread-safe mesh router.
func NewRouter() *Router {
	return NewRouterWithNode("", "")
}

// NewRouterWithNode creates a new thread-safe mesh router configured with the local node identity and target.
func NewRouterWithNode(nodeID, target string) *Router {
	defaultRetry, _ := model.DefaultRoutingConfig().ToRetryConfig()
	r := &Router{
		config:       newRouteConfig(),
		nodeID:       nodeID,
		target:       target,
		defaultRetry: defaultRetry,
		connTrackers: make(map[model.EndpointKey]*atomic.Int64),
		rrTrackers:   make(map[rrTrackerKey]*atomic.Uint64),
	}
	r.snapshot.Store(emptySnapshot(defaultRetry))
	return r
}

// SetRoutingConfig updates the default data-plane retry/routing parameters used when
// Control Plane TrafficPolicies do not specify overrides.
func (r *Router) SetRoutingConfig(cfg model.RoutingConfig) error {
	parsed, err := cfg.ToRetryConfig()
	if err != nil {
		return err
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()
	r.defaultRetry = parsed
	r.publishLocked()
	return nil
}

// DefaultRetryConfig returns the active default RetryConfig.
func (r *Router) DefaultRetryConfig() model.RetryConfig {
	r.updateMu.Lock()
	defer r.updateMu.Unlock()
	return r.defaultRetry
}

// SetNodeInfo sets the local node ID and network target of the node processing connections.
func (r *Router) SetNodeInfo(nodeID, target string) {
	r.updateMu.Lock()
	defer r.updateMu.Unlock()
	r.nodeID = nodeID
	r.target = target
	r.publishLocked()
}

// SetNodeID sets the local node ID of the node processing connections.
func (r *Router) SetNodeID(nodeID string) {
	r.updateMu.Lock()
	defer r.updateMu.Unlock()
	r.nodeID = nodeID
	r.publishLocked()
}

// SetTargetAddress explicitly sets the TargetAddress of the node processing connections.
func (r *Router) SetTargetAddress(targetAddress string) {
	r.updateMu.Lock()
	defer r.updateMu.Unlock()
	r.targetAddress = targetAddress
	r.publishLocked()
}

// ApplySnapshot replaces the routing table with the provided ScopeSnapshot.
func (r *Router) ApplySnapshot(snapshot *omnimeshv1.ScopeSnapshot) {
	if snapshot == nil {
		return
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()

	workingCopy := newRouteConfig()
	if r.config != nil {
		for k, v := range r.config.nodes {
			workingCopy.nodes[k] = v
		}
		for k, v := range r.config.targetAddresses {
			workingCopy.targetAddresses[k] = v
		}
	}

	for _, svc := range snapshot.Services {
		workingCopy.addService(svc)
	}
	for _, route := range snapshot.Routes {
		workingCopy.addRoute(route)
	}
	for _, tp := range snapshot.TrafficPolicies {
		workingCopy.addTrafficPolicy(tp)
	}
	for _, eh := range snapshot.EndpointHealth {
		workingCopy.addEndpointHealth(eh)
	}
	for _, ns := range snapshot.Namespaces {
		if key := namespaceKey(ns); key != "" {
			workingCopy.namespaces[key] = ns
		}
	}

	r.config = workingCopy
	r.publishLocked()

	log.Printf("Router: ScopeSnapshot applied with %d services, %d routes, %d traffic policies, %d health entries, and %d namespaces\n",
		len(snapshot.Services), len(snapshot.Routes), len(snapshot.TrafficPolicies), len(snapshot.EndpointHealth), len(snapshot.Namespaces))
}

// ApplyUpdate incrementally updates the routing table with a ScopeUpdate.
func (r *Router) ApplyUpdate(update *omnimeshv1.ScopeUpdate) {
	if update == nil {
		return
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()

	workingCopy := r.config.clone()

	switch update.Type {
	case omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE:
		for _, svc := range update.Services {
			workingCopy.removeService(svc)
		}
		for _, route := range update.Routes {
			workingCopy.removeRoute(route)
		}
		for _, tp := range update.TrafficPolicies {
			workingCopy.removeTrafficPolicy(tp)
		}
		for _, eh := range update.EndpointHealth {
			workingCopy.removeEndpointHealth(eh)
		}
		for _, ns := range update.Namespaces {
			if key := namespaceKey(ns); key != "" {
				delete(workingCopy.namespaces, key)
			}
		}
	default: // ADD or MODIFY
		for _, svc := range update.Services {
			workingCopy.addService(svc)
		}
		for _, route := range update.Routes {
			workingCopy.addRoute(route)
		}
		for _, tp := range update.TrafficPolicies {
			workingCopy.addTrafficPolicy(tp)
		}
		for _, eh := range update.EndpointHealth {
			workingCopy.addEndpointHealth(eh)
		}
		for _, ns := range update.Namespaces {
			if key := namespaceKey(ns); key != "" {
				workingCopy.namespaces[key] = ns
			}
		}
	}

	r.config = workingCopy
	r.publishLocked()

	log.Printf("Router: ScopeUpdate (%v) applied with %d services, %d routes, %d traffic policies, %d health entries, and %d namespaces\n",
		update.Type, len(update.Services), len(update.Routes), len(update.TrafficPolicies), len(update.EndpointHealth), len(update.Namespaces))
}

// publishLocked compiles r.config into an immutable routeSnapshot and swaps it atomically.
// Caller must hold r.updateMu.
func (r *Router) publishLocked() {
	snap := r.compileSnapshotLocked(r.config)
	r.snapshot.Store(snap)
}

func (r *Router) compileSnapshotLocked(cfg *routeConfig) *routeSnapshot {
	if cfg == nil {
		return emptySnapshot(r.defaultRetry)
	}

	localTargetAddr := cfg.resolveLocalTargetAddress(r.nodeID, r.target, r.targetAddress)

	// Compile namespaces and subnets once.
	var namespaces []*omnimeshv1.NamespaceInfo
	var subnets []string
	if len(cfg.namespaces) > 0 {
		namespaces = make([]*omnimeshv1.NamespaceInfo, 0, len(cfg.namespaces))
		for _, ns := range cfg.namespaces {
			namespaces = append(namespaces, ns)
			subnets = append(subnets, extractNamespaceSubnets(ns)...)
		}
		slices.SortFunc(namespaces, func(a, b *omnimeshv1.NamespaceInfo) int {
			return strings.Compare(a.GetName(), b.GetName())
		})
		if len(subnets) > 0 {
			slices.Sort(subnets)
			subnets = slices.Compact(subnets)
		}
	}

	// Index TrafficPolicies by target service key with deterministic precedence.
	policiesBySvc := indexTrafficPolicies(cfg.trafficPolicies)

	plansByIP := make(map[string]*compiledServicePlan, len(cfg.services))
	plansByIPv4 := make(map[uint32]*compiledServicePlan, len(cfg.services))
	endpointsByKey := make(map[model.EndpointKey]*compiledEndpoint)

	seenEndpoints := make(map[model.EndpointKey]struct{})
	seenRRKeys := make(map[rrTrackerKey]struct{})

	r.trackerMu.Lock()
	defer r.trackerMu.Unlock()

	getConnTracker := func(key model.EndpointKey) *atomic.Int64 {
		seenEndpoints[key] = struct{}{}
		if c, ok := r.connTrackers[key]; ok {
			return c
		}
		c := &atomic.Int64{}
		r.connTrackers[key] = c
		return c
	}

	getRRTracker := func(key rrTrackerKey) *atomic.Uint64 {
		seenRRKeys[key] = struct{}{}
		if c, ok := r.rrTrackers[key]; ok {
			return c
		}
		c := &atomic.Uint64{}
		r.rrTrackers[key] = c
		return c
	}

	type rawCompiledPair struct {
		raw      *omnimeshv1.NodeEndpointInfo
		compiled *compiledEndpoint
	}

	for meshIP, svc := range cfg.services {
		if svc == nil || meshIP == "" {
			continue
		}

		sk := serviceKey{namespace: svc.Namespace, name: svc.Name}
		rawNodes := cfg.routes[sk]
		policy := policiesBySvc[sk]

		algorithm := omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_RANDOM
		if policy != nil && policy.LoadBalancer != nil &&
			policy.LoadBalancer.Algorithm != omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_UNSPECIFIED {
			algorithm = policy.LoadBalancer.Algorithm
		}

		retryCfg := resolveRetryConfig(r.defaultRetry, policy)

		var pairs []rawCompiledPair
		var allEndpoints []*compiledEndpoint
		seenInSvc := make(map[model.EndpointKey]struct{}, len(rawNodes))

		for _, ep := range rawNodes {
			if ep == nil {
				continue
			}
			key := endpointKeyOf(ep)
			if _, dup := seenInSvc[key]; dup {
				continue
			}
			seenInSvc[key] = struct{}{}

			healthStatus := cfg.resolveEndpointHealth(svc.Namespace, svc.Name, ep)
			if !isEndpointHealthy(healthStatus) {
				continue
			}

			targetHost := ep.Addr
			if ep.TargetAddress != "" && ep.TargetAddress != localTargetAddr {
				targetHost = ep.TargetAddress
			}

			cep := endpointsByKey[key]
			if cep == nil || cep.targetHost != targetHost {
				cep = &compiledEndpoint{
					key:         key,
					nodeID:      ep.NodeId,
					routeName:   ep.RouteName,
					targetHost:  targetHost,
					activeConns: getConnTracker(key),
				}
				endpointsByKey[key] = cep
			}

			pairs = append(pairs, rawCompiledPair{raw: ep, compiled: cep})
			allEndpoints = append(allEndpoints, cep)
		}

		defaultRealDest := ""
		if svc.Port > 0 && svc.Port <= 65535 {
			defaultRealDest = meshIP + ":" + strconv.FormatInt(int64(svc.Port), 10)
		}

		plan := &compiledServicePlan{
			namespace:        svc.Namespace,
			serviceName:      svc.Name,
			meshAddr:         meshIP,
			protocol:         svc.Protocol,
			defaultPort:      svc.Port,
			defaultRealDest:  defaultRealDest,
			algorithm:        algorithm,
			retry:            retryCfg,
			rawEndpointCount: len(rawNodes),
			allEndpoints:     allEndpoints,
			rrCounter:        getRRTracker(rrTrackerKey{namespace: svc.Namespace, serviceName: svc.Name, groupIdx: -1}),
		}

		if policy != nil && len(policy.Routes) > 0 {
			plan.hasTrafficRules = true
			for idx, rule := range policy.Routes {
				if rule == nil || rule.Weight <= 0 {
					continue
				}
				var matched []*compiledEndpoint
				for _, pair := range pairs {
					if endpointMatchesDestination(pair.raw, rule.Destination) {
						matched = append(matched, pair.compiled)
					}
				}
				if len(matched) == 0 {
					continue
				}
				groupRR := getRRTracker(rrTrackerKey{namespace: svc.Namespace, serviceName: svc.Name, groupIdx: idx})
				plan.groups = append(plan.groups, &compiledRouteGroup{
					weight:    rule.Weight,
					endpoints: matched,
					rrCounter: groupRR,
				})
				plan.totalWeight += int64(rule.Weight)
				plan.cumWeights = append(plan.cumWeights, plan.totalWeight)
			}
		}

		plansByIP[meshIP] = plan
		if ip4, ok := parseIPv4Uint32(meshIP); ok {
			plansByIPv4[ip4] = plan
		}
	}

	// Prune unused trackers whose in-flight counter is zero.
	for k, c := range r.connTrackers {
		if _, ok := seenEndpoints[k]; !ok && c.Load() <= 0 {
			delete(r.connTrackers, k)
		}
	}
	for k := range r.rrTrackers {
		if _, ok := seenRRKeys[k]; !ok {
			delete(r.rrTrackers, k)
		}
	}

	return &routeSnapshot{
		plansByIP:      plansByIP,
		plansByIPv4:    plansByIPv4,
		endpointsByKey: endpointsByKey,
		namespaces:     namespaces,
		subnets:        subnets,
		defaultRetry:   r.defaultRetry,
	}
}

func indexTrafficPolicies(policies map[policyKey]*omnimeshv1.TrafficPolicyInfo) map[serviceKey]*omnimeshv1.TrafficPolicyInfo {
	if len(policies) == 0 {
		return nil
	}
	grouped := make(map[serviceKey][]*omnimeshv1.TrafficPolicyInfo)
	for _, p := range policies {
		if p == nil || p.TargetServiceName == "" {
			continue
		}
		targetNS := p.TargetServiceNamespace
		if targetNS == "" {
			targetNS = p.Namespace
		}
		sk := serviceKey{namespace: targetNS, name: p.TargetServiceName}
		grouped[sk] = append(grouped[sk], p)
	}

	selected := make(map[serviceKey]*omnimeshv1.TrafficPolicyInfo, len(grouped))
	for sk, list := range grouped {
		if len(list) > 1 {
			slices.SortFunc(list, func(a, b *omnimeshv1.TrafficPolicyInfo) int {
				if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
					return c
				}
				return strings.Compare(a.Name, b.Name)
			})
			log.Printf("Router: multiple TrafficPolicies target %s/%s; deterministically selecting %s/%s\n",
				sk.namespace, sk.name, list[0].Namespace, list[0].Name)
		}
		selected[sk] = list[0]
	}
	return selected
}

func resolveRetryConfig(defaults model.RetryConfig, policy *omnimeshv1.TrafficPolicyInfo) model.RetryConfig {
	cfg := defaults
	if policy == nil || policy.Retry == nil {
		return cfg
	}

	rp := policy.Retry
	maxRetries := int(rp.MaxRetries)
	if maxRetries < 0 {
		maxRetries = 0
	}
	cfg.MaxRetries = maxRetries

	if rp.BackoffBaseMs > 0 {
		cfg.BackoffBase = time.Duration(rp.BackoffBaseMs) * time.Millisecond
	} else if rp.BackoffBaseMs < 0 {
		cfg.BackoffBase = 0
	}
	if rp.BackoffMaxMs > 0 {
		cfg.BackoffMax = time.Duration(rp.BackoffMaxMs) * time.Millisecond
	}
	if cfg.BackoffMax < cfg.BackoffBase {
		cfg.BackoffMax = cfg.BackoffBase
	}

	if len(rp.RetryOn) > 0 {
		cfg.RetryOnConnectFail = false
		cfg.RetryOn5xx = false
		for _, tok := range rp.RetryOn {
			switch strings.ToLower(strings.TrimSpace(tok)) {
			case "connect-failure", "connect_failure", "reset":
				cfg.RetryOnConnectFail = true
			case "5xx":
				cfg.RetryOn5xx = true
			case "all":
				cfg.RetryOnConnectFail = true
				cfg.RetryOn5xx = true
			}
		}
	}

	return cfg
}

func endpointKeyOf(ep *omnimeshv1.NodeEndpointInfo) model.EndpointKey {
	if ep == nil {
		return model.EndpointKey{}
	}
	return model.EndpointKey{
		NodeID:    ep.NodeId,
		RouteName: ep.RouteName,
		Addr:      ep.Addr,
	}
}

func isEndpointHealthy(status omnimeshv1.EndpointHealthStatus) bool {
	return status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY &&
		status != omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_DRAINING
}

func endpointMatchesDestination(ep *omnimeshv1.NodeEndpointInfo, dest *omnimeshv1.TrafficRouteDestinationInfo) bool {
	if ep == nil {
		return false
	}
	if dest == nil {
		return true
	}
	if dest.Target != "" && ep.Target != dest.Target {
		return false
	}
	for k, v := range dest.Labels {
		if ep.Labels == nil || ep.Labels[k] != v {
			return false
		}
	}
	return true
}

func parseIPv4Uint32(ipStr string) (uint32, bool) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return 0, false
	}
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

func formatIPv4Port(ip uint32, port uint16) string {
	var buf [22]byte
	b := buf[:0]
	b = strconv.AppendUint(b, uint64(byte(ip>>24)), 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(byte(ip>>16)), 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(byte(ip>>8)), 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(byte(ip)), 10)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port), 10)
	return string(b)
}

func formatHostPort(host string, port uint16) string {
	var buf [64]byte
	b := append(buf[:0], host...)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port), 10)
	return string(b)
}

// Subnets returns a sorted, deduplicated slice of CIDR subnets across all active namespaces.
func (r *Router) Subnets() []string {
	snap := r.snapshot.Load()
	if snap == nil || len(snap.subnets) == 0 {
		return nil
	}
	return slices.Clone(snap.subnets)
}

// Namespaces returns the currently active namespaces sorted by name.
func (r *Router) Namespaces() []*omnimeshv1.NamespaceInfo {
	snap := r.snapshot.Load()
	if snap == nil || len(snap.namespaces) == 0 {
		return nil
	}
	return slices.Clone(snap.namespaces)
}

// AcquireEndpoint increments the active-connection counter for the specified endpoint
// (used by LEAST_CONNECTIONS load balancing) and returns a release callback that must be
// invoked once the tunnel completes or fails.
func (r *Router) AcquireEndpoint(key model.EndpointKey) func() {
	if key == (model.EndpointKey{}) {
		return func() {}
	}
	if snap := r.snapshot.Load(); snap != nil {
		if ep, ok := snap.endpointsByKey[key]; ok && ep.activeConns != nil {
			ep.activeConns.Add(1)
			return func() { ep.activeConns.Add(-1) }
		}
	}
	r.trackerMu.RLock()
	c, ok := r.connTrackers[key]
	r.trackerMu.RUnlock()
	if ok && c != nil {
		c.Add(1)
		return func() { c.Add(-1) }
	}
	return func() {}
}

// ResolveRoute resolves the HBONE target host and real destination endpoint for intercepted traffic.
// Returns nil if the destination service exists in the mesh but has no healthy or matching endpoints.
func (r *Router) ResolveRoute(destIP string, destPort uint16, defaultTargetHost string) *model.ResolvedRoute {
	route, _, err := r.ResolveRouteWithExclusions(destIP, destPort, defaultTargetHost, nil)
	if err != nil {
		return nil
	}
	return route
}

// ResolveRouteWithExclusions resolves a route for string destIP, skipping any endpoints in excluded.
func (r *Router) ResolveRouteWithExclusions(
	destIP string,
	destPort uint16,
	defaultTargetHost string,
	excluded []model.EndpointKey,
) (*model.ResolvedRoute, model.RetryConfig, error) {
	snap := r.snapshot.Load()
	if snap == nil {
		return resolveNoPlan(model.RetryConfig{}, formatHostPort(destIP, destPort), defaultTargetHost, excluded)
	}

	plan := snap.plansByIP[destIP]
	if plan == nil {
		return resolveNoPlan(snap.defaultRetry, formatHostPort(destIP, destPort), defaultTargetHost, excluded)
	}

	realDest := plan.defaultRealDest
	if realDest == "" || int32(destPort) != plan.defaultPort {
		realDest = formatHostPort(destIP, destPort)
	}
	return resolveFromPlan(plan, realDest, defaultTargetHost, excluded)
}

// ResolveRouteIPv4 resolves a route for a big-endian uint32 IPv4 address on the hot path,
// skipping any endpoints in excluded.
func (r *Router) ResolveRouteIPv4(
	destIP uint32,
	destPort uint16,
	defaultTargetHost string,
	excluded []model.EndpointKey,
) (*model.ResolvedRoute, model.RetryConfig, error) {
	snap := r.snapshot.Load()
	if snap == nil {
		return resolveNoPlan(model.RetryConfig{}, formatIPv4Port(destIP, destPort), defaultTargetHost, excluded)
	}

	plan := snap.plansByIPv4[destIP]
	if plan == nil {
		return resolveNoPlan(snap.defaultRetry, formatIPv4Port(destIP, destPort), defaultTargetHost, excluded)
	}

	realDest := plan.defaultRealDest
	if realDest == "" || int32(destPort) != plan.defaultPort {
		realDest = formatIPv4Port(destIP, destPort)
	}
	return resolveFromPlan(plan, realDest, defaultTargetHost, excluded)
}

// HasAvailableEndpointIPv4 reports whether at least one non-excluded eligible endpoint
// currently exists for the given IPv4 destination.
func (r *Router) HasAvailableEndpointIPv4(destIP uint32, excluded []model.EndpointKey) bool {
	snap := r.snapshot.Load()
	if snap == nil {
		return false
	}
	plan := snap.plansByIPv4[destIP]
	if plan == nil || plan.rawEndpointCount == 0 || len(plan.allEndpoints) == 0 {
		return false
	}
	if plan.hasTrafficRules {
		for _, g := range plan.groups {
			if poolHasAvailable(g.endpoints, excluded) {
				return true
			}
		}
		return false
	}
	return poolHasAvailable(plan.allEndpoints, excluded)
}

func resolveNoPlan(cfg model.RetryConfig, realDest, defaultTargetHost string, excluded []model.EndpointKey) (*model.ResolvedRoute, model.RetryConfig, error) {
	if len(excluded) == 0 && defaultTargetHost != "" {
		cfg.MaxRetries = 0
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   realDest,
		}, cfg, nil
	}
	return nil, cfg, domain.ErrNoRoute
}

func resolveFromPlan(
	plan *compiledServicePlan,
	realDest string,
	defaultTargetHost string,
	excluded []model.EndpointKey,
) (*model.ResolvedRoute, model.RetryConfig, error) {
	if plan.rawEndpointCount == 0 {
		if len(excluded) == 0 && defaultTargetHost != "" {
			fallbackCfg := plan.retry
			fallbackCfg.MaxRetries = 0
			return &model.ResolvedRoute{
				TargetHost:  defaultTargetHost,
				RealDest:    realDest,
				Namespace:   plan.namespace,
				ServiceName: plan.serviceName,
				Protocol:    plan.protocol,
			}, fallbackCfg, nil
		}
		return nil, plan.retry, domain.ErrNoRoute
	}

	if len(plan.allEndpoints) == 0 {
		return nil, plan.retry, domain.ErrNoHealthyEndpoints
	}

	var chosen *compiledEndpoint
	var err error
	if plan.hasTrafficRules {
		if len(plan.groups) == 0 {
			return nil, plan.retry, domain.ErrNoMatchingEndpoints
		}
		chosen, err = selectFromWeightedGroups(plan, excluded)
	} else {
		chosen = selectFromPool(plan.allEndpoints, plan.algorithm, plan.rrCounter, excluded)
		if chosen == nil {
			err = domain.ErrNoAvailableEndpoints
		}
	}
	if err != nil || chosen == nil {
		if err == nil {
			err = domain.ErrNoAvailableEndpoints
		}
		return nil, plan.retry, err
	}

	targetHost := chosen.targetHost
	if targetHost == "" {
		targetHost = defaultTargetHost
	}

	return &model.ResolvedRoute{
		TargetHost:  targetHost,
		RealDest:    realDest,
		ServiceID:   chosen.routeName,
		NodeID:      chosen.nodeID,
		Namespace:   plan.namespace,
		ServiceName: plan.serviceName,
		Protocol:    plan.protocol,
		EndpointKey: chosen.key,
	}, plan.retry, nil
}

func selectFromWeightedGroups(plan *compiledServicePlan, excluded []model.EndpointKey) (*compiledEndpoint, error) {
	if len(excluded) == 0 {
		g := pickGroupFast(plan)
		ep := selectFromPool(g.endpoints, plan.algorithm, g.rrCounter, nil)
		if ep == nil {
			return nil, domain.ErrNoAvailableEndpoints
		}
		return ep, nil
	}

	var idxBuf [16]int
	activeIdx := idxBuf[:0]
	var activeWeight int64

	for i, g := range plan.groups {
		if poolHasAvailable(g.endpoints, excluded) {
			activeIdx = append(activeIdx, i)
			activeWeight += int64(g.weight)
		}
	}
	if activeWeight <= 0 || len(activeIdx) == 0 {
		return nil, domain.ErrNoAvailableEndpoints
	}

	r := rand.Int64N(activeWeight)
	var cum int64
	chosenGroup := plan.groups[activeIdx[len(activeIdx)-1]]
	for _, gi := range activeIdx {
		g := plan.groups[gi]
		cum += int64(g.weight)
		if cum > r {
			chosenGroup = g
			break
		}
	}

	ep := selectFromPool(chosenGroup.endpoints, plan.algorithm, chosenGroup.rrCounter, excluded)
	if ep == nil {
		return nil, domain.ErrNoAvailableEndpoints
	}
	return ep, nil
}

func pickGroupFast(plan *compiledServicePlan) *compiledRouteGroup {
	n := len(plan.groups)
	if n == 1 {
		return plan.groups[0]
	}
	r := rand.Int64N(plan.totalWeight)
	if n <= 8 {
		for i, cw := range plan.cumWeights {
			if cw > r {
				return plan.groups[i]
			}
		}
		return plan.groups[n-1]
	}
	idx := sort.Search(n, func(i int) bool {
		return plan.cumWeights[i] > r
	})
	if idx >= n {
		idx = n - 1
	}
	return plan.groups[idx]
}

func selectFromPool(
	endpoints []*compiledEndpoint,
	alg omnimeshv1.LoadBalancerAlgorithm,
	rrCounter *atomic.Uint64,
	excluded []model.EndpointKey,
) *compiledEndpoint {
	n := len(endpoints)
	if n == 0 {
		return nil
	}

	if len(excluded) == 0 {
		switch alg {
		case omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN:
			idx := (rrCounter.Add(1) - 1) % uint64(n)
			return endpoints[idx]
		case omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_LEAST_CONNECTIONS:
			return selectLeastConnFast(endpoints)
		default: // RANDOM (and UNSPECIFIED)
			return endpoints[rand.IntN(n)]
		}
	}

	switch alg {
	case omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN:
		start := (rrCounter.Add(1) - 1) % uint64(n)
		for i := 0; i < n; i++ {
			cand := endpoints[(start+uint64(i))%uint64(n)]
			if !isExcluded(cand.key, excluded) {
				return cand
			}
		}
		return nil
	case omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_LEAST_CONNECTIONS:
		return selectLeastConnExcluded(endpoints, excluded)
	default: // RANDOM
		return selectRandomExcluded(endpoints, excluded)
	}
}

func selectRandomExcluded(endpoints []*compiledEndpoint, excluded []model.EndpointKey) *compiledEndpoint {
	if len(endpoints) <= 64 {
		var buf [64]*compiledEndpoint
		avail := buf[:0]
		for _, ep := range endpoints {
			if !isExcluded(ep.key, excluded) {
				avail = append(avail, ep)
			}
		}
		if len(avail) == 0 {
			return nil
		}
		return avail[rand.IntN(len(avail))]
	}

	// Reservoir sampling for > 64 endpoints without heap allocation.
	var chosen *compiledEndpoint
	seen := 0
	for _, ep := range endpoints {
		if isExcluded(ep.key, excluded) {
			continue
		}
		seen++
		if rand.IntN(seen) == 0 {
			chosen = ep
		}
	}
	return chosen
}

func selectLeastConnFast(endpoints []*compiledEndpoint) *compiledEndpoint {
	n := len(endpoints)
	if n == 1 {
		return endpoints[0]
	}
	if n <= 8 {
		var best *compiledEndpoint
		var minConns int64
		ties := 0
		for _, ep := range endpoints {
			c := ep.activeConns.Load()
			if best == nil || c < minConns {
				best = ep
				minConns = c
				ties = 1
			} else if c == minConns {
				ties++
				if rand.IntN(ties) == 0 {
					best = ep
				}
			}
		}
		return best
	}

	// Power of Two Choices (P2C) for larger pools.
	i := rand.IntN(n)
	j := rand.IntN(n - 1)
	if j >= i {
		j++
	}
	ci := endpoints[i].activeConns.Load()
	cj := endpoints[j].activeConns.Load()
	if ci < cj {
		return endpoints[i]
	}
	if cj < ci {
		return endpoints[j]
	}
	if rand.IntN(2) == 0 {
		return endpoints[i]
	}
	return endpoints[j]
}

func selectLeastConnExcluded(endpoints []*compiledEndpoint, excluded []model.EndpointKey) *compiledEndpoint {
	if len(endpoints) <= 64 {
		var buf [64]*compiledEndpoint
		avail := buf[:0]
		for _, ep := range endpoints {
			if !isExcluded(ep.key, excluded) {
				avail = append(avail, ep)
			}
		}
		if len(avail) == 0 {
			return nil
		}
		return selectLeastConnFast(avail)
	}

	var best *compiledEndpoint
	var minConns int64
	ties := 0
	for _, ep := range endpoints {
		if isExcluded(ep.key, excluded) {
			continue
		}
		c := ep.activeConns.Load()
		if best == nil || c < minConns {
			best = ep
			minConns = c
			ties = 1
		} else if c == minConns {
			ties++
			if rand.IntN(ties) == 0 {
				best = ep
			}
		}
	}
	return best
}

func poolHasAvailable(endpoints []*compiledEndpoint, excluded []model.EndpointKey) bool {
	for _, ep := range endpoints {
		if !isExcluded(ep.key, excluded) {
			return true
		}
	}
	return false
}

func isExcluded(key model.EndpointKey, excluded []model.EndpointKey) bool {
	for i := range excluded {
		if excluded[i] == key {
			return true
		}
	}
	return false
}
