package proxy

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

/*
Full update on every cycle implementation.
Reduces lock contention by using copy-on-write routing tables:
1. Receive full or partial snapshot.
2. Create working copy of the config.
3. Apply updates to working copy.
4. Commit working copy to main config.

Lock is required to serialize snapshot/update operations,
but only a reduced read lock is needed to get the pointer
to the main config for ResolveRoute.
*/

// routeConfig stores the routing tables for services, routes, and namespaces.
// Once committed to Router, instances of routeConfig are immutable.
type routeConfig struct {
	services        map[string]*omnimeshv1.ServiceInfo                   // key: destination IP (MeshAddr)
	routes          map[string]map[string][]*omnimeshv1.NodeEndpointInfo // key: namespace -> serviceName -> TargetNodes
	nodes           map[string]*omnimeshv1.NodeEndpointInfo              // key: nodeID -> endpoint metadata
	targetAddresses map[string]string                                    // key: target name -> targetAddress
	namespaces      map[string]*omnimeshv1.NamespaceInfo                 // key: namespace name
}

// newRouteConfig allocates a new, empty routeConfig.
func newRouteConfig() *routeConfig {
	return &routeConfig{
		services:        make(map[string]*omnimeshv1.ServiceInfo),
		routes:          make(map[string]map[string][]*omnimeshv1.NodeEndpointInfo),
		nodes:           make(map[string]*omnimeshv1.NodeEndpointInfo),
		targetAddresses: make(map[string]string),
		namespaces:      make(map[string]*omnimeshv1.NamespaceInfo),
	}
}

// clone creates a deep copy of the routeConfig maps and target node slices.
func (c *routeConfig) clone() *routeConfig {
	copy := newRouteConfig()
	if c == nil {
		return copy
	}
	for k, v := range c.services {
		copy.services[k] = v
	}
	for ns, svcRoutes := range c.routes {
		nsCopy := make(map[string][]*omnimeshv1.NodeEndpointInfo, len(svcRoutes))
		for svcName, endpoints := range svcRoutes {
			nsCopy[svcName] = slices.Clone(endpoints)
		}
		copy.routes[ns] = nsCopy
	}
	for k, v := range c.nodes {
		copy.nodes[k] = v
	}
	for k, v := range c.targetAddresses {
		copy.targetAddresses[k] = v
	}
	for k, v := range c.namespaces {
		copy.namespaces[k] = v
	}
	return copy
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
	nsRoutes, ok := c.routes[route.Namespace]
	if !ok {
		nsRoutes = make(map[string][]*omnimeshv1.NodeEndpointInfo)
		c.routes[route.Namespace] = nsRoutes
	}

	endpoints := nsRoutes[route.ServiceName]
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
	nsRoutes[route.ServiceName] = endpoints
}

func (c *routeConfig) removeRoute(route *omnimeshv1.RouteInfo) {
	if route == nil {
		return
	}
	nsRoutes, ok := c.routes[route.Namespace]
	if !ok {
		return
	}

	if len(route.TargetNodes) == 0 {
		delete(nsRoutes, route.ServiceName)
	} else {
		remaining := removeTargetNodes(nsRoutes[route.ServiceName], route.TargetNodes)
		if len(remaining) == 0 {
			delete(nsRoutes, route.ServiceName)
		} else {
			nsRoutes[route.ServiceName] = remaining
		}
	}

	if len(nsRoutes) == 0 {
		delete(c.routes, route.Namespace)
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

// Router maintains mesh routing tables derived from ScopeSnapshot and ScopeUpdate messages.
type Router struct {
	updateMu          sync.Mutex
	mu                sync.RWMutex
	config            *routeConfig
	nodeID            string
	target            string
	targetAddress     string
	roundRobinCounter uint64
}

// NewRouter creates a new thread-safe mesh router.
func NewRouter() *Router {
	return &Router{
		config: newRouteConfig(),
	}
}

// NewRouterWithNode creates a new thread-safe mesh router configured with the local node identity and target.
func NewRouterWithNode(nodeID, target string) *Router {
	return &Router{
		config: newRouteConfig(),
		nodeID: nodeID,
		target: target,
	}
}

// SetNodeInfo sets the local node ID and network target of the node processing connections.
func (r *Router) SetNodeInfo(nodeID, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodeID = nodeID
	r.target = target
}

// SetNodeID sets the local node ID of the node processing connections.
func (r *Router) SetNodeID(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodeID = nodeID
}

// SetTargetAddress explicitly sets the TargetAddress of the node processing connections.
func (r *Router) SetTargetAddress(targetAddress string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targetAddress = targetAddress
}

// ApplySnapshot replaces the routing table with the provided ScopeSnapshot.
func (r *Router) ApplySnapshot(snapshot *omnimeshv1.ScopeSnapshot) {
	if snapshot == nil {
		return
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()

	// 1. Receive full snapshot.
	// 2. Create working copy of the config.
	r.mu.RLock()
	current := r.config
	r.mu.RUnlock()

	workingCopy := newRouteConfig()
	if current != nil {
		for k, v := range current.nodes {
			workingCopy.nodes[k] = v
		}
		for k, v := range current.targetAddresses {
			workingCopy.targetAddresses[k] = v
		}
	}

	// 3. Apply updates to working copy.
	for _, svc := range snapshot.Services {
		workingCopy.addService(svc)
	}

	for _, route := range snapshot.Routes {
		workingCopy.addRoute(route)
	}

	for _, ns := range snapshot.Namespaces {
		if key := namespaceKey(ns); key != "" {
			workingCopy.namespaces[key] = ns
		}
	}

	// 4. Commit working copy to main config.
	r.mu.Lock()
	r.config = workingCopy
	r.mu.Unlock()

	log.Printf("Router: ScopeSnapshot applied with %d services, %d routes, and %d namespaces\n",
		len(snapshot.Services), len(snapshot.Routes), len(snapshot.Namespaces))
}

// ApplyUpdate incrementally updates the routing table with a ScopeUpdate.
func (r *Router) ApplyUpdate(update *omnimeshv1.ScopeUpdate) {
	if update == nil {
		return
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()

	// 1. Receive partial snapshot / update.
	// 2. Create working copy of the config.
	r.mu.RLock()
	current := r.config
	r.mu.RUnlock()

	workingCopy := current.clone()

	// 3. Apply updates to working copy.
	switch update.Type {
	case omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE:
		for _, svc := range update.Services {
			workingCopy.removeService(svc)
		}
		for _, route := range update.Routes {
			workingCopy.removeRoute(route)
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
		for _, ns := range update.Namespaces {
			if key := namespaceKey(ns); key != "" {
				workingCopy.namespaces[key] = ns
			}
		}
	}

	// 4. Commit working copy to main config.
	r.mu.Lock()
	r.config = workingCopy
	r.mu.Unlock()

	log.Printf("Router: ScopeUpdate (%v) applied with %d services, %d routes, and %d namespaces\n",
		update.Type, len(update.Services), len(update.Routes), len(update.Namespaces))
}

// Subnets returns a sorted, deduplicated slice of CIDR subnets across all active namespaces.
func (r *Router) Subnets() []string {
	r.mu.RLock()
	cfg := r.config
	r.mu.RUnlock()

	if cfg == nil || len(cfg.namespaces) == 0 {
		return nil
	}

	var subnets []string
	for _, ns := range cfg.namespaces {
		subnets = append(subnets, extractNamespaceSubnets(ns)...)
	}
	if len(subnets) == 0 {
		return nil
	}

	slices.Sort(subnets)
	return slices.Compact(subnets)
}

// Namespaces returns the currently active namespaces sorted by name.
func (r *Router) Namespaces() []*omnimeshv1.NamespaceInfo {
	r.mu.RLock()
	cfg := r.config
	r.mu.RUnlock()

	if cfg == nil || len(cfg.namespaces) == 0 {
		return nil
	}

	out := make([]*omnimeshv1.NamespaceInfo, 0, len(cfg.namespaces))
	for _, ns := range cfg.namespaces {
		out = append(out, ns)
	}
	slices.SortFunc(out, func(a, b *omnimeshv1.NamespaceInfo) int {
		return strings.Compare(a.GetName(), b.GetName())
	})
	return out
}

// ResolveRoute resolves the HBONE target host and real destination endpoint for intercepted traffic.
func (r *Router) ResolveRoute(destIP string, destPort uint16, defaultTargetHost string) *model.ResolvedRoute {
	fallbackRealDest := fmt.Sprintf("%s:%d", destIP, destPort)

	// Acquire reduced read lock solely to get pointer to current routing config
	r.mu.RLock()
	cfg := r.config
	nodeID := r.nodeID
	nodeTarget := r.target
	nodeTargetAddr := r.targetAddress
	r.mu.RUnlock()

	if cfg == nil {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	// 1. Find destination service using the destination IP.
	svc, ok := cfg.services[destIP]
	if !ok {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	// 2. Separate the TargetNodes routes that are possible to that service.
	nsRoutes, ok := cfg.routes[svc.Namespace]
	if !ok {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}
	targetNodes := nsRoutes[svc.Name]
	if len(targetNodes) == 0 {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	// 3. Pick target node (round robin across target nodes).
	count := uint64(len(targetNodes))
	idx := (atomic.AddUint64(&r.roundRobinCounter, 1) - 1) % count
	targetNode := targetNodes[idx]

	// 4. If the selected node has a TargetAddress, and the node processing the
	// information has a different TargetAddress, use it as targetHost.
	targetHost := targetNode.Addr
	if targetNode.TargetAddress != "" {
		localTargetAddr := cfg.resolveLocalTargetAddress(nodeID, nodeTarget, nodeTargetAddr)
		if targetNode.TargetAddress != localTargetAddr {
			targetHost = targetNode.TargetAddress
		}
	}
	if targetHost == "" {
		targetHost = defaultTargetHost
	}

	return &model.ResolvedRoute{
		TargetHost: targetHost,
		RealDest:   fallbackRealDest,
	}
}
