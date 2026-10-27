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
	services   map[string]*omnimeshv1.ServiceInfo   // key: "meshAddr:port" and "meshAddr"
	routes     map[string]*omnimeshv1.RouteInfo     // key: "namespace/serviceName"
	namespaces map[string]*omnimeshv1.NamespaceInfo // key: namespace name
}

// newRouteConfig allocates a new, empty routeConfig.
func newRouteConfig() *routeConfig {
	return &routeConfig{
		services:   make(map[string]*omnimeshv1.ServiceInfo),
		routes:     make(map[string]*omnimeshv1.RouteInfo),
		namespaces: make(map[string]*omnimeshv1.NamespaceInfo),
	}
}

// clone creates a shallow copy of the routeConfig maps.
func (c *routeConfig) clone() *routeConfig {
	copy := newRouteConfig()
	if c == nil {
		return copy
	}
	for k, v := range c.services {
		copy.services[k] = v
	}
	for k, v := range c.routes {
		copy.routes[k] = v
	}
	for k, v := range c.namespaces {
		copy.namespaces[k] = v
	}
	return copy
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
	roundRobinCounter uint64
}

// NewRouter creates a new thread-safe mesh router.
func NewRouter() *Router {
	return &Router{
		config: newRouteConfig(),
	}
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
	workingCopy := newRouteConfig()

	// 3. Apply updates to working copy.
	for _, svc := range snapshot.Services {
		key := fmt.Sprintf("%s:%d", svc.MeshAddr, svc.Port)
		workingCopy.services[key] = svc
		// Also index by MeshAddr alone for fallback matching
		if _, exists := workingCopy.services[svc.MeshAddr]; !exists {
			workingCopy.services[svc.MeshAddr] = svc
		}
	}

	for _, route := range snapshot.Routes {
		key := fmt.Sprintf("%s/%s", route.Namespace, route.ServiceName)
		workingCopy.routes[key] = route
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
			key := fmt.Sprintf("%s:%d", svc.MeshAddr, svc.Port)
			delete(workingCopy.services, key)
			delete(workingCopy.services, svc.MeshAddr)
		}
		for _, route := range update.Routes {
			key := fmt.Sprintf("%s/%s", route.Namespace, route.ServiceName)
			delete(workingCopy.routes, key)
		}
		for _, ns := range update.Namespaces {
			if key := namespaceKey(ns); key != "" {
				delete(workingCopy.namespaces, key)
			}
		}
	default: // ADD or MODIFY
		for _, svc := range update.Services {
			key := fmt.Sprintf("%s:%d", svc.MeshAddr, svc.Port)
			workingCopy.services[key] = svc
			if _, exists := workingCopy.services[svc.MeshAddr]; !exists {
				workingCopy.services[svc.MeshAddr] = svc
			}
		}
		for _, route := range update.Routes {
			key := fmt.Sprintf("%s/%s", route.Namespace, route.ServiceName)
			workingCopy.routes[key] = route
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
	r.mu.RUnlock()

	if cfg == nil {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	// Try matching by exact "IP:Port"
	keyWithPort := fmt.Sprintf("%s:%d", destIP, destPort)
	svc, ok := cfg.services[keyWithPort]
	if !ok {
		// Fallback match by IP
		svc, ok = cfg.services[destIP]
	}

	if !ok {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	routeKey := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
	route, routeOk := cfg.routes[routeKey]
	if !routeOk || len(route.TargetNodes) == 0 {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	// Pick target node (round robin across target nodes)
	count := uint64(len(route.TargetNodes))
	idx := atomic.AddUint64(&r.roundRobinCounter, 1) % count
	targetNode := route.TargetNodes[idx]

	targetHost := targetNode.Addr
	if targetHost == "" {
		targetHost = defaultTargetHost
	}

	realDest := targetNode.TargetAddress
	if realDest == "" {
		realDest = fallbackRealDest
	}

	return &model.ResolvedRoute{
		TargetHost: targetHost,
		RealDest:   realDest,
	}
}
