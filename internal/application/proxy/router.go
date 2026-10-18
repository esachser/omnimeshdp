package proxy

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

/**
TODO: Create a full update on every cycle.
With that, we can reduce the lock contention.

How it should work:
1. Receive full or partial snapshot.
2. Create working copy of the config
3. Apply updates to working copy.
4. Commit working copy to main config.

That way, we need lock to update snapshot,
but only a reduced lock to get the pointer
to the main map for ResolveRoute.
*/

// Router maintains mesh routing tables derived from ScopeSnapshot and ScopeUpdate messages.
type Router struct {
	mu                sync.RWMutex
	services          map[string]*omnimeshv1.ServiceInfo // key: "meshAddr:port"
	routes            map[string]*omnimeshv1.RouteInfo   // key: "namespace/serviceName"
	roundRobinCounter uint64
}

// NewRouter creates a new thread-safe mesh router.
func NewRouter() *Router {
	return &Router{
		services: make(map[string]*omnimeshv1.ServiceInfo),
		routes:   make(map[string]*omnimeshv1.RouteInfo),
	}
}

// ApplySnapshot replaces the routing table with the provided ScopeSnapshot.
func (r *Router) ApplySnapshot(snapshot *omnimeshv1.ScopeSnapshot) {
	if snapshot == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.services = make(map[string]*omnimeshv1.ServiceInfo)
	r.routes = make(map[string]*omnimeshv1.RouteInfo)

	for _, svc := range snapshot.Services {
		key := fmt.Sprintf("%s:%d", svc.MeshAddr, svc.Port)
		r.services[key] = svc
		// Also index by MeshAddr alone for fallback matching
		if _, exists := r.services[svc.MeshAddr]; !exists {
			r.services[svc.MeshAddr] = svc
		}
	}

	for _, route := range snapshot.Routes {
		key := fmt.Sprintf("%s/%s", route.Namespace, route.ServiceName)
		r.routes[key] = route
	}

	log.Printf("Router: ScopeSnapshot applied with %d services and %d routes\n",
		len(snapshot.Services), len(snapshot.Routes))
}

// ApplyUpdate incrementally updates the routing table with a ScopeUpdate.
func (r *Router) ApplyUpdate(update *omnimeshv1.ScopeUpdate) {
	if update == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch update.Type {
	case omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE:
		for _, svc := range update.Services {
			key := fmt.Sprintf("%s:%d", svc.MeshAddr, svc.Port)
			delete(r.services, key)
			delete(r.services, svc.MeshAddr)
		}
		for _, route := range update.Routes {
			key := fmt.Sprintf("%s/%s", route.Namespace, route.ServiceName)
			delete(r.routes, key)
		}
	default: // ADD or MODIFY
		for _, svc := range update.Services {
			key := fmt.Sprintf("%s:%d", svc.MeshAddr, svc.Port)
			r.services[key] = svc
			if _, exists := r.services[svc.MeshAddr]; !exists {
				r.services[svc.MeshAddr] = svc
			}
		}
		for _, route := range update.Routes {
			key := fmt.Sprintf("%s/%s", route.Namespace, route.ServiceName)
			r.routes[key] = route
		}
	}

	log.Printf("Router: ScopeUpdate (%v) applied with %d services and %d routes\n",
		update.Type, len(update.Services), len(update.Routes))
}

// ResolveRoute resolves the HBONE target host and real destination endpoint for intercepted traffic.
func (r *Router) ResolveRoute(destIP string, destPort uint16, defaultTargetHost string) *model.ResolvedRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fallbackRealDest := fmt.Sprintf("%s:%d", destIP, destPort)

	// Try matching by exact "IP:Port"
	keyWithPort := fmt.Sprintf("%s:%d", destIP, destPort)
	svc, ok := r.services[keyWithPort]
	if !ok {
		// Fallback match by IP
		svc, ok = r.services[destIP]
	}

	if !ok {
		return &model.ResolvedRoute{
			TargetHost: defaultTargetHost,
			RealDest:   fallbackRealDest,
		}
	}

	routeKey := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
	route, routeOk := r.routes[routeKey]
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
