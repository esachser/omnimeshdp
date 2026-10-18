package proxy_test

import (
	"testing"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
)

func TestRouter_ApplySnapshotAndResolve(t *testing.T) {
	router := proxy.NewRouter()

	snapshot := &omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{
				Namespace: "default",
				Name:      "product-service",
				MeshAddr:  "10.10.10.50",
				Port:      8080,
			},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "product-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:   "node-2",
						Addr:     "192.168.1.102:15008",
						TargetAddress: "10.10.10.50:8080",
					},
				},
			},
		},
	}

	router.ApplySnapshot(snapshot)

	// Resolve existing route with exact port
	route := router.ResolveRoute("10.10.10.50", 8080, "fallback:15008")
	if route == nil {
		t.Fatalf("expected resolved route, got nil")
	}
	if route.TargetHost != "192.168.1.102:15008" {
		t.Errorf("expected TargetHost '192.168.1.102:15008', got %q", route.TargetHost)
	}
	if route.RealDest != "10.10.10.50:8080" {
		t.Errorf("expected RealDest '10.10.10.50:8080', got %q", route.RealDest)
	}

	// Resolve unknown destination falls back gracefully
	fallbackRoute := router.ResolveRoute("10.99.99.99", 9000, "default-proxy:15008")
	if fallbackRoute.TargetHost != "default-proxy:15008" {
		t.Errorf("expected fallback TargetHost, got %q", fallbackRoute.TargetHost)
	}
	if fallbackRoute.RealDest != "10.99.99.99:9000" {
		t.Errorf("expected fallback RealDest '10.99.99.99:9000', got %q", fallbackRoute.RealDest)
	}
}

func TestRouter_ApplyUpdate(t *testing.T) {
	router := proxy.NewRouter()

	// 1. Initial snapshot
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{
				Namespace: "default",
				Name:      "cart-service",
				MeshAddr:  "10.10.10.60",
				Port:      8080,
			},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "cart-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:   "node-1",
						Addr:     "192.168.1.101:15008",
						TargetAddress: "10.10.10.60:8080",
					},
				},
			},
		},
	})

	// Verify route exists
	route := router.ResolveRoute("10.10.10.60", 8080, "fallback:15008")
	if route.TargetHost != "192.168.1.101:15008" {
		t.Fatalf("expected node-1 target, got %s", route.TargetHost)
	}

	// 2. Modify route with ScopeUpdate
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "cart-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:   "node-3",
						Addr:     "192.168.1.103:15008",
						TargetAddress: "10.10.10.60:9090",
					},
				},
			},
		},
	})

	updatedRoute := router.ResolveRoute("10.10.10.60", 8080, "fallback:15008")
	if updatedRoute.TargetHost != "192.168.1.103:15008" {
		t.Errorf("expected updated TargetHost, got %s", updatedRoute.TargetHost)
	}
	if updatedRoute.RealDest != "10.10.10.60:9090" {
		t.Errorf("expected updated RealDest, got %s", updatedRoute.RealDest)
	}

	// 3. Remove route
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Services: []*omnimeshv1.ServiceInfo{
			{
				Namespace: "default",
				Name:      "cart-service",
				MeshAddr:  "10.10.10.60",
				Port:      8080,
			},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "cart-service",
			},
		},
	})

	removedRoute := router.ResolveRoute("10.10.10.60", 8080, "fallback:15008")
	if removedRoute.TargetHost != "fallback:15008" {
		t.Errorf("expected fallback TargetHost after removal, got %s", removedRoute.TargetHost)
	}
}
