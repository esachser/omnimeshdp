package proxy_test

import (
	"slices"
	"sync"
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
						NodeId: "node-2",
						Addr:   "192.168.1.102:15008",
					},
				},
			},
		},
	}

	router.ApplySnapshot(snapshot)

	// Resolve existing route by destination IP
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
						NodeId: "node-1",
						Addr:   "192.168.1.101:15008",
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

	// 2. Modify existing node route with ScopeUpdate
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "cart-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId: "node-1",
						Addr:   "192.168.1.103:15008",
					},
				},
			},
		},
	})

	updatedRoute := router.ResolveRoute("10.10.10.60", 8080, "fallback:15008")
	if updatedRoute.TargetHost != "192.168.1.103:15008" {
		t.Errorf("expected updated TargetHost, got %s", updatedRoute.TargetHost)
	}
	if updatedRoute.RealDest != "10.10.10.60:8080" {
		t.Errorf("expected RealDest '10.10.10.60:8080', got %s", updatedRoute.RealDest)
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

func TestRouter_RoundRobinAndTargetAddressRouting(t *testing.T) {
	// Node processing the connection is "node-local" in target "target-a" (gateway "gw-a.internal:8443")
	router := proxy.NewRouterWithNode("node-local", "target-a")

	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{
				Namespace: "production",
				Name:      "payment-service",
				MeshAddr:  "10.10.20.10",
				Port:      8080,
			},
			{
				Namespace: "production",
				Name:      "order-service",
				MeshAddr:  "10.10.20.11",
				Port:      9090,
			},
		},
		Routes: []*omnimeshv1.RouteInfo{
			// Local node's own route (establishes local node's TargetAddress = "gw-a.internal:8443")
			{
				Namespace:   "production",
				ServiceName: "order-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:        "node-local",
						Addr:          "192.168.1.10:15008",
						RouteName:     "order-local-1",
						Target:        "target-a",
						TargetAddress: "gw-a.internal:8443",
					},
				},
			},
			// First target node for payment-service: in the SAME target ("target-a", same TargetAddress)
			{
				Namespace:   "production",
				ServiceName: "payment-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:        "node-peer-same-target",
						Addr:          "192.168.1.20:15008",
						RouteName:     "payment-1",
						Target:        "target-a",
						TargetAddress: "gw-a.internal:8443",
					},
				},
			},
			// Second target node for payment-service: in a DIFFERENT target ("target-b", different TargetAddress)
			{
				Namespace:   "production",
				ServiceName: "payment-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:        "node-remote-target",
						Addr:          "10.244.1.50:15008",
						RouteName:     "payment-2",
						Target:        "target-b",
						TargetAddress: "gw-b.external:8443",
					},
				},
			},
		},
	})

	// 1st connection: selects node-peer-same-target (same TargetAddress -> uses direct Addr)
	r1 := router.ResolveRoute("10.10.20.10", 8080, "fallback:15008")
	if r1.TargetHost != "192.168.1.20:15008" {
		t.Errorf("expected 1st route to use direct node Addr '192.168.1.20:15008', got %q", r1.TargetHost)
	}
	if r1.RealDest != "10.10.20.10:8080" {
		t.Errorf("expected RealDest '10.10.20.10:8080', got %q", r1.RealDest)
	}

	// 2nd connection: selects node-remote-target (different TargetAddress -> uses TargetAddress as targetHost)
	r2 := router.ResolveRoute("10.10.20.10", 8080, "fallback:15008")
	if r2.TargetHost != "gw-b.external:8443" {
		t.Errorf("expected 2nd route to use remote TargetAddress 'gw-b.external:8443', got %q", r2.TargetHost)
	}

	// 3rd connection: wraps around round-robin back to 1st target node
	r3 := router.ResolveRoute("10.10.20.10", 8080, "fallback:15008")
	if r3.TargetHost != "192.168.1.20:15008" {
		t.Errorf("expected 3rd route to wrap around to '192.168.1.20:15008', got %q", r3.TargetHost)
	}

	// Remove only the remote target node via ScopeUpdate; peer node in target-a must remain
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "production",
				ServiceName: "payment-service",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:    "node-remote-target",
						RouteName: "payment-2",
					},
				},
			},
		},
	})

	r4 := router.ResolveRoute("10.10.20.10", 8080, "fallback:15008")
	if r4.TargetHost != "192.168.1.20:15008" {
		t.Errorf("expected remaining route '192.168.1.20:15008', got %q", r4.TargetHost)
	}
	if r4.ServiceID != "payment-1" {
		t.Errorf("expected ServiceID 'payment-1', got %q", r4.ServiceID)
	}
	if r4.Namespace != "production" || r4.ServiceName != "payment-service" {
		t.Errorf("expected Namespace='production' ServiceName='payment-service', got %q/%q", r4.Namespace, r4.ServiceName)
	}
}

func TestRouter_ConcurrentAccess(t *testing.T) {
	router := proxy.NewRouter()

	// Seed with an initial snapshot
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{
				Namespace: "default",
				Name:      "service-0",
				MeshAddr:  "10.0.0.1",
				Port:      8080,
			},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "service-0",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{
						NodeId:        "node-0",
						Addr:          "192.168.1.1:15008",
						TargetAddress: "10.0.0.1:8080",
					},
				},
			},
		},
	})

	var readerWg sync.WaitGroup
	var writerWg sync.WaitGroup
	stopCh := make(chan struct{})

	// Launch reader goroutines continuously resolving routes
	for i := 0; i < 10; i++ {
		readerWg.Add(1)
		go func(readerID int) {
			defer readerWg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					route := router.ResolveRoute("10.0.0.1", 8080, "fallback:15008")
					if route == nil {
						t.Errorf("reader %d got nil route", readerID)
					}
				}
			}
		}(i)
	}

	// Launch writer goroutines modifying/updating routes
	for i := 0; i < 4; i++ {
		writerWg.Add(1)
		go func(writerID int) {
			defer writerWg.Done()
			for j := 0; j < 50; j++ {
				router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
					Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
					Services: []*omnimeshv1.ServiceInfo{
						{
							Namespace: "default",
							Name:      "service-0",
							MeshAddr:  "10.0.0.1",
							Port:      8080,
						},
					},
					Routes: []*omnimeshv1.RouteInfo{
						{
							Namespace:   "default",
							ServiceName: "service-0",
							TargetNodes: []*omnimeshv1.NodeEndpointInfo{
								{
									NodeId:        "node-1",
									Addr:          "192.168.1.2:15008",
									TargetAddress: "10.0.0.1:8080",
								},
							},
						},
					},
				})

				router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
					Services: []*omnimeshv1.ServiceInfo{
						{
							Namespace: "default",
							Name:      "service-0",
							MeshAddr:  "10.0.0.1",
							Port:      8080,
						},
					},
					Routes: []*omnimeshv1.RouteInfo{
						{
							Namespace:   "default",
							ServiceName: "service-0",
							TargetNodes: []*omnimeshv1.NodeEndpointInfo{
								{
									NodeId:        "node-0",
									Addr:          "192.168.1.1:15008",
									TargetAddress: "10.0.0.1:8080",
								},
							},
						},
					},
				})
			}
		}(i)
	}

	// Wait for writers to complete, then signal readers to stop
	writerWg.Wait()
	close(stopCh)
	readerWg.Wait()
}

func TestRouter_NamespacesAndSubnets(t *testing.T) {
	router := proxy.NewRouter()

	if got := router.Subnets(); len(got) != 0 {
		t.Fatalf("expected empty subnets initially, got %v", got)
	}

	// 1. Initial snapshot with two namespaces
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{
				Name:    "ns-a",
				Subnets: []string{"10.10.12.0/24", "10.10.10.0/24"},
			},
			{
				Name: "ns-b",
				Cidr: "10.10.20.0/24", // Fallback to Cidr when Subnets is empty
			},
		},
	})

	want := []string{"10.10.10.0/24", "10.10.12.0/24", "10.10.20.0/24"}
	if got := router.Subnets(); !slices.Equal(got, want) {
		t.Fatalf("expected subnets %v, got %v", want, got)
	}
	if gotNs := router.Namespaces(); len(gotNs) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(gotNs))
	}

	// 2. Add a new namespace via ScopeUpdate (ADD)
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_ADD,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{
				Name:    "ns-c",
				Subnets: []string{"10.10.30.0/24", "10.10.10.0/24"}, // duplicate subnet across namespaces
			},
		},
	})

	want = []string{"10.10.10.0/24", "10.10.12.0/24", "10.10.20.0/24", "10.10.30.0/24"}
	if got := router.Subnets(); !slices.Equal(got, want) {
		t.Fatalf("expected subnets after ADD %v, got %v", want, got)
	}

	// 3. Modify namespace ns-a via ScopeUpdate (MODIFY)
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{
				Name:    "ns-a",
				Subnets: []string{"10.10.15.0/24"},
			},
		},
	})

	// 10.10.10.0/24 is still kept because ns-c owns it; 10.10.12.0/24 is replaced by 10.10.15.0/24
	want = []string{"10.10.10.0/24", "10.10.15.0/24", "10.10.20.0/24", "10.10.30.0/24"}
	if got := router.Subnets(); !slices.Equal(got, want) {
		t.Fatalf("expected subnets after MODIFY %v, got %v", want, got)
	}

	// 4. Remove namespace ns-c and ns-b via ScopeUpdate (REMOVE)
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-b"},
			{Name: "ns-c"},
		},
	})

	want = []string{"10.10.15.0/24"}
	if got := router.Subnets(); !slices.Equal(got, want) {
		t.Fatalf("expected subnets after REMOVE %v, got %v", want, got)
	}

	// 5. Remove last remaining namespace ns-a
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		Namespaces: []*omnimeshv1.NamespaceInfo{
			{Name: "ns-a"},
		},
	})

	if got := router.Subnets(); len(got) != 0 {
		t.Fatalf("expected empty subnets after removing all namespaces, got %v", got)
	}
}


