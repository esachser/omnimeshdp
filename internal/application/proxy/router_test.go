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


