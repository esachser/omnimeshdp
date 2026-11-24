package proxy_test

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
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
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "payment-rr",
				Namespace:              "production",
				TargetServiceNamespace: "production",
				TargetServiceName:      "payment-service",
				LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
					Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_WEIGHTED_ROUND_ROBIN,
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

func TestRouter_DefaultSelectionIsRandomNotRoundRobin(t *testing.T) {
	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "svc-rand", MeshAddr: "10.10.30.1", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "svc-rand",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "node-1", RouteName: "ep-1", Addr: "192.168.1.1:15008"},
					{NodeId: "node-2", RouteName: "ep-2", Addr: "192.168.1.2:15008"},
					{NodeId: "node-3", RouteName: "ep-3", Addr: "192.168.1.3:15008"},
					{NodeId: "node-4", RouteName: "ep-4", Addr: "192.168.1.4:15008"},
				},
			},
		},
	})

	const trials = 2000
	counts := make(map[string]int, 4)
	seq := make([]string, 0, trials)
	for i := 0; i < trials; i++ {
		r := router.ResolveRoute("10.10.30.1", 8080, "")
		if r == nil {
			t.Fatalf("unexpected nil route on trial %d", i)
		}
		counts[r.TargetHost]++
		seq = append(seq, r.TargetHost)
	}

	// Each of 4 endpoints should receive roughly 500 hits (allow generous statistical bounds [350, 650]).
	for _, host := range []string{"192.168.1.1:15008", "192.168.1.2:15008", "192.168.1.3:15008", "192.168.1.4:15008"} {
		if counts[host] < 350 || counts[host] > 650 {
			t.Fatalf("expected roughly uniform random distribution for %s (~500), got %d", host, counts[host])
		}
	}

	// Verify it is NOT strictly deterministic round-robin cycling (ep[i%4] repeating).
	strictCycle := true
	for i := 4; i < len(seq); i++ {
		if seq[i] != seq[i-4] {
			strictCycle = false
			break
		}
	}
	if strictCycle {
		t.Fatalf("selection followed a strict deterministic round-robin cycle instead of random")
	}
}

func TestRouter_TrafficPolicyWeightedSplitAndRemoval(t *testing.T) {
	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "checkout", MeshAddr: "10.10.40.1", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "checkout",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "n1", RouteName: "v1-a", Addr: "10.0.1.1:15008", Target: "cluster-a", Labels: map[string]string{"version": "v1"}},
					{NodeId: "n2", RouteName: "v1-b", Addr: "10.0.1.2:15008", Target: "cluster-a", Labels: map[string]string{"version": "v1"}},
					{NodeId: "n3", RouteName: "v2-a", Addr: "10.0.2.1:15008", Target: "cluster-b", Labels: map[string]string{"version": "v2"}},
					{NodeId: "n4", RouteName: "v3-unrouted", Addr: "10.0.3.1:15008", Target: "cluster-c", Labels: map[string]string{"version": "v3"}},
				},
			},
		},
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "canary-80-20",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "checkout",
				Routes: []*omnimeshv1.TrafficRouteInfo{
					{
						Weight: 80,
						Destination: &omnimeshv1.TrafficRouteDestinationInfo{
							Target: "cluster-a",
							Labels: map[string]string{"version": "v1"},
						},
					},
					{
						Weight: 20,
						Destination: &omnimeshv1.TrafficRouteDestinationInfo{
							Labels: map[string]string{"version": "v2"},
						},
					},
				},
			},
		},
	})

	const trials = 4000
	v1Hits, v2Hits, v3Hits := 0, 0, 0
	for i := 0; i < trials; i++ {
		r := router.ResolveRoute("10.10.40.1", 8080, "")
		if r == nil {
			t.Fatalf("unexpected nil route")
		}
		switch r.ServiceID {
		case "v1-a", "v1-b":
			v1Hits++
		case "v2-a":
			v2Hits++
		case "v3-unrouted":
			v3Hits++
		default:
			t.Fatalf("unexpected ServiceID %q", r.ServiceID)
		}
	}

	if v3Hits != 0 {
		t.Fatalf("expected 0 hits for unpermitted v3 endpoint, got %d", v3Hits)
	}
	v1Ratio := float64(v1Hits) / trials
	if v1Ratio < 0.75 || v1Ratio > 0.85 {
		t.Fatalf("expected ~0.80 v1 traffic share, got %.3f (v1=%d, v2=%d)", v1Ratio, v1Hits, v2Hits)
	}

	// Remove the TrafficPolicy via ScopeUpdate(REMOVE) -> reverts to uniform random across all 4 endpoints (including v3).
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_REMOVE,
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{Name: "canary-80-20", Namespace: "prod"},
		},
	})

	v3Hits = 0
	for i := 0; i < 400; i++ {
		r := router.ResolveRoute("10.10.40.1", 8080, "")
		if r != nil && r.ServiceID == "v3-unrouted" {
			v3Hits++
		}
	}
	if v3Hits == 0 {
		t.Fatalf("expected v3 endpoint to become eligible after removing TrafficPolicy")
	}
}

func TestRouter_TrafficPolicyNoMatchingEndpointsAndPrecedence(t *testing.T) {
	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "api", MeshAddr: "10.10.50.1", Port: 80},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "api",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "n1", RouteName: "v1", Addr: "10.0.1.1:15008", Labels: map[string]string{"version": "v1"}},
					{NodeId: "n2", RouteName: "v2", Addr: "10.0.1.2:15008", Labels: map[string]string{"version": "v2"}},
				},
			},
		},
		// Two conflicting policies: "alpha" precedes "zeta" lexicographically.
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "zeta",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "api",
				Routes: []*omnimeshv1.TrafficRouteInfo{
					{Weight: 100, Destination: &omnimeshv1.TrafficRouteDestinationInfo{Labels: map[string]string{"version": "v2"}}},
				},
			},
			{
				Name:                   "alpha",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "api",
				Routes: []*omnimeshv1.TrafficRouteInfo{
					{Weight: 100, Destination: &omnimeshv1.TrafficRouteDestinationInfo{Labels: map[string]string{"version": "v1"}}},
				},
			},
		},
	})

	for i := 0; i < 10; i++ {
		r, _, err := router.ResolveRouteWithExclusions("10.10.50.1", 80, "fallback:15008", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.ServiceID != "v1" {
			t.Fatalf("expected lexicographically first policy 'alpha' to pick v1, got %q", r.ServiceID)
		}
	}

	// Update "alpha" to match non-existent label version=v9 -> must return ErrNoMatchingEndpoints and NOT fall back.
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "alpha",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "api",
				Routes: []*omnimeshv1.TrafficRouteInfo{
					{Weight: 100, Destination: &omnimeshv1.TrafficRouteDestinationInfo{Labels: map[string]string{"version": "v9"}}},
				},
			},
		},
	})

	r, _, err := router.ResolveRouteWithExclusions("10.10.50.1", 80, "fallback:15008", nil)
	if !errors.Is(err, domain.ErrNoMatchingEndpoints) || r != nil {
		t.Fatalf("expected ErrNoMatchingEndpoints and nil route, got route=%v err=%v", r, err)
	}
	if legacy := router.ResolveRoute("10.10.50.1", 80, "fallback:15008"); legacy != nil {
		t.Fatalf("expected legacy ResolveRoute to return nil (not bypass policy) when no endpoints match, got %v", legacy)
	}
}

func TestRouter_HealthFilteringAndExclusions(t *testing.T) {
	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "catalog", MeshAddr: "10.10.60.1", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "catalog",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "n1", RouteName: "ep-healthy", Addr: "10.0.0.1:15008"},
					{NodeId: "n2", RouteName: "ep-unhealthy", Addr: "10.0.0.2:15008"},
					{NodeId: "n3", RouteName: "ep-draining", Addr: "10.0.0.3:15008"},
					{NodeId: "n4", RouteName: "ep-unspecified", Addr: "10.0.0.4:15008"},
				},
			},
		},
		EndpointHealth: []*omnimeshv1.EndpointHealthInfo{
			{Namespace: "default", ServiceName: "catalog", NodeId: "n1", RouteName: "ep-healthy", Status: omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_HEALTHY},
			{Namespace: "default", ServiceName: "catalog", NodeId: "n2", RouteName: "ep-unhealthy", Status: omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY},
			{Namespace: "default", ServiceName: "catalog", NodeId: "n3", RouteName: "ep-draining", Status: omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_DRAINING},
		},
	})

	// Only n1 and n4 are eligible; n2 and n3 must never be chosen.
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		r := router.ResolveRoute("10.10.60.1", 8080, "")
		if r == nil {
			t.Fatalf("expected healthy route, got nil")
		}
		if r.ServiceID == "ep-unhealthy" || r.ServiceID == "ep-draining" {
			t.Fatalf("selected unhealthy/draining endpoint %q", r.ServiceID)
		}
		seen[r.ServiceID] = true
	}
	if !seen["ep-healthy"] || !seen["ep-unspecified"] {
		t.Fatalf("expected both HEALTHY and UNSPECIFIED endpoints to be selected, got %v", seen)
	}

	// Exclude n1 -> must always pick n4
	excluded := []model.EndpointKey{{NodeID: "n1", RouteName: "ep-healthy", Addr: "10.0.0.1:15008"}}
	for i := 0; i < 20; i++ {
		r, _, err := router.ResolveRouteWithExclusions("10.10.60.1", 8080, "", excluded)
		if err != nil || r.ServiceID != "ep-unspecified" {
			t.Fatalf("expected ep-unspecified when n1 excluded, got r=%v err=%v", r, err)
		}
	}

	// Exclude both n1 and n4 -> ErrNoAvailableEndpoints
	excluded = append(excluded, model.EndpointKey{NodeID: "n4", RouteName: "ep-unspecified", Addr: "10.0.0.4:15008"})
	if _, _, err := router.ResolveRouteWithExclusions("10.10.60.1", 8080, "", excluded); !errors.Is(err, domain.ErrNoAvailableEndpoints) {
		t.Fatalf("expected ErrNoAvailableEndpoints, got %v", err)
	}

	// Mark n1 and n4 unhealthy -> ErrNoHealthyEndpoints (no fallback to defaultTargetHost)
	router.ApplyUpdate(&omnimeshv1.ScopeUpdate{
		Type: omnimeshv1.ScopeUpdateType_SCOPE_UPDATE_TYPE_MODIFY,
		EndpointHealth: []*omnimeshv1.EndpointHealthInfo{
			{Namespace: "default", ServiceName: "catalog", NodeId: "n1", RouteName: "ep-healthy", Status: omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY},
			{Namespace: "default", ServiceName: "catalog", NodeId: "n4", RouteName: "ep-unspecified", Status: omnimeshv1.EndpointHealthStatus_ENDPOINT_HEALTH_STATUS_UNHEALTHY},
		},
	})
	if _, _, err := router.ResolveRouteWithExclusions("10.10.60.1", 8080, "fallback:15008", nil); !errors.Is(err, domain.ErrNoHealthyEndpoints) {
		t.Fatalf("expected ErrNoHealthyEndpoints, got %v", err)
	}
}

func TestRouter_LeastConnections(t *testing.T) {
	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "db", MeshAddr: "10.10.70.1", Port: 5432},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "default",
				ServiceName: "db",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "n1", RouteName: "db-1", Addr: "10.0.0.1:15008"},
					{NodeId: "n2", RouteName: "db-2", Addr: "10.0.0.2:15008"},
					{NodeId: "n3", RouteName: "db-3", Addr: "10.0.0.3:15008"},
				},
			},
		},
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "db-lc",
				Namespace:              "default",
				TargetServiceNamespace: "default",
				TargetServiceName:      "db",
				LoadBalancer: &omnimeshv1.LoadBalancerPolicyInfo{
					Algorithm: omnimeshv1.LoadBalancerAlgorithm_LOAD_BALANCER_ALGORITHM_LEAST_CONNECTIONS,
				},
			},
		},
	})

	rel1 := router.AcquireEndpoint(model.EndpointKey{NodeID: "n1", RouteName: "db-1", Addr: "10.0.0.1:15008"})
	rel2 := router.AcquireEndpoint(model.EndpointKey{NodeID: "n2", RouteName: "db-2", Addr: "10.0.0.2:15008"})
	defer rel1()
	defer rel2()

	// n3 has 0 active connections while n1 and n2 have 1 each -> must always choose n3.
	for i := 0; i < 20; i++ {
		r := router.ResolveRoute("10.10.70.1", 5432, "")
		if r == nil || r.ServiceID != "db-3" {
			t.Fatalf("expected db-3 with 0 active connections, got %v", r)
		}
	}
}

func BenchmarkResolveRouteIPv4_Random(b *testing.B) {
	router := proxy.NewRouter()
	nodes := make([]*omnimeshv1.NodeEndpointInfo, 10)
	for i := range nodes {
		nodes[i] = &omnimeshv1.NodeEndpointInfo{
			NodeId:    fmt.Sprintf("node-%d", i),
			RouteName: fmt.Sprintf("svc-%d", i),
			Addr:      fmt.Sprintf("192.168.1.%d:15008", i+1),
		}
	}
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "default", Name: "bench-svc", MeshAddr: "10.10.10.50", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{Namespace: "default", ServiceName: "bench-svc", TargetNodes: nodes},
		},
	})

	const destIP = uint32(10<<24 | 10<<16 | 10<<8 | 50)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r, _, err := router.ResolveRouteIPv4(destIP, 8080, "", nil)
			if err != nil || r == nil {
				b.Fatalf("unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkResolveRouteIPv4_WeightedTrafficRules(b *testing.B) {
	router := proxy.NewRouter()
	router.ApplySnapshot(&omnimeshv1.ScopeSnapshot{
		Services: []*omnimeshv1.ServiceInfo{
			{Namespace: "prod", Name: "bench-policy", MeshAddr: "10.10.10.51", Port: 8080},
		},
		Routes: []*omnimeshv1.RouteInfo{
			{
				Namespace:   "prod",
				ServiceName: "bench-policy",
				TargetNodes: []*omnimeshv1.NodeEndpointInfo{
					{NodeId: "n1", RouteName: "v1-1", Addr: "10.0.1.1:15008", Labels: map[string]string{"version": "v1"}},
					{NodeId: "n2", RouteName: "v1-2", Addr: "10.0.1.2:15008", Labels: map[string]string{"version": "v1"}},
					{NodeId: "n3", RouteName: "v2-1", Addr: "10.0.2.1:15008", Labels: map[string]string{"version": "v2"}},
				},
			},
		},
		TrafficPolicies: []*omnimeshv1.TrafficPolicyInfo{
			{
				Name:                   "split",
				Namespace:              "prod",
				TargetServiceNamespace: "prod",
				TargetServiceName:      "bench-policy",
				Routes: []*omnimeshv1.TrafficRouteInfo{
					{Weight: 80, Destination: &omnimeshv1.TrafficRouteDestinationInfo{Labels: map[string]string{"version": "v1"}}},
					{Weight: 20, Destination: &omnimeshv1.TrafficRouteDestinationInfo{Labels: map[string]string{"version": "v2"}}},
				},
			},
		},
	})

	const destIP = uint32(10<<24 | 10<<16 | 10<<8 | 51)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r, _, err := router.ResolveRouteIPv4(destIP, 8080, "", nil)
			if err != nil || r == nil {
				b.Fatalf("unexpected error: %v", err)
			}
		}
	})
}


