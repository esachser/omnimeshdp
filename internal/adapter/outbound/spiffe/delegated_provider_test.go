package spiffe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/spiffe"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockDelegatedIdentityServer struct {
	delegatedidentityv1.UnimplementedDelegatedIdentityServer
	svidsByPID map[int32]*delegatedidentityv1.X509SVIDWithKey
	callCount  int
}

func (m *mockDelegatedIdentityServer) SubscribeToX509SVIDs(
	req *delegatedidentityv1.SubscribeToX509SVIDsRequest,
	stream grpc.ServerStreamingServer[delegatedidentityv1.SubscribeToX509SVIDsResponse],
) error {
	m.callCount++
	svid, ok := m.svidsByPID[req.Pid]
	if !ok {
		return status.Errorf(codes.NotFound, "no workload registered for PID %d", req.Pid)
	}

	return stream.Send(&delegatedidentityv1.SubscribeToX509SVIDsResponse{
		X509Svids: []*delegatedidentityv1.X509SVIDWithKey{svid},
	})
}

func generateTestSPIFFEWorkload(t *testing.T, spiffeIDStr string) (*x509.Certificate, *delegatedidentityv1.X509SVIDWithKey, *x509bundle.Bundle) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Omnimesh Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	spiffeURI, err := url.Parse(spiffeIDStr)
	if err != nil {
		t.Fatalf("invalid spiffe id: %v", err)
	}

	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate workload key: %v", err)
	}

	workloadTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Omnimesh Workload",
		},
		URIs:                  []*url.URL{spiffeURI},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	workloadDER, err := x509.CreateCertificate(rand.Reader, workloadTemplate, caCert, &workloadKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create workload certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(workloadKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
	bundle := x509bundle.New(td)
	bundle.AddX509Authority(caCert)

	svidWithKey := &delegatedidentityv1.X509SVIDWithKey{
		X509Svid: &spiretypes.X509SVID{
			CertChain: [][]byte{workloadDER},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Id: &spiretypes.SPIFFEID{
				TrustDomain: td.String(),
				Path:        spiffeURI.Path,
			},
		},
		X509SvidKey: keyDER,
	}

	return caCert, svidWithKey, bundle
}

func startMockSPIREServer(t *testing.T, srv delegatedidentityv1.DelegatedIdentityServer) (string, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	delegatedidentityv1.RegisterDelegatedIdentityServer(s, srv)

	go func() {
		_ = s.Serve(lis)
	}()

	cleanup := func() {
		s.Stop()
		_ = lis.Close()
	}

	return lis.Addr().String(), cleanup
}

func TestDelegatedWorkloadProvider_GetClientTLSConfigByPID(t *testing.T) {
	const testPID = uint64(12345)
	const expectedSPIFFEID = "spiffe://omnimesh.local/ns/production/sa/order-service"

	_, svidWithKey, bundle := generateTestSPIFFEWorkload(t, expectedSPIFFEID)

	mockServer := &mockDelegatedIdentityServer{
		svidsByPID: map[int32]*delegatedidentityv1.X509SVIDWithKey{
			int32(testPID): svidWithKey,
		},
	}

	addr, cleanup := startMockSPIREServer(t, mockServer)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider, err := spiffe.NewDelegatedWorkloadProvider(ctx, "tcp://"+addr, bundle, "omnimesh.local")
	if err != nil {
		t.Fatalf("NewDelegatedWorkloadProvider failed: %v", err)
	}
	defer provider.Close()

	// First query: should hit the mock server
	tlsConfig, spiffeID, err := provider.GetClientTLSConfigByPID(ctx, testPID)
	if err != nil {
		t.Fatalf("GetClientTLSConfigByPID failed: %v", err)
	}

	if spiffeID != expectedSPIFFEID {
		t.Errorf("expected SPIFFE ID %q, got %q", expectedSPIFFEID, spiffeID)
	}

	if tlsConfig == nil {
		t.Fatal("expected non-nil *tls.Config")
	}

	if len(tlsConfig.NextProtos) == 0 || tlsConfig.NextProtos[0] != "h2" {
		t.Errorf("expected NextProtos to include 'h2', got %v", tlsConfig.NextProtos)
	}

	if mockServer.callCount != 1 {
		t.Errorf("expected 1 call to mock server, got %d", mockServer.callCount)
	}

	// Second query for same PID: should use cache
	cachedTLS, cachedID, err := provider.GetClientTLSConfigByPID(ctx, testPID)
	if err != nil {
		t.Fatalf("second GetClientTLSConfigByPID failed: %v", err)
	}
	if cachedID != expectedSPIFFEID {
		t.Errorf("expected cached SPIFFE ID %q, got %q", expectedSPIFFEID, cachedID)
	}
	if cachedTLS == nil {
		t.Fatal("expected non-nil cached *tls.Config")
	}
	if mockServer.callCount != 1 {
		t.Errorf("expected call count to remain 1 due to cache, got %d", mockServer.callCount)
	}
}

func TestDelegatedWorkloadProvider_UnknownPID(t *testing.T) {
	mockServer := &mockDelegatedIdentityServer{
		svidsByPID: make(map[int32]*delegatedidentityv1.X509SVIDWithKey),
	}

	addr, cleanup := startMockSPIREServer(t, mockServer)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
	bundle := x509bundle.New(td)

	provider, err := spiffe.NewDelegatedWorkloadProvider(ctx, "tcp://"+addr, bundle, "omnimesh.local")
	if err != nil {
		t.Fatalf("NewDelegatedWorkloadProvider failed: %v", err)
	}
	defer provider.Close()

	// Query for PID that does not exist in SPIRE
	_, _, err = provider.GetClientTLSConfigByPID(ctx, 99999)
	if err == nil {
		t.Fatal("expected error for unknown PID, got nil")
	}
	if !errors.Is(err, domain.ErrDelegatedIdentityFailed) && !errors.Is(err, domain.ErrSVIDNotFound) {
		t.Errorf("expected ErrDelegatedIdentityFailed or ErrSVIDNotFound, got: %v", err)
	}
}

func TestDelegatedWorkloadProvider_ZeroPID(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("omnimesh.local")
	bundle := x509bundle.New(td)

	provider := spiffe.NewDelegatedWorkloadProviderWithClient(nil, bundle, "omnimesh.local")
	defer provider.Close()

	_, _, err := provider.GetClientTLSConfigByPID(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error for PID 0, got nil")
	}
	if !errors.Is(err, domain.ErrSVIDNotFound) {
		t.Errorf("expected ErrSVIDNotFound, got: %v", err)
	}
}

