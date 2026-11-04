package spiffe

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var _ outbound.WorkloadSVIDProvider = (*DelegatedWorkloadProvider)(nil)

type cachedSVID struct {
	svid      *x509svid.SVID
	expiresAt time.Time
}

// DelegatedWorkloadProvider retrieves workload SVIDs and mTLS configs from the SPIRE Agent Delegated Identity API.
type DelegatedWorkloadProvider struct {
	conn         *grpc.ClientConn
	client       delegatedidentityv1.DelegatedIdentityClient
	bundleSource x509bundle.Source
	trustDomain  spiffeid.TrustDomain
	cache        map[uint64]*cachedSVID
	cacheMu      sync.RWMutex
}

// NewDelegatedWorkloadProvider connects to the SPIRE Agent Delegated Identity API endpoint.
func NewDelegatedWorkloadProvider(
	ctx context.Context,
	socketPath string,
	bundleSource x509bundle.Source,
	trustDomainStr string,
) (*DelegatedWorkloadProvider, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("spire delegated identity: socketPath is required")
	}

	address, dialer := getSpireDialer(socketPath)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if dialer != nil {
		opts = append(opts, grpc.WithContextDialer(dialer))
	}

	conn, err := grpc.NewClient(address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SPIRE delegated identity at %q: %w", socketPath, err)
	}

	var td spiffeid.TrustDomain
	if trustDomainStr != "" {
		parsedTD, err := spiffeid.TrustDomainFromString(trustDomainStr)
		if err == nil {
			td = parsedTD
		}
	}

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)

	return &DelegatedWorkloadProvider{
		conn:         conn,
		client:       client,
		bundleSource: bundleSource,
		trustDomain:  td,
		cache:        make(map[uint64]*cachedSVID),
	}, nil
}

// NewDelegatedWorkloadProviderWithClient creates a provider with a pre-configured client (useful for testing).
func NewDelegatedWorkloadProviderWithClient(
	client delegatedidentityv1.DelegatedIdentityClient,
	bundleSource x509bundle.Source,
	trustDomainStr string,
) *DelegatedWorkloadProvider {
	var td spiffeid.TrustDomain
	if trustDomainStr != "" {
		parsedTD, err := spiffeid.TrustDomainFromString(trustDomainStr)
		if err == nil {
			td = parsedTD
		}
	}

	return &DelegatedWorkloadProvider{
		client:       client,
		bundleSource: bundleSource,
		trustDomain:  td,
		cache:        make(map[uint64]*cachedSVID),
	}
}

// GetClientTLSConfigByPID queries the SPIRE Agent Delegated Identity API for the SVID corresponding to the PID,
// and returns a *tls.Config ready for mTLS client connection along with the SPIFFE ID string.
func (p *DelegatedWorkloadProvider) GetClientTLSConfigByPID(ctx context.Context, pid uint64) (*tls.Config, string, error) {
	if pid == 0 {
		return nil, "", fmt.Errorf("%w: invalid pid 0", domain.ErrSVIDNotFound)
	}

	now := time.Now()

	p.cacheMu.RLock()
	cached, ok := p.cache[pid]
	p.cacheMu.RUnlock()

	var svid *x509svid.SVID
	if ok && cached != nil && now.Before(cached.expiresAt) {
		svid = cached.svid
	}

	if svid == nil {
		if p.client == nil {
			return nil, "", fmt.Errorf("%w: client not initialized", domain.ErrDelegatedIdentityFailed)
		}

		streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		req := &delegatedidentityv1.SubscribeToX509SVIDsRequest{
			Pid: int32(pid),
		}

		stream, err := p.client.SubscribeToX509SVIDs(streamCtx, req)
		if err != nil {
			return nil, "", fmt.Errorf("%w: SubscribeToX509SVIDs failed for PID %d: %v", domain.ErrDelegatedIdentityFailed, pid, err)
		}

		resp, err := stream.Recv()
		if err != nil {
			return nil, "", fmt.Errorf("%w: failed to receive SVID stream for PID %d: %v", domain.ErrDelegatedIdentityFailed, pid, err)
		}

		svids := resp.GetX509Svids()
		if len(svids) == 0 || svids[0].GetX509Svid() == nil {
			return nil, "", fmt.Errorf("%w: no SVID returned by SPIRE for PID %d", domain.ErrSVIDNotFound, pid)
		}

		svidWithKey := svids[0]
		rawChain := svidWithKey.GetX509Svid().GetCertChain()
		if len(rawChain) == 0 {
			return nil, "", fmt.Errorf("%w: empty certificate chain for PID %d", domain.ErrSVIDNotFound, pid)
		}

		var certBytes []byte
		for _, c := range rawChain {
			certBytes = append(certBytes, c...)
		}

		parsedSVID, err := x509svid.ParseRaw(certBytes, svidWithKey.GetX509SvidKey())
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse SVID raw credentials for PID %d: %w", pid, err)
		}
		svid = parsedSVID

		expiresAt := time.Unix(svidWithKey.GetX509Svid().GetExpiresAt(), 0)
		cacheExpiry := expiresAt.Add(-30 * time.Second)
		if cacheExpiry.After(now) {
			p.cacheMu.Lock()
			p.cache[pid] = &cachedSVID{
				svid:      svid,
				expiresAt: cacheExpiry,
			}
			p.cacheMu.Unlock()
		}
	}

	var authorizer tlsconfig.Authorizer
	if !p.trustDomain.IsZero() {
		authorizer = tlsconfig.AuthorizeMemberOf(p.trustDomain)
	} else {
		authorizer = tlsconfig.AuthorizeAny()
	}

	var tlsConfig *tls.Config
	if p.bundleSource != nil {
		tlsConfig = tlsconfig.MTLSClientConfig(svid, p.bundleSource, authorizer)
	} else {
		tlsConfig = tlsconfig.TLSServerConfig(svid)
		tlsConfig.InsecureSkipVerify = true
	}

	tlsConfig.NextProtos = []string{"h2"}
	return tlsConfig, svid.ID.String(), nil
}

// Close closes the underlying gRPC client connection to the SPIRE Agent.
func (p *DelegatedWorkloadProvider) Close() error {
	p.cacheMu.Lock()
	p.cache = make(map[uint64]*cachedSVID)
	p.cacheMu.Unlock()

	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

