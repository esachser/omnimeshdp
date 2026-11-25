package httpproxy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

const (
	MeshHeaderCallerIdentity = "x-omnimesh-caller-identity"
	MeshHeaderSourceNode     = "x-omnimesh-source-node"
	MeshHeaderDestNode       = "x-omnimesh-dest-node"
	MeshHeaderDestService    = "x-omnimesh-dest-service"
	MeshHeaderNodeServiceID  = "x-omnimesh-node-service-id"
	MeshHeaderForwardedFor   = "x-forwarded-for"
)

var _ outbound.HeaderInterceptor = (*MeshMetadataInterceptor)(nil)

// MeshMetadataInterceptor enforces trust boundaries on OmniMesh internal headers and stamps
// authoritative workload identity, node, and service metadata onto HTTP requests.
type MeshMetadataInterceptor struct {
	cfg                     model.MeshHeadersConfig
	allowUnverifiedIdentity bool
	stripPrefixLower        string
}

// NewMeshMetadataInterceptor constructs a MeshMetadataInterceptor.
func NewMeshMetadataInterceptor(cfg model.MeshHeadersConfig, allowUnverifiedIdentity bool) *MeshMetadataInterceptor {
	return &MeshMetadataInterceptor{
		cfg:                     cfg,
		allowUnverifiedIdentity: allowUnverifiedIdentity,
		stripPrefixLower:        strings.ToLower(cfg.StripPrefixOnInbound),
	}
}

// Name returns the interceptor identifier.
func (m *MeshMetadataInterceptor) Name() string {
	return "mesh-metadata"
}

// OnRequest sanitizes untrusted mesh headers and injects authoritative metadata.
func (m *MeshMetadataInterceptor) OnRequest(_ context.Context, conn *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	m.SanitizeRequest(conn, req)
	return m.InjectRequest(conn, req)
}

// OnResponse is a no-op for mesh metadata injection.
func (m *MeshMetadataInterceptor) OnResponse(_ context.Context, _ *model.ConnectionMeta, _ *model.HTTPRequestContext, _ *model.HTTPResponseContext) error {
	return nil
}

// SanitizeRequest strips untrusted OmniMesh headers according to the traffic direction's trust boundary.
func (m *MeshMetadataInterceptor) SanitizeRequest(conn *model.ConnectionMeta, req *model.HTTPRequestContext) {
	if conn == nil || req == nil || len(req.Headers) == 0 {
		return
	}

	switch conn.Direction {
	case model.DirectionInbound:
		if m.stripPrefixLower != "" {
			for k := range req.Headers {
				if strings.HasPrefix(strings.ToLower(k), m.stripPrefixLower) {
					delete(req.Headers, k)
				}
			}
		}
	case model.DirectionOutbound:
		if m.cfg.StripUntrustedOutbound {
			req.Headers.Del(MeshHeaderCallerIdentity)
			req.Headers.Del(MeshHeaderSourceNode)
			req.Headers.Del(MeshHeaderDestNode)
			req.Headers.Del(MeshHeaderDestService)
			req.Headers.Del(MeshHeaderNodeServiceID)
		}
	}
}

// InjectRequest stamps authoritative OmniMesh metadata headers onto req.Headers.
func (m *MeshMetadataInterceptor) InjectRequest(conn *model.ConnectionMeta, req *model.HTTPRequestContext) error {
	if conn == nil || req == nil {
		return nil
	}
	if req.Headers == nil {
		req.Headers = make(http.Header)
	}

	if m.cfg.InjectCallerIdentity && conn.CallerIdentity != "" {
		if conn.CallerVerified || m.allowUnverifiedIdentity {
			setSanitizedHeader(req.Headers, MeshHeaderCallerIdentity, conn.CallerIdentity)
		}
	}
	if m.cfg.InjectSourceNode && conn.SourceNodeID != "" {
		setSanitizedHeader(req.Headers, MeshHeaderSourceNode, conn.SourceNodeID)
	}
	if m.cfg.InjectDestNode && conn.DestNodeID != "" {
		setSanitizedHeader(req.Headers, MeshHeaderDestNode, conn.DestNodeID)
	}
	if m.cfg.InjectDestService {
		destService := formatDestService(conn.Namespace, conn.ServiceName)
		if destService != "" {
			setSanitizedHeader(req.Headers, MeshHeaderDestService, destService)
		}
	}
	if m.cfg.InjectNodeServiceID && conn.NodeServiceID != "" {
		setSanitizedHeader(req.Headers, MeshHeaderNodeServiceID, conn.NodeServiceID)
	}
	if m.cfg.InjectXForwardedFor {
		if clientIP := extractClientIP(conn.SourceAddr); clientIP != "" {
			prior := req.Headers.Values(MeshHeaderForwardedFor)
			if len(prior) > 0 {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			setSanitizedHeader(req.Headers, MeshHeaderForwardedFor, clientIP)
		}
	}
	return nil
}

func formatDestService(namespace, serviceName string) string {
	if namespace != "" && serviceName != "" {
		return namespace + "/" + serviceName
	}
	return serviceName
}

func extractClientIP(addr string) string {
	if addr == "" {
		return ""
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return parsed.String()
}

func setSanitizedHeader(h http.Header, name, value string) {
	sanitized := model.SanitizeHeaderValue(value)
	if sanitized != "" {
		h.Set(name, sanitized)
	}
}
