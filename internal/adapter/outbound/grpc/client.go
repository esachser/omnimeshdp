package grpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var _ outbound.ControlPlaneClient = (*Client)(nil)

// Client handles bidirectional gRPC communication with omnimeshcontrol.
type Client struct {
	addr              string
	tlsConfigProvider outbound.TLSConfigProvider
	conn              *grpc.ClientConn
	stream            omnimeshv1.AgentService_AgentStreamClient
	mu                sync.Mutex
}

// NewClient constructs a new control plane gRPC client.
func NewClient(addr string, tlsConfigProvider outbound.TLSConfigProvider) *Client {
	return &Client{
		addr:              addr,
		tlsConfigProvider: tlsConfigProvider,
	}
}

// Connect dials the control plane and establishes the bidirectional AgentStream.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Printf("Connecting to Control Plane at %s...\n", c.addr)

	var dialOpt grpc.DialOption
	targetAddr := c.addr

	if strings.HasPrefix(targetAddr, "https://") {
		targetAddr = strings.TrimPrefix(targetAddr, "https://")
		if c.tlsConfigProvider == nil {
			return fmt.Errorf("tlsConfigProvider is required for https connection")
		}
		tlsConfig, err := c.tlsConfigProvider.GetTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to get TLS config: %w", err)
		}
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	} else if strings.HasPrefix(targetAddr, "http://") {
		targetAddr = strings.TrimPrefix(targetAddr, "http://")
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		// Default to insecure for local development
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(targetAddr, dialOpt)
	if err != nil {
		return fmt.Errorf("failed to dial Control Plane (%s): %w", c.addr, err)
	}

	grpcClient := omnimeshv1.NewAgentServiceClient(conn)
	stream, err := grpcClient.AgentStream(ctx)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to establish AgentStream with Control Plane: %w", err)
	}

	c.conn = conn
	c.stream = stream
	log.Println("Bidirectional gRPC stream established with Control Plane.")
	return nil
}

// RegisterAndGetSnapshot sends node registration and waits for the initial ScopeSnapshot.
func (c *Client) RegisterAndGetSnapshot(ctx context.Context, reg *model.NodeRegistration) (*omnimeshv1.ScopeSnapshot, error) {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()

	if stream == nil {
		return nil, fmt.Errorf("stream is not connected")
	}

	services := make([]*omnimeshv1.NodeServiceInfo, len(reg.Services))
	for i, s := range reg.Services {
		services[i] = &omnimeshv1.NodeServiceInfo{
			Namespace: s.Namespace,
			Name:      s.Name,
			Id:        s.ID,
			Labels:    s.Labels,
		}
	}

	initReq := &omnimeshv1.AgentStreamRequest{
		Payload: &omnimeshv1.AgentStreamRequest_RegisterNode{
			RegisterNode: &omnimeshv1.RegisterNodeRequest{
				NodeId:   reg.NodeID,
				Platform: reg.Platform,
				Addr:     reg.Addr,
				Labels:   reg.Labels,
				Services: services,
				Target:   reg.Target,
			},
		},
	}

	if err := stream.Send(initReq); err != nil {
		return nil, fmt.Errorf("failed to send RegisterNode request: %w", err)
	}
	log.Println("Sent initial RegisterNode request to Control Plane.")

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive initial ScopeSnapshot: %w", err)
	}

	switch payload := resp.Payload.(type) {
	case *omnimeshv1.AgentStreamResponse_ScopeSnapshot:
		log.Printf("Initial ScopeSnapshot received with %d services, %d routes\n",
			len(payload.ScopeSnapshot.Services), len(payload.ScopeSnapshot.Routes))
		return payload.ScopeSnapshot, nil
	default:
		return nil, fmt.Errorf("unexpected initial message from Control Plane: %T", resp.Payload)
	}
}

// SendUpdateServices sends updated service definitions to the control plane.
func (c *Client) SendUpdateServices(ctx context.Context, services []model.NodeServiceInfo) error {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()

	if stream == nil {
		return fmt.Errorf("stream is not connected")
	}

	added := make([]*omnimeshv1.NodeServiceInfo, len(services))
	for i, s := range services {
		added[i] = &omnimeshv1.NodeServiceInfo{
			Namespace: s.Namespace,
			Name:      s.Name,
			Id:        s.ID,
			Labels:    s.Labels,
		}
	}

	req := &omnimeshv1.AgentStreamRequest{
		Payload: &omnimeshv1.AgentStreamRequest_UpdateNodeServices{
			UpdateNodeServices: &omnimeshv1.UpdateNodeServicesRequest{
				AddedServices: added,
			},
		},
	}

	if err := stream.Send(req); err != nil {
		return fmt.Errorf("failed to send UpdateNodeServices request: %w", err)
	}
	log.Printf("Sent UpdateNodeServices with %d services to Control Plane.\n", len(added))
	return nil
}

// StreamUpdates continuously consumes incoming ScopeUpdate messages until context completion.
func (c *Client) StreamUpdates(ctx context.Context, onUpdate func(*omnimeshv1.ScopeUpdate)) error {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()

	if stream == nil {
		return fmt.Errorf("stream is not connected")
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF || ctx.Err() != nil {
			log.Println("Control Plane stream closed.")
			return nil
		}
		if err != nil {
			log.Printf("Control Plane stream error: %v\n", err)
			return err
		}

		switch payload := resp.Payload.(type) {
		case *omnimeshv1.AgentStreamResponse_ScopeUpdate:
			if onUpdate != nil {
				onUpdate(payload.ScopeUpdate)
			}
		case *omnimeshv1.AgentStreamResponse_ScopeSnapshot:
			log.Printf("Received additional ScopeSnapshot with %d services, %d routes\n",
				len(payload.ScopeSnapshot.Services), len(payload.ScopeSnapshot.Routes))
		default:
			log.Printf("Received message from Control Plane: %v\n", resp)
		}
	}
}

// Run executes registration and streaming as a single combined workflow.
func (c *Client) Run(ctx context.Context, reg *model.NodeRegistration) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	defer c.Close()

	if _, err := c.RegisterAndGetSnapshot(ctx, reg); err != nil {
		return err
	}

	return c.StreamUpdates(ctx, nil)
}

// Close terminates the gRPC connection and stream.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.stream = nil
		return err
	}
	return nil
}
