package grpc

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"strings"

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
}

// NewClient constructs a new control plane gRPC client.
func NewClient(addr string, tlsConfigProvider outbound.TLSConfigProvider) *Client {
	return &Client{
		addr:              addr,
		tlsConfigProvider: tlsConfigProvider,
	}
}

// Run dials the control plane, initiates the agent stream, sends registration, and consumes incoming updates.
func (c *Client) Run(ctx context.Context, reg *model.NodeRegistration) error {
	log.Printf("Connecting to Control Plane at %s...\n", c.addr)

	var dialOpt grpc.DialOption
	targetAddr := c.addr
	var tlsConfig *tls.Config
	var err error

	if strings.HasPrefix(targetAddr, "https://") {
		targetAddr = strings.TrimPrefix(targetAddr, "https://")
		tlsConfig, err = c.tlsConfigProvider.GetTLSConfig()
		if err != nil {
			return err
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
		log.Printf("Warning: failed to dial Control Plane (%s): %v\n", c.addr, err)
		return err
	}
	defer conn.Close()

	grpcClient := omnimeshv1.NewAgentServiceClient(conn)

	stream, err := grpcClient.AgentStream(ctx)
	if err != nil {
		log.Printf("Warning: failed to establish AgentStream with Control Plane: %v ", err)
		return err
	}

	log.Println("Bidirectional gRPC stream established with Control Plane.")

	// Construct and send initial registration request
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
		return err
	}

	log.Println("Sent initial RegisterNode request to Control Plane.")

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
		case *omnimeshv1.AgentStreamResponse_ScopeSnapshot:
			snapshot := payload.ScopeSnapshot
			log.Printf("ScopeSnapshot received with %d services, %d routes\n",
				len(snapshot.Services), len(snapshot.Routes))
		case *omnimeshv1.AgentStreamResponse_ScopeUpdate:
			update := payload.ScopeUpdate
			log.Printf("ScopeUpdate received: type %v\n", update.Type)
		default:
			log.Printf("Received message from Control Plane: %v\n", resp)
		}
	}
}
