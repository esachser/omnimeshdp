package orchestrator

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	adaptergrpc "github.com/esachser/omnimeshdp/internal/adapter/outbound/grpc"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/spiffe"
	"github.com/esachser/omnimeshdp/internal/application/agent"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

// PacketProcessorFactory creates a packet processor configured with the given subnets.
type PacketProcessorFactory func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error)

// TLSProviderFactory creates a SPIFFE TLS config provider.
type TLSProviderFactory func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error)

// ControlPlaneClientFactory creates a ControlPlaneClient for connecting to omnimeshcontrol.
type ControlPlaneClientFactory func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient

// ListenerOpener binds a network address to open a listener.
type ListenerOpener func(network, address string) (net.Listener, error)

// Option configures an Orchestrator.
type Option func(*Orchestrator)

// Orchestrator coordinates the startup and execution of OmnimeshDP according to spec/run-start.md.
type Orchestrator struct {
	configPath       string
	config           *model.AppConfig
	processorFactory PacketProcessorFactory
	tlsFactory       TLSProviderFactory
	cpClientFactory  ControlPlaneClientFactory
	listenerOpener   ListenerOpener

	// Internal state across steps
	tlsProvider        outbound.TLSConfigProvider
	tlsCloser          io.Closer
	internalListener   net.Listener
	externalListener   net.Listener
	clientSideService  *proxy.ClientSideService
	serverSideService  *proxy.ServerSideService
	controlPlaneClient outbound.ControlPlaneClient
	controlPlaneAgent  *agent.ControlPlaneAgent
	router             *proxy.Router
	packetProcessor    outbound.PacketProcessor
	servicesToDeploy   []model.NodeServiceInfo

	wg      sync.WaitGroup
	stopped bool
	mu      sync.Mutex
}

// WithConfigPath sets the path to the configuration file.
func WithConfigPath(path string) Option {
	return func(o *Orchestrator) {
		o.configPath = path
	}
}

// WithConfig sets the pre-loaded configuration.
func WithConfig(cfg *model.AppConfig) Option {
	return func(o *Orchestrator) {
		o.config = cfg
	}
}

// WithProcessorFactory configures custom packet processor creation.
func WithProcessorFactory(fn PacketProcessorFactory) Option {
	return func(o *Orchestrator) {
		o.processorFactory = fn
	}
}

// WithTLSFactory configures custom SPIFFE/TLS provider creation.
func WithTLSFactory(fn TLSProviderFactory) Option {
	return func(o *Orchestrator) {
		o.tlsFactory = fn
	}
}

// WithControlPlaneClientFactory configures custom ControlPlaneClient creation.
func WithControlPlaneClientFactory(fn ControlPlaneClientFactory) Option {
	return func(o *Orchestrator) {
		o.cpClientFactory = fn
	}
}

// WithListenerOpener configures custom listener opening.
func WithListenerOpener(fn ListenerOpener) Option {
	return func(o *Orchestrator) {
		o.listenerOpener = fn
	}
}

// NewOrchestrator creates a new Orchestrator with default factories and options.
func NewOrchestrator(opts ...Option) *Orchestrator {
	o := &Orchestrator{
		tlsFactory: func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error) {
			provider, err := spiffe.NewSpiffeTLSProvider(ctx, socketPath, serverSVID)
			if err != nil {
				return nil, nil, err
			}
			return provider, provider, nil
		},
		cpClientFactory: func(addr string, tlsProvider outbound.TLSConfigProvider) outbound.ControlPlaneClient {
			return adaptergrpc.NewClient(addr, tlsProvider)
		},
		listenerOpener: func(network, address string) (net.Listener, error) {
			return net.Listen(network, address)
		},
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// Run executes the 10-step sequence specified in spec/run-start.md.
// It fails fast and returns an error if any step fails.
func (o *Orchestrator) Run(ctx context.Context) error {
	defer o.Cleanup()

	// Step 1: Read configuration from file or env.
	log.Println("[Step 1/10] Reading configuration from file or env...")
	if o.config == nil {
		cfg, err := model.LoadConfig(o.configPath)
		if err != nil {
			return fmt.Errorf("%w: %v", domain.ErrConfigLoadFailed, err)
		}
		o.config = cfg
	}
	log.Printf("[Step 1/10] Configuration loaded successfully. Node ID: %s, Interception: %s\n",
		o.config.ControlPlane.NodeID, o.config.Interception.Type)

	// Step 2: Connect to the Spire Agent to get a mTLS configuration.
	log.Println("[Step 2/10] Connecting to Spire Agent to get mTLS configuration...")
	if o.config.Spire.Disabled {
		log.Println("[Step 2/10] Spire mTLS disabled by configuration.")
	} else {
		if o.tlsFactory == nil {
			return fmt.Errorf("%w: TLS factory not configured", domain.ErrSpireConnectionFailed)
		}
		provider, closer, err := o.tlsFactory(ctx, o.config.Spire.SocketPath, o.config.Spire.ServerSVID)
		if err != nil {
			return fmt.Errorf("%w: %v", domain.ErrSpireConnectionFailed, err)
		}
		o.tlsProvider = provider
		o.tlsCloser = closer
		log.Println("[Step 2/10] Successfully obtained mTLS configuration from Spire Agent.")
	}

	// Step 3: Open the internal and external ports to listen for incoming connections.
	// - The next step must only run after this one succeeds.
	log.Println("[Step 3/10] Opening internal and external ports...")
	intLn, err := o.listenerOpener("tcp", o.config.Listeners.InternalAddr)
	if err != nil {
		return fmt.Errorf("%w: failed to open internal port %s: %v", domain.ErrPortBindFailed, o.config.Listeners.InternalAddr, err)
	}
	o.internalListener = intLn

	extLn, err := o.listenerOpener("tcp", o.config.Listeners.ExternalAddr)
	if err != nil {
		_ = intLn.Close()
		return fmt.Errorf("%w: failed to open external port %s: %v", domain.ErrPortBindFailed, o.config.Listeners.ExternalAddr, err)
	}
	o.externalListener = extLn

	log.Printf("[Step 3/10] Ports successfully opened: internal=%s, external=%s\n",
		intLn.Addr().String(), extLn.Addr().String())

	// Hand off listeners to proxy services
	o.router = proxy.NewRouter()
	o.clientSideService = proxy.NewClientSideService(o.config.Listeners.InternalAddr, "", nil)
	o.clientSideService.SetRouter(o.router)
	o.serverSideService = proxy.NewServerSideService(o.config.Listeners.ExternalAddr)

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		_ = o.clientSideService.Serve(ctx, o.internalListener)
	}()

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		_ = o.serverSideService.Serve(ctx, o.externalListener)
	}()

	// Step 4: Connect to the Control Plane using the mTLS configuration from step 2.
	log.Println("[Step 4/10] Connecting to Control Plane using mTLS configuration...")
	cpClient := o.cpClientFactory(o.config.ControlPlane.Address, o.tlsProvider)
	o.controlPlaneClient = cpClient
	o.controlPlaneAgent = agent.NewControlPlaneAgentWithConfig(
		cpClient,
		o.config.ControlPlane.NodeID,
		o.config.ControlPlane.Target,
	)

	if err := o.controlPlaneAgent.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrControlPlaneConnectionFailed, err)
	}
	log.Println("[Step 4/10] Successfully connected to Control Plane.")

	// Step 5: Receive the inicial ScopeSnapshot and prepare routing config.
	log.Println("[Step 5/10] Receiving initial ScopeSnapshot and preparing routing config...")
	snapshot, err := o.controlPlaneAgent.RegisterAndGetSnapshot(ctx, o.config.Listeners.ExternalAddr, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrInitialScopeSnapshotFailed, err)
	}
	o.router.ApplySnapshot(snapshot)
	log.Printf("[Step 5/10] ScopeSnapshot processed: %d services, %d routes.\n",
		len(snapshot.Services), len(snapshot.Routes))

	// Step 6: Read namespace subnets from the configuration file.
	log.Println("[Step 6/10] Reading namespace subnets from configuration file...")
	subnets := o.config.Interception.Subnets
	if len(subnets) == 0 {
		return fmt.Errorf("%w: no subnets specified in configuration", domain.ErrSubnetsConfigFailed)
	}
	log.Printf("[Step 6/10] Loaded %d namespace subnets: %v\n", len(subnets), subnets)

	// Step 7: Use packet processsor to configure packet filtering.
	log.Println("[Step 7/10] Using packet processor to configure packet filtering...")
	_, portStr, err := net.SplitHostPort(o.config.Listeners.InternalAddr)
	var internalPort uint16 = 15001
	if err == nil {
		if p, err := strconv.ParseUint(portStr, 10, 16); err == nil {
			internalPort = uint16(p)
		}
	}

	if o.processorFactory == nil {
		return fmt.Errorf("%w: processor factory not configured", domain.ErrPacketProcessorInitFailed)
	}
	processor, err := o.processorFactory(o.config.Interception.Type, subnets, internalPort)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrPacketProcessorInitFailed, err)
	}
	o.packetProcessor = processor
	o.clientSideService.SetPacketProcessor(processor)

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		if err := processor.Run(ctx); err != nil {
			log.Printf("Packet processor stopped: %v\n", err)
		}
	}()
	log.Println("[Step 7/10] Packet filtering configured and processor running.")

	// Step 8: Read from config and files what services to deploy.
	log.Println("[Step 8/10] Reading from config and files what services to deploy...")
	o.servicesToDeploy = o.config.Services
	log.Printf("[Step 8/10] Loaded %d services to deploy from config/files.\n", len(o.servicesToDeploy))

	// Step 9: Send and receive updates to/from Control Plane and update routing config and packet filtering.
	// - This should run until the application is stopped.
	log.Println("[Step 9/10] Sending and receiving updates to/from Control Plane...")
	if len(o.servicesToDeploy) > 0 {
		if err := o.controlPlaneAgent.SendDeployedServices(ctx, o.servicesToDeploy); err != nil {
			log.Printf("Warning: failed to send deployed services to Control Plane: %v\n", err)
		}
	}

	streamErrCh := make(chan error, 1)
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		err := o.controlPlaneAgent.StreamUpdates(ctx, func(update *omnimeshv1.ScopeUpdate) {
			o.router.ApplyUpdate(update)
		})
		if err != nil && ctx.Err() == nil {
			streamErrCh <- err
		}
	}()

	log.Println("[Step 9/10] OmnimeshDP running and listening for updates. Ready to process traffic.")

	select {
	case <-ctx.Done():
		log.Println("Shutdown signal received.")
	case err := <-streamErrCh:
		log.Printf("Control Plane stream terminated with error: %v\n", err)
	}

	// Step 10: Clean up and exit.
	log.Println("[Step 10/10] Cleaning up and exiting...")
	return nil
}

// Cleanup terminates all opened listeners, connections, and packet processors.
func (o *Orchestrator) Cleanup() {
	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return
	}
	o.stopped = true
	o.mu.Unlock()

	if o.packetProcessor != nil {
		_ = o.packetProcessor.Close()
	}
	if o.internalListener != nil {
		_ = o.internalListener.Close()
	}
	if o.externalListener != nil {
		_ = o.externalListener.Close()
	}
	if o.controlPlaneAgent != nil {
		_ = o.controlPlaneAgent.Close()
	}
	if o.tlsCloser != nil {
		_ = o.tlsCloser.Close()
	}

	done := make(chan struct{})
	go func() {
		o.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Println("Cleanup timeout exceeded while waiting for background goroutines.")
	}
}
