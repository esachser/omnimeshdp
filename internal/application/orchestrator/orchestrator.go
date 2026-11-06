package orchestrator

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	adaptergrpc "github.com/esachser/omnimeshdp/internal/adapter/outbound/grpc"
	"github.com/esachser/omnimeshdp/internal/adapter/outbound/spiffe"
	"github.com/esachser/omnimeshdp/internal/application/agent"
	"github.com/esachser/omnimeshdp/internal/application/proxy"
	"github.com/esachser/omnimeshdp/internal/application/service"
	"github.com/esachser/omnimeshdp/internal/domain"
	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
)

// PacketProcessorFactory creates a packet processor configured with the given subnets.
type PacketProcessorFactory func(interceptionType string, subnets []string, internalPort uint16) (outbound.PacketProcessor, error)

// TLSProviderFactory creates a SPIFFE TLS config provider.
type TLSProviderFactory func(ctx context.Context, socketPath, serverSVID string) (outbound.TLSConfigProvider, io.Closer, error)

// WorkloadSVIDProviderFactory creates a WorkloadSVIDProvider for fetching SVIDs by calling process PID.
type WorkloadSVIDProviderFactory func(ctx context.Context, socketPath string, bundleSource x509bundle.Source, trustDomain string) (outbound.WorkloadSVIDProvider, io.Closer, error)

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
	svidFactory      WorkloadSVIDProviderFactory
	cpClientFactory  ControlPlaneClientFactory
	listenerOpener   ListenerOpener
	retryInterval    time.Duration

	// Internal state across steps
	runCtx             context.Context
	internalPort       uint16
	tlsProvider        outbound.TLSConfigProvider
	tlsCloser          io.Closer
	svidProvider       outbound.WorkloadSVIDProvider
	svidCloser         io.Closer
	internalListener   net.Listener
	externalListener   net.Listener
	clientSideService  *proxy.ClientSideService
	serverSideService  *proxy.ServerSideService
	controlPlaneClient outbound.ControlPlaneClient
	controlPlaneAgent  *agent.ControlPlaneAgent
	router             *proxy.Router
	packetProcessor    outbound.PacketProcessor
	processorCancel    context.CancelFunc
	processorDone      chan struct{}
	currentSubnets     []string
	servicesToDeploy   []model.NodeServiceInfo
	serviceManager     *service.Manager

	processorMu sync.Mutex
	wg          sync.WaitGroup
	stopped     bool
	mu          sync.Mutex
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

// WithWorkloadSVIDProviderFactory configures custom WorkloadSVIDProvider creation.
func WithWorkloadSVIDProviderFactory(fn WorkloadSVIDProviderFactory) Option {
	return func(o *Orchestrator) {
		o.svidFactory = fn
	}
}

// WithWorkloadSVIDProvider configures a pre-instantiated WorkloadSVIDProvider.
func WithWorkloadSVIDProvider(provider outbound.WorkloadSVIDProvider) Option {
	return func(o *Orchestrator) {
		o.svidProvider = provider
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

// WithRetryInterval sets the backoff duration for control plane reconnection.
func WithRetryInterval(interval time.Duration) Option {
	return func(o *Orchestrator) {
		o.retryInterval = interval
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
		svidFactory: func(ctx context.Context, socketPath string, bundleSource x509bundle.Source, trustDomain string) (outbound.WorkloadSVIDProvider, io.Closer, error) {
			provider, err := spiffe.NewDelegatedWorkloadProvider(ctx, socketPath, bundleSource, trustDomain)
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

	o.mu.Lock()
	o.runCtx = ctx
	o.mu.Unlock()

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

		// Initialize Delegated Workload SVID Provider for impersonating calling services
		if o.svidProvider == nil && o.svidFactory != nil {
			adminSocket := o.config.Spire.AdminSocketPath
			if adminSocket == "" {
				adminSocket = o.config.Spire.SocketPath
			}
			trustDomain := o.config.Spire.TrustDomain
			var bundleSource x509bundle.Source
			if sp, ok := provider.(*spiffe.SpiffeTLSProvider); ok {
				bundleSource = sp.Source()
				if trustDomain == "" {
					trustDomain = sp.ServerSVID().TrustDomain().String()
				}
			}
			svidProv, svidCloser, err := o.svidFactory(ctx, adminSocket, bundleSource, trustDomain)
			if err != nil {
				log.Printf("[Step 2/10] Warning: failed to connect to SPIRE Delegated Identity API: %v\n", err)
			} else {
				o.svidProvider = svidProv
				o.svidCloser = svidCloser
				log.Println("[Step 2/10] Successfully initialized Delegated Workload SVID Provider.")
			}
		}
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
	o.router = proxy.NewRouterWithNode(o.config.ControlPlane.NodeID, o.config.ControlPlane.Target)
	o.clientSideService = proxy.NewClientSideService(o.config.Listeners.InternalAddr, "", nil)
	o.clientSideService.SetRouter(o.router)
	if o.svidProvider != nil {
		o.clientSideService.SetWorkloadSVIDProvider(o.svidProvider)
	}

	var serverTLS *tls.Config
	if o.tlsProvider != nil {
		if sp, ok := o.tlsProvider.(outbound.ServerTLSConfigProvider); ok {
			if cfg, err := sp.GetServerTLSConfig(); err == nil {
				serverTLS = cfg
			}
		}
	}
	o.serverSideService = proxy.NewServerSideService(o.config.Listeners.ExternalAddr, serverTLS)

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
	if o.retryInterval > 0 {
		o.controlPlaneAgent.SetRetryInterval(o.retryInterval)
	} else if o.config.ControlPlane.RetryInterval != "" {
		if d, err := time.ParseDuration(o.config.ControlPlane.RetryInterval); err == nil && d > 0 {
			o.controlPlaneAgent.SetRetryInterval(d)
		}
	}
	if len(o.config.ControlPlane.Labels) > 0 {
		o.controlPlaneAgent.SetLabels(o.config.ControlPlane.Labels)
	}

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
	log.Printf("[Step 5/10] ScopeSnapshot processed: %d services, %d routes, %d namespaces.\n",
		len(snapshot.Services), len(snapshot.Routes), len(snapshot.Namespaces))

	o.controlPlaneAgent.SetSnapshotHandler(func(newSnapshot *omnimeshv1.ScopeSnapshot) {
		log.Printf("Router: applying updated ScopeSnapshot received upon reconnect (%d services, %d routes, %d namespaces)\n",
			len(newSnapshot.Services), len(newSnapshot.Routes), len(newSnapshot.Namespaces))
		o.router.ApplySnapshot(newSnapshot)
		if err := o.syncPacketProcessorSubnets(o.router.Subnets()); err != nil {
			log.Printf("Failed to update packet processor subnets from ScopeSnapshot: %v\n", err)
		}
	})

	// Step 6: Extract namespace subnets from the initial ScopeSnapshot.
	log.Println("[Step 6/10] Extracting namespace subnets from ScopeSnapshot...")
	subnets := o.router.Subnets()
	if err := validateSubnets(subnets); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrSubnetsConfigFailed, err)
	}
	log.Printf("[Step 6/10] Loaded %d namespace subnets from Control Plane: %v\n", len(subnets), subnets)

	// Step 7: Use packet processsor to configure packet filtering.
	log.Println("[Step 7/10] Using packet processor to configure packet filtering...")
	_, portStr, err := net.SplitHostPort(o.config.Listeners.InternalAddr)
	var internalPort uint16 = 15001
	if err == nil {
		if p, err := strconv.ParseUint(portStr, 10, 16); err == nil {
			internalPort = uint16(p)
		}
	}
	o.mu.Lock()
	o.internalPort = internalPort
	o.mu.Unlock()

	if o.processorFactory == nil {
		return fmt.Errorf("%w: processor factory not configured", domain.ErrPacketProcessorInitFailed)
	}
	if err := o.syncPacketProcessorSubnets(subnets); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrPacketProcessorInitFailed, err)
	}
	log.Println("[Step 7/10] Packet filtering configured and processor running.")

	// Step 8: Read from config and files what services to deploy.
	log.Println("[Step 8/10] Reading from config and files what services to deploy...")
	o.servicesToDeploy = append([]model.NodeServiceInfo(nil), o.config.Services...)
	if o.config.ServicesDir != "" {
		dirServices, err := model.ReadServicesFromDir(o.config.ServicesDir)
		if err != nil {
			log.Printf("[Step 8/10] Warning: failed to read services directory %q: %v\n", o.config.ServicesDir, err)
		} else {
			o.servicesToDeploy = model.MergeServices(o.servicesToDeploy, dirServices)
		}
	}
	log.Printf("[Step 8/10] Loaded %d services to deploy from config/files/directory.\n", len(o.servicesToDeploy))
	if o.serverSideService != nil {
		o.serverSideService.SetServices(o.servicesToDeploy)
	}

	// Step 9: Send and receive updates to/from Control Plane and update routing config and packet filtering.
	// - This should run until the application is stopped.
	log.Println("[Step 9/10] Sending and receiving updates to/from Control Plane...")
	if len(o.servicesToDeploy) > 0 {
		if err := o.controlPlaneAgent.SendDeployedServices(ctx, o.servicesToDeploy); err != nil {
			log.Printf("Warning: failed to send deployed services to Control Plane: %v\n", err)
		}
	}

	// Start dynamic service manager (directory watcher and health probers)
	svcMgr := service.NewManager(service.ManagerConfig{
		ServicesDir:       o.config.ServicesDir,
		InitialServices:   o.servicesToDeploy,
		ControlPlaneAgent: o.controlPlaneAgent,
		OnServicesChange: func(added, removed []model.NodeServiceInfo) {
			if o.serverSideService != nil {
				o.serverSideService.UpdateServices(added, removed)
			}
		},
	})
	o.mu.Lock()
	o.serviceManager = svcMgr
	o.mu.Unlock()

	if err := svcMgr.Start(ctx); err != nil {
		log.Printf("[Step 9/10] Warning: failed to start dynamic service manager: %v\n", err)
	}

	streamErrCh := make(chan error, 1)
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		err := o.controlPlaneAgent.StreamUpdates(ctx, func(update *omnimeshv1.ScopeUpdate) {
			o.router.ApplyUpdate(update)
			if len(update.Namespaces) > 0 {
				if err := o.syncPacketProcessorSubnets(o.router.Subnets()); err != nil {
					log.Printf("Failed to update packet processor subnets from ScopeUpdate: %v\n", err)
				}
			}
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
	proc := o.packetProcessor
	procCancel := o.processorCancel
	svcMgr := o.serviceManager
	o.serviceManager = nil
	o.mu.Unlock()

	if svcMgr != nil {
		_ = svcMgr.Close()
	}

	if procCancel != nil {
		procCancel()
	}
	if proc != nil {
		_ = proc.Close()
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
	if o.svidCloser != nil {
		_ = o.svidCloser.Close()
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

// ServiceManager returns the dynamic ServiceManager used by the Orchestrator, or nil if not running.
func (o *Orchestrator) ServiceManager() *service.Manager {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.serviceManager
}

// WorkloadSVIDProvider returns the active WorkloadSVIDProvider used by the Orchestrator, or nil if none is running.
func (o *Orchestrator) WorkloadSVIDProvider() outbound.WorkloadSVIDProvider {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.svidProvider
}

// Router returns the mesh Router used by the Orchestrator.
func (o *Orchestrator) Router() *proxy.Router {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.router
}

// Subnets returns a copy of the currently intercepted subnets.
func (o *Orchestrator) Subnets() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.currentSubnets...)
}

// PacketProcessor returns the currently active PacketProcessor, or nil if none is running.
func (o *Orchestrator) PacketProcessor() outbound.PacketProcessor {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.packetProcessor
}

// UpdateInterceptionSubnets replaces the intercepted subnets while running, without
// restarting the packet processor. It returns domain.ErrSubnetUpdateUnsupported if
// the active processor cannot be updated at runtime.
func (o *Orchestrator) UpdateInterceptionSubnets(subnets []string) error {
	o.processorMu.Lock()
	defer o.processorMu.Unlock()

	o.mu.Lock()
	processor := o.packetProcessor
	stopped := o.stopped
	o.mu.Unlock()

	if stopped || processor == nil {
		return fmt.Errorf("cannot update intercepted subnets: packet processor is not running")
	}
	updater, ok := processor.(outbound.SubnetUpdater)
	if !ok {
		return fmt.Errorf("%w: %T", domain.ErrSubnetUpdateUnsupported, processor)
	}
	if err := updater.UpdateSubnets(subnets); err != nil {
		return fmt.Errorf("failed to update intercepted subnets: %w", err)
	}

	o.mu.Lock()
	o.currentSubnets = normalizeSubnetList(subnets)
	o.mu.Unlock()
	log.Printf("Intercepted subnets updated: %v\n", subnets)
	return nil
}

// syncPacketProcessorSubnets updates the active packet processor to match the given
// namespace subnets. If the running processor implements outbound.SubnetUpdater, its
// subnets are updated in place; otherwise the processor is stopped and recreated via
// processorFactory with the new subnets (or stopped if subnets is empty).
func (o *Orchestrator) syncPacketProcessorSubnets(subnets []string) error {
	normalized := normalizeSubnetList(subnets)
	if err := validateSubnets(normalized); err != nil {
		return err
	}

	o.processorMu.Lock()
	defer o.processorMu.Unlock()

	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return nil
	}
	currentProc := o.packetProcessor
	sameSubnets := slices.Equal(normalized, o.currentSubnets)
	o.mu.Unlock()

	if sameSubnets && (len(normalized) == 0 || currentProc != nil) {
		return nil
	}

	if len(normalized) == 0 {
		if currentProc != nil {
			if updater, ok := currentProc.(outbound.SubnetUpdater); ok {
				if err := updater.UpdateSubnets(nil); err != nil {
					return fmt.Errorf("failed to clear intercepted subnets: %w", err)
				}
				o.mu.Lock()
				o.currentSubnets = nil
				o.mu.Unlock()
				log.Println("Intercepted subnets cleared (no active namespaces).")
				return nil
			}
			o.stopProcessorLocked()
		}
		o.mu.Lock()
		o.currentSubnets = nil
		o.mu.Unlock()
		log.Println("Packet processor idle (no active namespace subnets).")
		return nil
	}

	if currentProc != nil {
		if updater, ok := currentProc.(outbound.SubnetUpdater); ok {
			if err := updater.UpdateSubnets(normalized); err != nil {
				return fmt.Errorf("failed to update intercepted subnets: %w", err)
			}
			o.mu.Lock()
			o.currentSubnets = normalized
			o.mu.Unlock()
			log.Printf("Intercepted subnets updated in-place: %v\n", normalized)
			return nil
		}
		o.stopProcessorLocked()
	}

	if err := o.startProcessorLocked(normalized); err != nil {
		return err
	}
	log.Printf("Packet processor configured with subnets: %v\n", normalized)
	return nil
}

// stopProcessorLocked stops and closes the currently running packet processor.
// Caller must hold o.processorMu.
func (o *Orchestrator) stopProcessorLocked() {
	o.mu.Lock()
	proc := o.packetProcessor
	cancel := o.processorCancel
	done := o.processorDone
	o.packetProcessor = nil
	o.processorCancel = nil
	o.processorDone = nil
	svc := o.clientSideService
	o.mu.Unlock()

	if svc != nil {
		svc.SetPacketProcessor(nil)
	}
	if cancel != nil {
		cancel()
	}
	if proc != nil {
		_ = proc.Close()
	}
	if done != nil {
		<-done
	}
}

// startProcessorLocked creates and starts a new packet processor for the given subnets.
// Caller must hold o.processorMu.
func (o *Orchestrator) startProcessorLocked(subnets []string) error {
	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return nil
	}
	factory := o.processorFactory
	interceptionType := o.config.Interception.Type
	internalPort := o.internalPort
	runCtx := o.runCtx
	svc := o.clientSideService
	o.mu.Unlock()

	if factory == nil {
		return fmt.Errorf("processor factory not configured")
	}

	processor, err := factory(interceptionType, subnets, internalPort)
	if err != nil {
		return err
	}

	procCtx, procCancel := context.WithCancel(runCtx)
	procDone := make(chan struct{})

	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		procCancel()
		_ = processor.Close()
		return nil
	}
	o.packetProcessor = processor
	o.processorCancel = procCancel
	o.processorDone = procDone
	o.currentSubnets = append([]string(nil), subnets...)
	o.mu.Unlock()

	if svc != nil {
		svc.SetPacketProcessor(processor)
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer close(procDone)
		if err := processor.Run(procCtx); err != nil && procCtx.Err() == nil {
			log.Printf("Packet processor stopped: %v\n", err)
		}
	}()

	return nil
}

func validateSubnets(subnets []string) error {
	for _, subnet := range subnets {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			return fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
		}
	}
	return nil
}

func normalizeSubnetList(subnets []string) []string {
	if len(subnets) == 0 {
		return nil
	}
	cp := make([]string, 0, len(subnets))
	for _, s := range subnets {
		if s != "" {
			cp = append(cp, s)
		}
	}
	if len(cp) == 0 {
		return nil
	}
	slices.Sort(cp)
	return slices.Compact(cp)
}
