package service

import (
	"context"
	"fmt"
	"log"
	"sync"

	omnimeshv1 "github.com/esachser/omnimeshcontrol/api/gen/omnimesh/v1"
	"github.com/esachser/omnimeshdp/internal/application/agent"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

// ManagerConfig configures the service manager.
type ManagerConfig struct {
	ServicesDir       string
	InitialServices   []model.NodeServiceInfo
	ControlPlaneAgent *agent.ControlPlaneAgent
	OnServicesChange  func(added, removed []model.NodeServiceInfo)
	OnHealthChange    func(svc model.NodeServiceInfo, report *omnimeshv1.HealthReport)
}

// Manager coordinates directory monitoring, health checking, and Control Plane event advising.
type Manager struct {
	config        ManagerConfig
	healthChecker *HealthChecker
	watcher       *Watcher
	mu            sync.Mutex
	closed        bool
}

// NewManager constructs a new service Manager.
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		config: cfg,
	}
}

// Start begins service health checks and filesystem watching.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("service manager is closed")
	}

	// 1. Initialize HealthChecker
	m.healthChecker = NewHealthChecker(func(svc model.NodeServiceInfo, report *omnimeshv1.HealthReport) {
		log.Printf("[ServiceManager] Health report: %s/%s (%s) is now %v (%s)\n",
			report.Namespace, report.ServiceName, report.RouteName, report.Status, report.ProbeType)

		if m.config.ControlPlaneAgent != nil {
			if err := m.config.ControlPlaneAgent.SendHealthReport(ctx, report); err != nil {
				log.Printf("[ServiceManager] Warning: failed to send health report to Control Plane: %v\n", err)
			}
		}

		if m.config.OnHealthChange != nil {
			m.config.OnHealthChange(svc, report)
		}
	})

	// 2. Start health checking for initial services
	for _, svc := range m.config.InitialServices {
		if svc.HealthCheck != nil {
			m.healthChecker.StartService(svc)
		}
	}

	// 3. Initialize and start Watcher if ServicesDir is configured
	if m.config.ServicesDir != "" {
		w, err := NewWatcher(m.config.ServicesDir, func(added, removed []model.NodeServiceInfo) {
			log.Printf("[ServiceManager] Directory update: %d added/modified, %d removed\n",
				len(added), len(removed))

			// Stop health checks for removed services
			for _, r := range removed {
				m.healthChecker.StopService(r.Key())
			}

			// Start/restart health checks for added or modified services
			for _, a := range added {
				if a.HealthCheck != nil {
					m.healthChecker.StartService(a)
				} else {
					m.healthChecker.StopService(a.Key())
				}
			}

			// Advise the Control Plane of service additions and removals
			if m.config.ControlPlaneAgent != nil {
				if err := m.config.ControlPlaneAgent.SendServiceUpdates(ctx, added, removed); err != nil {
					log.Printf("[ServiceManager] Warning: failed to advise Control Plane of service updates: %v\n", err)
				}
			}

			if m.config.OnServicesChange != nil {
				m.config.OnServicesChange(added, removed)
			}
		})
		if err != nil {
			return fmt.Errorf("failed to initialize service directory watcher: %w", err)
		}

		m.watcher = w
		w.Start(ctx)
		log.Printf("[ServiceManager] Started watching directory %q for dynamic service updates.\n", m.config.ServicesDir)
	}

	return nil
}

// HealthChecker returns the underlying HealthChecker instance.
func (m *Manager) HealthChecker() *HealthChecker {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthChecker
}

// Watcher returns the underlying Watcher instance, or nil if ServicesDir was empty.
func (m *Manager) Watcher() *Watcher {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.watcher
}

// Close terminates directory watching and stops all active health probers.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	w := m.watcher
	h := m.healthChecker
	m.mu.Unlock()

	var err error
	if w != nil {
		err = w.Close()
	}
	if h != nil {
		h.Close()
	}
	return err
}

