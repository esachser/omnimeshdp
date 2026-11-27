package oteltelemetry

import (
	"context"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const defaultSVIDRefreshInterval = 30 * time.Second

// SVIDSource abstracts a SPIFFE X.509 SVID source for expiry and rotation monitoring.
type SVIDSource interface {
	GetX509SVID() (*x509svid.SVID, error)
	Updated() <-chan struct{}
}

var _ SVIDSource = (*workloadapi.X509Source)(nil)

// SVIDMonitor periodically records active SVID TTL and counts rotations observed from SPIRE.
type SVIDMonitor struct {
	source     SVIDSource
	metrics    outbound.MetricRecorder
	cancel     context.CancelFunc
	done       chan struct{}
	stopOnce   sync.Once
	mu         sync.Mutex
	lastSerial string
}

// NewSVIDMonitor starts monitoring source and emits omnimesh.agent.mtls.svid.* metrics.
func NewSVIDMonitor(ctx context.Context, source SVIDSource, metrics outbound.MetricRecorder) *SVIDMonitor {
	if source == nil || metrics == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	m := &SVIDMonitor{
		source:  source,
		metrics: metrics,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	m.sample(runCtx)
	go m.loop(runCtx)
	return m
}

func (m *SVIDMonitor) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(defaultSVIDRefreshInterval)
	defer ticker.Stop()

	updatedCh := m.source.Updated()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-updatedCh:
			m.sample(ctx)
			if !ok {
				updatedCh = nil
			}
		case <-ticker.C:
			m.sample(ctx)
		}
	}
}

func (m *SVIDMonitor) sample(ctx context.Context) {
	svid, err := m.source.GetX509SVID()
	if err != nil || svid == nil || len(svid.Certificates) == 0 {
		return
	}

	leaf := svid.Certificates[0]
	spiffeID := svid.ID.String()
	expirySec := time.Until(leaf.NotAfter).Seconds()
	if expirySec < 0 {
		expirySec = 0
	}

	m.metrics.RecordGauge(ctx, outbound.MetricMTLSSVIDExpirySeconds, expirySec,
		model.MetricAttribute{Key: outbound.MetricAttrSPIFFEID, Value: spiffeID},
	)

	serial := leaf.SerialNumber.String()
	m.mu.Lock()
	rotated := m.lastSerial != "" && m.lastSerial != serial
	m.lastSerial = serial
	m.mu.Unlock()

	if rotated {
		m.metrics.AddCounter(ctx, outbound.MetricMTLSSVIDRotationsTotal, 1,
			model.MetricAttribute{Key: outbound.MetricAttrSPIFFEID, Value: spiffeID},
		)
	}
}

// Stop stops the background SVID monitoring goroutine and waits for it to exit.
func (m *SVIDMonitor) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		if m.cancel != nil {
			m.cancel()
		}
		if m.done != nil {
			<-m.done
		}
	})
}
