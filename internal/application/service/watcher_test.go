package service_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/esachser/omnimeshdp/internal/application/service"
	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestWatcherFileLifecycle(t *testing.T) {
	tmpDir := t.TempDir()

	addedCh := make(chan []model.NodeServiceInfo, 5)
	removedCh := make(chan []model.NodeServiceInfo, 5)

	watcher, err := service.NewWatcher(
		tmpDir,
		func(added, removed []model.NodeServiceInfo) {
			if len(added) > 0 {
				addedCh <- added
			}
			if len(removed) > 0 {
				removedCh <- removed
			}
		},
		service.WithDebounceDuration(50*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create watcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)

	// 1. Add a service file
	svcFile := filepath.Join(tmpDir, "order.json")
	orderJSON := `{
		"namespace": "production",
		"name": "order-service",
		"id": "order-1",
		"labels": {"app": "order"}
	}`
	if err := os.WriteFile(svcFile, []byte(orderJSON), 0644); err != nil {
		t.Fatalf("failed to write service file: %v", err)
	}

	select {
	case added := <-addedCh:
		if len(added) != 1 || added[0].Name != "order-service" {
			t.Fatalf("unexpected added service: %v", added)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for added event")
	}

	if svcs := watcher.CurrentServices(); len(svcs) != 1 {
		t.Errorf("expected 1 current service, got %d", len(svcs))
	}

	// 2. Modify service file
	orderUpdatedJSON := `{
		"namespace": "production",
		"name": "order-service",
		"id": "order-1",
		"labels": {"app": "order", "v": "2"}
	}`
	if err := os.WriteFile(svcFile, []byte(orderUpdatedJSON), 0644); err != nil {
		t.Fatalf("failed to update service file: %v", err)
	}

	select {
	case added := <-addedCh:
		if len(added) != 1 || added[0].Labels["v"] != "2" {
			t.Fatalf("unexpected updated service: %v", added)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for update event")
	}

	// 3. Remove service file
	if err := os.Remove(svcFile); err != nil {
		t.Fatalf("failed to remove service file: %v", err)
	}

	select {
	case removed := <-removedCh:
		if len(removed) != 1 || removed[0].Name != "order-service" {
			t.Fatalf("unexpected removed service: %v", removed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for remove event")
	}

	if svcs := watcher.CurrentServices(); len(svcs) != 0 {
		t.Errorf("expected 0 current services after removal, got %d", len(svcs))
	}
}

func TestWatcherEmptyDir(t *testing.T) {
	watcher, err := service.NewWatcher("", nil)
	if err != nil {
		t.Fatalf("empty dir watcher should succeed: %v", err)
	}
	defer watcher.Close()

	added, removed, err := watcher.ScanAndDiff()
	if err != nil || len(added) > 0 || len(removed) > 0 {
		t.Errorf("expected nil/empty for empty dir watcher")
	}
}

