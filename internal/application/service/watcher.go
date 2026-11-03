package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/fsnotify/fsnotify"
)

// ServicesChangeCallback is invoked when services in the watched directory are added, updated, or removed.
type ServicesChangeCallback func(added, removed []model.NodeServiceInfo)

// Watcher monitors a directory for service JSON files and emits delta events.
type Watcher struct {
	dir         string
	onChange    ServicesChangeCallback
	fsWatcher   *fsnotify.Watcher
	currentMap  map[string]model.NodeServiceInfo
	mu          sync.Mutex
	debounceDur time.Duration
	doneCh      chan struct{}
	closed      bool
	wg          sync.WaitGroup
}

// WatcherOption configures a Watcher.
type WatcherOption func(*Watcher)

// WithDebounceDuration sets the debounce window before processing file changes.
func WithDebounceDuration(d time.Duration) WatcherOption {
	return func(w *Watcher) {
		w.debounceDur = d
	}
}

// NewWatcher creates a new directory watcher.
func NewWatcher(dir string, onChange ServicesChangeCallback, opts ...WatcherOption) (*Watcher, error) {
	w := &Watcher{
		dir:         filepath.Clean(dir),
		onChange:    onChange,
		currentMap:  make(map[string]model.NodeServiceInfo),
		debounceDur: 150 * time.Millisecond,
		doneCh:      make(chan struct{}),
	}
	for _, opt := range opts {
		opt(w)
	}

	if dir == "" {
		return w, nil
	}

	if err := os.MkdirAll(w.dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create services directory %q: %w", w.dir, err)
	}

	initialServices, err := model.ReadServicesFromDir(w.dir)
	if err != nil {
		log.Printf("[ServiceWatcher] Warning: initial read of %q: %v\n", w.dir, err)
	} else {
		for _, s := range initialServices {
			w.currentMap[s.Key()] = s
		}
	}

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	w.fsWatcher = fsWatcher

	if err := fsWatcher.Add(w.dir); err != nil {
		_ = fsWatcher.Close()
		return nil, fmt.Errorf("failed to watch directory %q: %w", w.dir, err)
	}

	return w, nil
}

// Start begins monitoring the filesystem events in a background goroutine.
func (w *Watcher) Start(ctx context.Context) {
	if w.fsWatcher == nil {
		return
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		var timer *time.Timer
		var timerCh <-chan time.Time

		for {
			select {
			case <-ctx.Done():
				return
			case <-w.doneCh:
				return
			case event, ok := <-w.fsWatcher.Events:
				if !ok {
					return
				}
				// Filter for JSON files or events affecting the directory
				ext := strings.ToLower(filepath.Ext(event.Name))
				base := filepath.Base(event.Name)
				if strings.HasPrefix(base, ".") || strings.HasPrefix(base, "#") || strings.HasSuffix(base, "~") {
					continue
				}
				if ext != ".json" && event.Op&fsnotify.Create == 0 && event.Op&fsnotify.Remove == 0 {
					continue
				}

				if timer != nil {
					timer.Stop()
				}
				timer = time.NewTimer(w.debounceDur)
				timerCh = timer.C

			case err, ok := <-w.fsWatcher.Errors:
				if !ok {
					return
				}
				log.Printf("[ServiceWatcher] Watcher error: %v\n", err)

			case <-timerCh:
				timerCh = nil
				if _, _, err := w.ScanAndDiff(); err != nil {
					log.Printf("[ServiceWatcher] Failed to scan and diff services: %v\n", err)
				}
			}
		}
	}()
}

// ScanAndDiff re-reads the directory, computes differences, updates tracked state,
// and invokes the onChange callback if any changes are detected.
func (w *Watcher) ScanAndDiff() (added []model.NodeServiceInfo, removed []model.NodeServiceInfo, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dir == "" {
		return nil, nil, nil
	}

	latestServices, err := model.ReadServicesFromDir(w.dir)
	if err != nil {
		return nil, nil, err
	}

	newMap := make(map[string]model.NodeServiceInfo, len(latestServices))
	for _, s := range latestServices {
		newMap[s.Key()] = s
	}

	// Find added or modified services
	for k, newSvc := range newMap {
		oldSvc, exists := w.currentMap[k]
		if !exists || !oldSvc.Equal(newSvc) {
			added = append(added, newSvc)
		}
	}

	// Find removed services
	for k, oldSvc := range w.currentMap {
		if _, exists := newMap[k]; !exists {
			removed = append(removed, oldSvc)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		w.currentMap = newMap
		if w.onChange != nil {
			w.onChange(added, removed)
		}
	}

	return added, removed, nil
}

// CurrentServices returns a slice of currently detected services in the directory.
func (w *Watcher) CurrentServices() []model.NodeServiceInfo {
	w.mu.Lock()
	defer w.mu.Unlock()

	svcs := make([]model.NodeServiceInfo, 0, len(w.currentMap))
	for _, s := range w.currentMap {
		svcs = append(svcs, s)
	}
	return svcs
}

// Close stops the watcher and frees filesystem resources.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.doneCh)
	w.mu.Unlock()

	var err error
	if w.fsWatcher != nil {
		err = w.fsWatcher.Close()
	}
	w.wg.Wait()
	return err
}

