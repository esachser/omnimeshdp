package model

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseServicesFromJSON parses a byte slice containing either a single NodeServiceInfo
// JSON object or an array of NodeServiceInfo objects.
func ParseServicesFromJSON(data []byte) ([]NodeServiceInfo, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	if strings.HasPrefix(trimmed, "[") {
		var services []NodeServiceInfo
		if err := json.Unmarshal(data, &services); err != nil {
			return nil, fmt.Errorf("failed to parse services list: %w", err)
		}
		return services, nil
	}

	var single NodeServiceInfo
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("failed to parse service object: %w", err)
	}
	if single.Name == "" {
		return nil, fmt.Errorf("service missing name")
	}
	return []NodeServiceInfo{single}, nil
}

// ReadServicesFromFile reads and parses services from a JSON file.
func ReadServicesFromFile(path string) ([]NodeServiceInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read services file %q: %w", path, err)
	}
	return ParseServicesFromJSON(data)
}

// ReadServicesFromDir reads all .json files from the specified directory and aggregates services.
func ReadServicesFromDir(dir string) ([]NodeServiceInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read services directory %q: %w", dir, err)
	}

	var allServices []NodeServiceInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Only consider .json files, ignore hidden/temporary files
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "#") || strings.HasSuffix(name, "~") {
			continue
		}
		if !strings.EqualFold(filepath.Ext(name), ".json") {
			continue
		}

		filePath := filepath.Join(dir, name)
		svcs, err := ReadServicesFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("error reading %q: %w", filePath, err)
		}
		allServices = append(allServices, svcs...)
	}

	return allServices, nil
}

// MergeServices combines existing and new services, with new services taking precedence on key conflicts.
func MergeServices(existing, incoming []NodeServiceInfo) []NodeServiceInfo {
	m := make(map[string]NodeServiceInfo)
	order := make([]string, 0, len(existing)+len(incoming))

	for _, s := range existing {
		k := s.Key()
		if _, ok := m[k]; !ok {
			order = append(order, k)
		}
		m[k] = s
	}
	for _, s := range incoming {
		k := s.Key()
		if _, ok := m[k]; !ok {
			order = append(order, k)
		}
		m[k] = s
	}

	res := make([]NodeServiceInfo, 0, len(order))
	for _, k := range order {
		res = append(res, m[k])
	}
	return res
}

