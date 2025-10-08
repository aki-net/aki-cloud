package ssl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type backoffEntry struct {
	RetryAfter time.Time `json:"retry_after"`
	Reason     string    `json:"reason,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type backoffStore struct {
	path string
	mu   sync.Mutex
}

func newBackoffStore(dataDir string) *backoffStore {
	path := filepath.Join(dataDir, "cluster", "acme_backoff.json")
	return &backoffStore{path: path}
}

func (s *backoffStore) loadAll() (map[string]backoffEntry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]backoffEntry), nil
		}
		return nil, err
	}
	var entries map[string]backoffEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		entries = make(map[string]backoffEntry)
	}
	return entries, nil
}

func (s *backoffStore) saveAll(entries map[string]backoffEntry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *backoffStore) Get(domain string) (*backoffEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	entry, ok := entries[strings.ToLower(domain)]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}

func (s *backoffStore) Set(domain string, entry backoffEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loadAll()
	if err != nil {
		return err
	}
	entries[strings.ToLower(domain)] = entry
	return s.saveAll(entries)
}

func (s *backoffStore) Clear(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loadAll()
	if err != nil {
		return err
	}
	key := strings.ToLower(domain)
	if _, ok := entries[key]; !ok {
		return nil
	}
	delete(entries, key)
	return s.saveAll(entries)
}
