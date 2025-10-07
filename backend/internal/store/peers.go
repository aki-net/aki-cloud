package store

import (
	"os"
	"sort"
)

type peersPayload struct {
	Peers []string `json:"peers"`
}

// GetPeers returns the configured peer endpoints.
func (s *Store) GetPeers() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	file := s.peersFile()
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var payload peersPayload
	if err := readJSON(file, &payload); err != nil {
		return nil, err
	}
	return payload.Peers, nil
}

// SavePeers persists peer endpoints atomically.
func (s *Store) SavePeers(peers []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unique := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		if peer == "" {
			continue
		}
		unique[peer] = struct{}{}
	}
	collapsed := make([]string, 0, len(unique))
	for peer := range unique {
		collapsed = append(collapsed, peer)
	}
	sort.Strings(collapsed)
	payload := peersPayload{Peers: collapsed}
	return writeJSONAtomic(s.peersFile(), payload)
}
