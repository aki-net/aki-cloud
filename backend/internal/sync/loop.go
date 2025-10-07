package sync

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type peerList struct {
	Peers []string `json:"peers"`
}

// Start launches the periodic sync loop.
func (s *Service) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				log.Printf("sync error: %v", err)
			}
		}
	}
}

// SyncOnce performs a single sync iteration.
func (s *Service) SyncOnce(ctx context.Context) error {
	peers, err := s.loadPeers()
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		return nil
	}
	peer := peers[rand.Intn(len(peers))]
	return s.PullFromPeer(ctx, peer)
}

func (s *Service) loadPeers() ([]string, error) {
	path := filepath.Join(s.dataDir, "cluster", "peers.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var list peerList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list.Peers, nil
}
