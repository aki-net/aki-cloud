package sync

import (
	"context"
	"log"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
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
	return s.store.GetPeers()
}
