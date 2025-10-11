package infra

import (
	"hash/fnv"
	"strings"

	"aki-cloud/backend/internal/models"
)

// PreferHealthyEndpoints returns endpoints prioritising ones marked healthy.
func PreferHealthyEndpoints(endpoints []EdgeEndpoint, health map[string]models.EdgeHealthStatus) []EdgeEndpoint {
	healthy := make([]EdgeEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		status, ok := health[endpoint.IP]
		if !ok || status.Healthy {
			healthy = append(healthy, endpoint)
		}
	}
	return healthy
}

// RendezvousSelect chooses an endpoint based on rendezvous hashing.
func RendezvousSelect(key string, endpoints []EdgeEndpoint) EdgeEndpoint {
	key = strings.TrimSpace(strings.ToLower(key))
	var (
		selected    EdgeEndpoint
		selectedSum uint64
		chosen      bool
	)
	for _, endpoint := range endpoints {
		score := rendezvousScore(key, endpoint)
		if !chosen || score > selectedSum || (score == selectedSum && endpointLess(endpoint, selected)) {
			selected = endpoint
			selectedSum = score
			chosen = true
		}
	}
	return selected
}

func rendezvousScore(key string, endpoint EdgeEndpoint) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(endpoint.IP))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(endpoint.NodeID))
	return h.Sum64()
}

func endpointLess(a, b EdgeEndpoint) bool {
	if a.IP == b.IP {
		return a.NodeID < b.NodeID
	}
	return a.IP < b.IP
}
