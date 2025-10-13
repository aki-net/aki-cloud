package infra

import (
	"hash/fnv"
	"sort"
	"strings"

	"aki-cloud/backend/internal/models"
)

// PreferHealthyEndpoints returns endpoints prioritising ones marked healthy.
func PreferHealthyEndpoints(endpoints []EdgeEndpoint, health map[string]models.EdgeHealthStatus) []EdgeEndpoint {
	healthy := make([]EdgeEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		status, ok := health[endpoint.IP]
		if ok && status.Healthy {
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

// RendezvousOrder returns endpoints sorted by rendezvous priority (highest score first).
func RendezvousOrder(key string, endpoints []EdgeEndpoint) []EdgeEndpoint {
	key = strings.TrimSpace(strings.ToLower(key))
	type candidate struct {
		endpoint EdgeEndpoint
		score    uint64
	}
	order := make([]candidate, 0, len(endpoints))
	for _, ep := range endpoints {
		order = append(order, candidate{
			endpoint: ep,
			score:    rendezvousScore(key, ep),
		})
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].score == order[j].score {
			return endpointLess(order[i].endpoint, order[j].endpoint)
		}
		return order[i].score > order[j].score
	})
	result := make([]EdgeEndpoint, 0, len(order))
	for _, cand := range order {
		result = append(result, cand.endpoint)
	}
	return result
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
