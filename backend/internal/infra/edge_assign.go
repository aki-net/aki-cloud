package infra

import (
	"fmt"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
)

const (
	rebalanceGrace = 5 * time.Minute
)

// EnsureDomainEdgeAssignment validates or updates the edge assignment for a domain.
func EnsureDomainEdgeAssignment(record *models.DomainRecord, endpoints []EdgeEndpoint, health map[string]models.EdgeHealthStatus) (bool, error) {
	record.Edge.Normalize()
	if record.Edge.AssignmentSalt == "" {
		record.Edge.AssignmentSalt = strings.ToLower(strings.TrimSpace(record.Domain))
	}

	eligible := FilterEdgeEndpointsByLabels(endpoints, record.Edge.Labels)
	if len(eligible) == 0 {
		return false, models.ErrValidation("no edge nodes match the requested labels")
	}

	endpointByIP := make(map[string]EdgeEndpoint, len(eligible))
	for _, endpoint := range eligible {
		endpointByIP[endpoint.IP] = endpoint
	}

	now := time.Now().UTC()
	mutated := false

	assign := func(ep EdgeEndpoint) {
		changed := false
		if record.Edge.AssignedIP != ep.IP {
			record.Edge.AssignedIP = ep.IP
			record.Edge.AssignedAt = now
			changed = true
		}
		if record.Edge.AssignedNodeID != ep.NodeID {
			record.Edge.AssignedNodeID = ep.NodeID
			changed = true
		}
		if record.Edge.AssignedAt.IsZero() {
			record.Edge.AssignedAt = now
			changed = true
		}
		if changed {
			mutated = true
		}
	}

	current, ok := endpointByIP[record.Edge.AssignedIP]
	needsAssignment := !ok || record.Edge.AssignedIP == ""

	// Check if current assignment is unhealthy
	if !needsAssignment && record.Edge.AssignedIP != "" {
		if status, ok := health[record.Edge.AssignedIP]; ok {
			// Only reassign if the node has been unhealthy for multiple failures
			if !status.Healthy && status.FailureCount >= 3 {
				needsAssignment = true
			}
		}
	}

	if needsAssignment {
		// Try to get healthy endpoints first
		candidates := PreferHealthyEndpoints(eligible, health)
		if len(candidates) == 0 {
			// If no healthy endpoints, use all eligible ones
			// This ensures service continues even if all nodes are degraded
			candidates = eligible
		}

		// Use deterministic selection with rendezvous hashing
		key := fmt.Sprintf("%s|%s", record.Domain, record.Edge.AssignmentSalt)
		selected := RendezvousSelect(key, candidates)

		// Only update if actually changed
		assign(selected)
	} else {
		// Update node ID if it changed (e.g., node was recreated with same IP)
		if record.Edge.AssignedNodeID != current.NodeID {
			record.Edge.AssignedNodeID = current.NodeID
			mutated = true
		}
		// Set assignment time if it was never set
		if record.Edge.AssignedAt.IsZero() {
			record.Edge.AssignedAt = now
			mutated = true
		}

		// Evaluate whether a rebalance is desired now that more edges may be available.
		candidates := PreferHealthyEndpoints(eligible, health)
		if len(candidates) == 0 {
			candidates = eligible
		}

		// Rendezvous hashing provides stable deterministic spread across the pool.
		key := fmt.Sprintf("%s|%s", record.Domain, record.Edge.AssignmentSalt)
		preferred := RendezvousSelect(key, candidates)

		if record.Edge.AssignedIP != preferred.IP && len(candidates) > 1 {
			// Only consider rebalance if the preferred endpoint is healthy (or we lack an opinion)
			preferredHealthy := true
			if st, ok := health[preferred.IP]; ok {
				preferredHealthy = st.Healthy
			}

			timeSinceAssign := rebalanceGrace
			if !record.Edge.AssignedAt.IsZero() {
				if delta := now.Sub(record.Edge.AssignedAt); delta > 0 {
					timeSinceAssign = delta
				}
			}

			if preferredHealthy && timeSinceAssign >= rebalanceGrace {
				assign(preferred)
			}
		}
	}

	record.Edge.Normalize()
	return mutated, nil
}
