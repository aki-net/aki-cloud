package infra

import (
	"fmt"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
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
		if record.Edge.AssignedIP != selected.IP {
			record.Edge.AssignedIP = selected.IP
			record.Edge.AssignedNodeID = selected.NodeID
			record.Edge.AssignedAt = now
			mutated = true
		}
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
	}

	record.Edge.Normalize()
	return mutated, nil
}
