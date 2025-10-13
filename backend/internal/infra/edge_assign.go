package infra

import (
	"crypto/sha256"
	"encoding/hex"
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
	mutated := false
	if ensureAssignmentSalt(&record.Edge, record.Domain) {
		mutated = true
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

	defaultSalt := computeDefaultSalt(record.Domain)
	if base, pinnedIP, ok := parsePinnedSalt(record.Edge.AssignmentSalt); ok {
		if base != defaultSalt {
			record.Edge.AssignmentSalt = fmt.Sprintf("pin:%s:%s", defaultSalt, pinnedIP)
			mutated = true
		}
		if ep, ok := endpointByIP[pinnedIP]; ok {
			assign(ep)
			record.Edge.Normalize()
			return mutated, nil
		}
		record.Edge.AssignmentSalt = defaultSalt
		mutated = true
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

func ensureAssignmentSalt(edge *models.DomainEdge, domain string) bool {
	defaultSalt := computeDefaultSalt(domain)
	current := strings.TrimSpace(edge.AssignmentSalt)
	if _, pinnedIP, ok := parsePinnedSalt(current); ok {
		normalized := fmt.Sprintf("pin:%s:%s", defaultSalt, pinnedIP)
		if current != normalized {
			edge.AssignmentSalt = normalized
			return true
		}
		return false
	}
	domainKey := strings.ToLower(strings.TrimSpace(domain))
	lower := strings.ToLower(current)
	if lower == "" || lower == domainKey || strings.HasPrefix(lower, domainKey+":") {
		if edge.AssignmentSalt != defaultSalt {
			edge.AssignmentSalt = defaultSalt
			return true
		}
		return false
	}
	if lower != defaultSalt {
		edge.AssignmentSalt = defaultSalt
		return true
	}
	if current != defaultSalt {
		edge.AssignmentSalt = defaultSalt
		return true
	}
	return false
}

func computeDefaultSalt(domain string) string {
	domainKey := strings.ToLower(strings.TrimSpace(domain))
	hasher := sha256.Sum256([]byte(domainKey))
	return hex.EncodeToString(hasher[:8])
}

func parsePinnedSalt(s string) (base string, ip string, ok bool) {
	if !strings.HasPrefix(s, "pin:") {
		return "", "", false
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}
