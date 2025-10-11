package infra

import (
	"sort"
	"strings"

	"aki-cloud/backend/internal/models"
)

// EdgeEndpoint represents an addressable edge IP tied to a node.
type EdgeEndpoint struct {
	NodeID   string            `json:"node_id"`
	NodeName string            `json:"node_name"`
	IP       string            `json:"ip"`
	Labels   []string          `json:"labels,omitempty"`
	Roles    []models.NodeRole `json:"roles,omitempty"`
}

// EdgeEndpoints returns the list of edge-capable endpoints across the cluster.
func (c *Controller) EdgeEndpoints() ([]EdgeEndpoint, error) {
	nodes, err := c.store.GetNodes()
	if err != nil {
		return nil, err
	}
	endpoints := make([]EdgeEndpoint, 0, len(nodes))
	for _, node := range nodes {
		node.ComputeEdgeIPs()
		if !node.HasRole(models.NodeRoleEdge) {
			continue
		}
		for _, ip := range node.EdgeIPs {
			endpoint := EdgeEndpoint{
				NodeID:   node.ID,
				NodeName: node.Name,
				IP:       ip,
				Labels:   append([]string{}, node.Labels...),
				Roles:    append([]models.NodeRole{}, node.Roles...),
			}
			endpoints = append(endpoints, endpoint)
		}
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].IP == endpoints[j].IP {
			return endpoints[i].NodeID < endpoints[j].NodeID
		}
		return endpoints[i].IP < endpoints[j].IP
	})
	return endpoints, nil
}

// FilterEdgeEndpointsByLabels returns endpoints whose labels overlap with the provided ones.
func FilterEdgeEndpointsByLabels(endpoints []EdgeEndpoint, labels []string) []EdgeEndpoint {
	cleanLabels := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		label = strings.TrimSpace(strings.ToLower(label))
		if label == "" {
			continue
		}
		cleanLabels[label] = struct{}{}
	}
	if len(cleanLabels) == 0 {
		return endpoints
	}
	out := make([]EdgeEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		for _, nodeLabel := range endpoint.Labels {
			if _, ok := cleanLabels[strings.ToLower(nodeLabel)]; ok {
				out = append(out, endpoint)
				break
			}
		}
	}
	return out
}

// EdgeEndpointByIP returns the first endpoint matching the provided IP.
func EdgeEndpointByIP(endpoints []EdgeEndpoint, ip string) *EdgeEndpoint {
	for i := range endpoints {
		if endpoints[i].IP == ip {
			return &endpoints[i]
		}
	}
	return nil
}
