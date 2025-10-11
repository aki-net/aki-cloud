package api

import (
	"testing"
	"time"

	"aki-cloud/backend/internal/models"
)

func TestEvaluateNodeStatus(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		node     models.Node
		health   map[string]models.EdgeHealthStatus
		expected models.NodeStatus
	}{
		{
			name:     "no edge ips",
			node:     models.Node{},
			health:   map[string]models.EdgeHealthStatus{},
			expected: models.NodeStatusIdle,
		},
		{
			name:     "pending edge awaiting health",
			node:     models.Node{IPs: []string{"10.0.0.1"}},
			health:   map[string]models.EdgeHealthStatus{},
			expected: models.NodeStatusPending,
		},
		{
			name: "all healthy",
			node: models.Node{IPs: []string{"10.0.0.1"}},
			health: map[string]models.EdgeHealthStatus{
				"10.0.0.1": {IP: "10.0.0.1", Healthy: true, LastChecked: now},
			},
			expected: models.NodeStatusHealthy,
		},
		{
			name: "mixed health degraded",
			node: models.Node{IPs: []string{"10.0.0.1", "10.0.0.2"}},
			health: map[string]models.EdgeHealthStatus{
				"10.0.0.1": {IP: "10.0.0.1", Healthy: true, LastChecked: now},
				"10.0.0.2": {IP: "10.0.0.2", Healthy: false, LastChecked: now},
			},
			expected: models.NodeStatusDegraded,
		},
		{
			name: "all unhealthy",
			node: models.Node{IPs: []string{"10.0.0.1"}},
			health: map[string]models.EdgeHealthStatus{
				"10.0.0.1": {IP: "10.0.0.1", Healthy: false, LastChecked: now},
			},
			expected: models.NodeStatusOffline,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := tc.node
			node.ComputeEdgeIPs()
			status, _, _, _, _ := evaluateNodeStatus(node, tc.health)
			if status != tc.expected {
				t.Fatalf("expected status %s, got %s", tc.expected, status)
			}
		})
	}
}
