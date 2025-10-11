package api

import (
	"strings"
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
		ns       []models.NameServerHealth
		expected models.NodeStatus
		contains string
	}{
		{
			name:     "no edge ips",
			node:     models.Node{},
			health:   map[string]models.EdgeHealthStatus{},
			expected: models.NodeStatusIdle,
			contains: "no services",
		},
		{
			name:     "pending edge awaiting health",
			node:     models.Node{IPs: []string{"10.0.0.1"}},
			health:   map[string]models.EdgeHealthStatus{},
			expected: models.NodeStatusPending,
			contains: "pending",
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
				"10.0.0.2": {IP: "10.0.0.2", Healthy: false, LastChecked: now, Message: "timeout"},
			},
			expected: models.NodeStatusDegraded,
			contains: "timeout",
		},
		{
			name: "all unhealthy",
			node: models.Node{IPs: []string{"10.0.0.1"}},
			health: map[string]models.EdgeHealthStatus{
				"10.0.0.1": {IP: "10.0.0.1", Healthy: false, LastChecked: now},
			},
			expected: models.NodeStatusOffline,
			contains: "unreachable",
		},
		{
			name:     "nameserver degraded overrides healthy edge",
			node:     models.Node{IPs: []string{"10.0.0.1"}, NSIPs: []string{"10.0.53.1"}},
			health:   map[string]models.EdgeHealthStatus{"10.0.0.1": {IP: "10.0.0.1", Healthy: true, LastChecked: now}},
			ns:       []models.NameServerHealth{{NodeID: "node", IPv4: "10.0.53.1", FQDN: "ns1.example", Healthy: false, Message: "refused", CheckedAt: now}},
			expected: models.NodeStatusOffline,
			contains: "refused",
		},
		{
			name:     "nameserver offline",
			node:     models.Node{NSIPs: []string{"10.0.53.1"}},
			health:   map[string]models.EdgeHealthStatus{},
			ns:       []models.NameServerHealth{{NodeID: "node", IPv4: "10.0.53.1", FQDN: "ns1.example", Healthy: false, Message: "timeout", CheckedAt: now}},
			expected: models.NodeStatusOffline,
			contains: "timeout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := tc.node
			node.ComputeEdgeIPs()
			status, msg, _, _, _ := evaluateNodeStatus(node, tc.health, tc.ns)
			if status != tc.expected {
				t.Fatalf("expected status %s, got %s", tc.expected, status)
			}
			if tc.contains != "" && !strings.Contains(msg, tc.contains) {
				t.Fatalf("expected message to contain %q, got %q", tc.contains, msg)
			}
		})
	}
}
