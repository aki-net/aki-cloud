package infra

import (
	"testing"

	"aki-cloud/backend/internal/models"
)

func TestPreferHealthyEndpoints(t *testing.T) {
	endpoints := []EdgeEndpoint{
		{IP: "192.0.2.10", NodeID: "node-healthy"},
		{IP: "192.0.2.20", NodeID: "node-unknown"},
		{IP: "192.0.2.30", NodeID: "node-unhealthy"},
	}

	health := map[string]models.EdgeHealthStatus{
		"192.0.2.10": {IP: "192.0.2.10", Healthy: true},
		"192.0.2.30": {IP: "192.0.2.30", Healthy: false, FailureCount: 3},
	}

	got := PreferHealthyEndpoints(endpoints, health)

	if len(got) != 1 {
		t.Fatalf("expected 1 healthy endpoint, got %d", len(got))
	}
	if got[0].IP != "192.0.2.10" {
		t.Fatalf("expected healthy endpoint 192.0.2.10, got %s", got[0].IP)
	}
}
