package render

import (
	"testing"
	"time"

	"aki-cloud/backend/internal/models"
)

func TestFilterHealthyEdges(t *testing.T) {
	now := time.Now().UTC()
	edges := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

	t.Run("no health data falls back to all", func(t *testing.T) {
		got := filterHealthyEdges(edges, map[string]models.EdgeHealthStatus{})
		if len(got) != len(edges) {
			t.Fatalf("expected all edges, got %v", got)
		}
	})

	t.Run("pending edges skipped when health data exists", func(t *testing.T) {
		health := map[string]models.EdgeHealthStatus{
			"10.0.0.1": {IP: "10.0.0.1", Healthy: true, LastChecked: now},
		}
		got := filterHealthyEdges(edges, health)
		if len(got) != 1 || got[0] != "10.0.0.1" {
			t.Fatalf("expected only healthy edge, got %v", got)
		}
	})

	t.Run("stale unhealthy edges fail open", func(t *testing.T) {
		health := map[string]models.EdgeHealthStatus{
			"10.0.0.1": {IP: "10.0.0.1", Healthy: false, LastChecked: now.Add(-11 * time.Minute)},
		}
		got := filterHealthyEdges([]string{"10.0.0.1"}, health)
		if len(got) != 1 {
			t.Fatalf("expected stale edge to be returned, got %v", got)
		}
	})
}
