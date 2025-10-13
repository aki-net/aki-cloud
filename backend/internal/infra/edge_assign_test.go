package infra

import (
	"strings"
	"testing"

	"aki-cloud/backend/internal/models"
)

func TestEnsureAssignmentSalt(t *testing.T) {
	var edge models.DomainEdge
	if changed := ensureAssignmentSalt(&edge, "Example.com"); !changed {
		t.Fatalf("expected change for empty salt")
	}
	if edge.AssignmentSalt == "" {
		t.Fatalf("expected non-empty salt")
	}
	if strings.EqualFold(edge.AssignmentSalt, "example.com") {
		t.Fatalf("expected salt to differ from domain, got %s", edge.AssignmentSalt)
	}
	if len(edge.AssignmentSalt) != 16 {
		t.Fatalf("expected 16-character salt, got %d", len(edge.AssignmentSalt))
	}

	original := edge.AssignmentSalt
	if changed := ensureAssignmentSalt(&edge, "example.com"); changed {
		t.Fatalf("unexpected change when salt already hashed")
	}
	if edge.AssignmentSalt != original {
		t.Fatalf("salt mutated unexpectedly: %s vs %s", edge.AssignmentSalt, original)
	}
}
