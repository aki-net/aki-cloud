package api

import (
	"fmt"

	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
)

func (s *Server) ensureDomainEdgeAssignment(record *models.DomainRecord) (bool, error) {
	endpoints, err := s.Infra.EdgeEndpoints()
	if err != nil {
		return false, fmt.Errorf("load edge endpoints: %w", err)
	}
	health, err := s.Store.GetEdgeHealthMap()
	if err != nil {
		return false, fmt.Errorf("load edge health: %w", err)
	}
	return infra.EnsureDomainEdgeAssignment(record, endpoints, health)
}
