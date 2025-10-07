package store

import (
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
)

// UpsertDomain creates or updates a domain record.
func (s *Store) UpsertDomain(record models.DomainRecord) error {
	record.Domain = strings.ToLower(record.Domain)
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = time.Now().UTC()
	}
	return s.SaveDomain(record)
}

// ListDomainsForOwner returns domains filtered by owner id.
func (s *Store) ListDomainsForOwner(owner string) ([]models.DomainRecord, error) {
	all, err := s.GetDomains()
	if err != nil {
		return nil, err
	}
	if owner == "" {
		return all, nil
	}
	out := make([]models.DomainRecord, 0, len(all))
	for _, d := range all {
		if d.Owner == owner {
			out = append(out, d)
		}
	}
	return out, nil
}
