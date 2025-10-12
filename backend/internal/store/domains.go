package store

import (
	"encoding/json"
	"os"
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

// MarkDomainDeleted creates or updates a tombstone for the specified domain.
func (s *Store) MarkDomainDeleted(domain string, nodeID string, at time.Time) error {
	domain = strings.ToLower(domain)
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	file := s.domainRecordFile(domain)
	var rec models.DomainRecord
	if data, err := os.ReadFile(file); err == nil {
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	rec.Domain = domain
	rec.EnsureTLSDefaults()
	if rec.TTL <= 0 {
		rec.TTL = 60
	}
	rec.Version.Counter++
	if rec.Version.Counter <= 0 {
		rec.Version.Counter = 1
	}
	rec.Version.NodeID = nodeID
	rec.Version.Updated = at.Unix()
	rec.MarkDeleted(at)
	return writeJSONAtomic(file, rec)
}
