package store

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aki-cloud/backend/internal/models"
)

// Store provides on-disk persistence backed by JSON files.
type Store struct {
	dataDir string
	mu      sync.RWMutex
}

// New creates a new file-backed store.
func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	return &Store{dataDir: dataDir}, nil
}

// path helpers
func (s *Store) usersFile() string {
	return filepath.Join(s.dataDir, "users", "users.json")
}

func (s *Store) versionsFile() string {
	return filepath.Join(s.dataDir, "cluster", "versions.json")
}

func (s *Store) nodesFile() string {
	return filepath.Join(s.dataDir, "infra", "nodes.json")
}

func (s *Store) peersFile() string {
	return filepath.Join(s.dataDir, "cluster", "peers.json")
}

func (s *Store) edgeHealthFile() string {
	return filepath.Join(s.dataDir, "cluster", "edge_health.json")
}

func (s *Store) domainDir(domain string) string {
	domain = strings.ToLower(domain)
	return filepath.Join(s.dataDir, "domains", domain)
}

func (s *Store) domainRecordFile(domain string) string {
	return filepath.Join(s.domainDir(domain), "record.json")
}

func readJSON(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func writeJSONAtomic(path string, in interface{}) error {
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	data, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func listDomainRecords(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domains = append(domains, entry.Name())
	}
	return domains, nil
}

// GetUsers fetches all users from disk.
func (s *Store) GetUsers() ([]models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path := s.usersFile()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []models.User{}, nil
		}
		return nil, err
	}
	var users []models.User
	if err := readJSON(path, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// SaveUsers persists the provided users slice atomically.
func (s *Store) SaveUsers(users []models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONAtomic(s.usersFile(), users)
}

// GetEdgeHealth returns the current edge health snapshot.
func (s *Store) GetEdgeHealth() ([]models.EdgeHealthStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path := s.edgeHealthFile()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []models.EdgeHealthStatus{}, nil
		}
		return nil, err
	}
	var statuses []models.EdgeHealthStatus
	if err := readJSON(path, &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

// GetEdgeHealthMap returns a map keyed by IP for quick lookups.
func (s *Store) GetEdgeHealthMap() (map[string]models.EdgeHealthStatus, error) {
	statuses, err := s.GetEdgeHealth()
	if err != nil {
		return nil, err
	}
	m := make(map[string]models.EdgeHealthStatus, len(statuses))
	for _, status := range statuses {
		m[status.IP] = status
	}
	return m, nil
}

// SaveEdgeHealth persists the provided health slice atomically.
func (s *Store) SaveEdgeHealth(statuses []models.EdgeHealthStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONAtomic(s.edgeHealthFile(), statuses)
}

// UpsertEdgeHealth inserts or updates a single edge health record.
func (s *Store) UpsertEdgeHealth(status models.EdgeHealthStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.edgeHealthFile()
	var statuses []models.EdgeHealthStatus
	if _, err := os.Stat(path); err == nil {
		if err := readJSON(path, &statuses); err != nil {
			return err
		}
	}
	replaced := false
	for i := range statuses {
		if statuses[i].IP == status.IP {
			statuses[i] = status
			replaced = true
			break
		}
	}
	if !replaced {
		statuses = append(statuses, status)
	}
	return writeJSONAtomic(path, statuses)
}

// DeleteEdgeHealth removes a record for the provided IP.
func (s *Store) DeleteEdgeHealth(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.edgeHealthFile()
	var statuses []models.EdgeHealthStatus
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := readJSON(path, &statuses); err != nil {
		return err
	}
	pruned := make([]models.EdgeHealthStatus, 0, len(statuses))
	for _, st := range statuses {
		if st.IP == ip {
			continue
		}
		pruned = append(pruned, st)
	}
	return writeJSONAtomic(path, pruned)
}

// GetDomains returns all domain records.
func (s *Store) GetDomains() ([]models.DomainRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	root := filepath.Join(s.dataDir, "domains")
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return []models.DomainRecord{}, nil
		}
		return nil, err
	}
	dirs, err := listDomainRecords(root)
	if err != nil {
		return nil, err
	}
	records := make([]models.DomainRecord, 0, len(dirs))
	for _, domain := range dirs {
		var rec models.DomainRecord
		file := filepath.Join(root, domain, "record.json")
		if err := readJSON(file, &rec); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading domain %s: %w", domain, err)
		}
		rec.EnsureTLSDefaults()
		records = append(records, rec)
	}
	return records, nil
}

// SaveDomain persists a single domain record.
func (s *Store) SaveDomain(record models.DomainRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record.EnsureTLSDefaults()
	return writeJSONAtomic(s.domainRecordFile(record.Domain), record)
}

// DeleteDomain removes a domain directory.
func (s *Store) DeleteDomain(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.RemoveAll(s.domainDir(domain))
}

// GetDomain retrieves a domain record if it exists.
func (s *Store) GetDomain(domain string) (*models.DomainRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	file := s.domainRecordFile(domain)
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	var rec models.DomainRecord
	if err := readJSON(file, &rec); err != nil {
		return nil, err
	}
	rec.EnsureTLSDefaults()
	return &rec, nil
}

// MutateDomain reads, applies the provided mutation, and persists the domain atomically.
func (s *Store) MutateDomain(domain string, mutate func(rec *models.DomainRecord) error) (*models.DomainRecord, error) {
	domain = strings.ToLower(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	file := s.domainRecordFile(domain)
	var rec models.DomainRecord
	if data, err := os.ReadFile(file); err == nil {
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err
		}
		rec.EnsureTLSDefaults()
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		rec.Domain = domain
		rec.EnsureTLSDefaults()
	}
	rec.Domain = domain

	if err := mutate(&rec); err != nil {
		return nil, err
	}
	rec.EnsureTLSDefaults()
	if err := writeJSONAtomic(file, rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetNodes returns infra nodes snapshot.
func (s *Store) GetNodes() ([]models.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path := s.nodesFile()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []models.Node{}, nil
		}
		return nil, err
	}
	var nodes []models.Node
	if err := readJSON(path, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// SaveNodes writes the nodes snapshot.
func (s *Store) SaveNodes(nodes []models.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range nodes {
		nodes[i].ComputeEdgeIPs()
	}
	return writeJSONAtomic(s.nodesFile(), nodes)
}

// WalkData executes fn for every file under the data dir.
func (s *Store) WalkData(fn func(path string, info fs.FileInfo) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filepath.WalkDir(s.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return fn(path, info)
	})
}
