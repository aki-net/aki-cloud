package store

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
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

func (s *Store) loginAttemptsFile() string {
	return filepath.Join(s.dataDir, "users", "login_attempts.json")
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

func (s *Store) nodeOverridesFile() string {
	return filepath.Join(s.dataDir, "infra", "node_overrides.json")
}

func (s *Store) edgeHealthFile() string {
	return filepath.Join(s.dataDir, "cluster", "edge_health.json")
}

func (s *Store) nameServerStatusFile() string {
	return filepath.Join(s.dataDir, "infra", "nameserver_status.json")
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

// PruneEdgeHealthByNodes removes edge health entries that do not belong to the provided nodes.
func (s *Store) PruneEdgeHealthByNodes(nodes []models.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	active := make(map[string]struct{})
	for _, node := range nodes {
		node.ComputeEdgeIPs()
		for _, ip := range node.EdgeIPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			active[ip] = struct{}{}
		}
	}

	path := s.edgeHealthFile()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var statuses []models.EdgeHealthStatus
	if err := readJSON(path, &statuses); err != nil {
		return err
	}
	pruned := make([]models.EdgeHealthStatus, 0, len(statuses))
	for _, st := range statuses {
		if _, ok := active[st.IP]; !ok {
			continue
		}
		pruned = append(pruned, st)
	}
	return writeJSONAtomic(path, pruned)
}

// GetNameServerStatus returns the cached nameserver health results.
func (s *Store) GetNameServerStatus() ([]models.NameServerHealth, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path := s.nameServerStatusFile()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return []models.NameServerHealth{}, nil
		}
		return nil, err
	}
	var statuses []models.NameServerHealth
	if err := readJSON(path, &statuses); err != nil {
		return nil, err
	}
	return statuses, nil
}

// SaveNameServerStatus persists nameserver health results atomically.
func (s *Store) SaveNameServerStatus(statuses []models.NameServerHealth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONAtomic(s.nameServerStatusFile(), statuses)
}

// GetDomains returns all domain records.
func (s *Store) GetDomains() ([]models.DomainRecord, error) {
	all, err := s.GetDomainsIncludingDeleted()
	if err != nil {
		return nil, err
	}
	active := make([]models.DomainRecord, 0, len(all))
	for _, rec := range all {
		if rec.IsDeleted() {
			continue
		}
		active = append(active, rec)
	}
	return active, nil
}

// GetDomainsIncludingDeleted returns all domain records, including tombstones.
func (s *Store) GetDomainsIncludingDeleted() ([]models.DomainRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadDomainsLocked()
}

func (s *Store) loadDomainsLocked() ([]models.DomainRecord, error) {
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
		rec.Domain = strings.ToLower(domain)
		records = append(records, rec)
	}
	return records, nil
}

// SaveDomain persists a single domain record.
func (s *Store) SaveDomain(record models.DomainRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record.EnsureTLSDefaults()
	path := s.domainRecordFile(record.Domain)
	if record.Domain == "" {
		log.Printf("store: refusing to persist domain with empty name")
		return nil
	}
	if record.Owner == "" && record.OriginIP == "" && record.DeletedAt.IsZero() {
		log.Printf("store: refusing to persist incomplete domain %s (missing owner/origin)", record.Domain)
		return nil
	}
	if err := writeJSONAtomic(path, record); err != nil {
		log.Printf("store: save domain %s failed: %v", record.Domain, err)
		return err
	}
	log.Printf("store: saved domain %s (owner=%s)", record.Domain, record.Owner)
	return nil
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
	rec.Domain = strings.ToLower(domain)
	if rec.IsDeleted() {
		return nil, fs.ErrNotExist
	}
	return &rec, nil
}

// GetDomainIncludingDeleted retrieves a domain record even if it has been tombstoned.
func (s *Store) GetDomainIncludingDeleted(domain string) (*models.DomainRecord, error) {
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
	rec.Domain = strings.ToLower(domain)
	return &rec, nil
}

// MutateDomain reads, applies the provided mutation, and persists the domain atomically.
func (s *Store) MutateDomain(domain string, mutate func(rec *models.DomainRecord) error) (*models.DomainRecord, error) {
	domain = strings.ToLower(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	file := s.domainRecordFile(domain)
	var rec models.DomainRecord
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	rec.EnsureTLSDefaults()
	rec.Domain = domain
	if rec.IsDeleted() {
		return nil, fs.ErrNotExist
	}

	if err := mutate(&rec); err != nil {
		return nil, err
	}
	rec.EnsureTLSDefaults()
	rec.Domain = domain
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if err := writeJSONAtomic(file, rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetNodes returns infra nodes snapshot.
func (s *Store) GetNodes() ([]models.Node, error) {
	nodes, err := s.GetNodesIncludingDeleted()
	if err != nil {
		return nil, err
	}
	active := make([]models.Node, 0, len(nodes))
	for _, node := range nodes {
		if !node.DeletedAt.IsZero() {
			continue
		}
		active = append(active, node)
	}
	return active, nil
}

// GetNodesIncludingDeleted returns all nodes, including soft-deleted entries.
func (s *Store) GetNodesIncludingDeleted() ([]models.Node, error) {
	s.mu.RLock()
	nodes, err := s.readNodesLocked()
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	return s.applyNodeOverrides(nodes), nil
}

func (s *Store) readNodesLocked() ([]models.Node, error) {
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
	for i := range nodes {
		nodes[i].ComputeEdgeIPs()
	}
	return nodes, nil
}

// SaveNodes writes the nodes snapshot.
func (s *Store) SaveNodes(nodes []models.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nodes = dedupeNodes(nodes)
	for i := range nodes {
		nodes[i].ComputeEdgeIPs()
		nodes[i].Status = ""
		nodes[i].StatusMsg = ""
		nodes[i].HealthyEdges = 0
		nodes[i].TotalEdges = 0
		nodes[i].LastHealthAt = time.Time{}
	}
	return writeJSONAtomic(s.nodesFile(), nodes)
}

type nodeOverride struct {
	EdgeManual bool     `json:"edge_manual,omitempty"`
	EdgeIPs    []string `json:"edge_ips,omitempty"`
	NSManual   bool     `json:"ns_manual,omitempty"`
	NSIPs      []string `json:"ns_ips,omitempty"`
}

func (s *Store) loadNodeOverrides() (map[string]nodeOverride, error) {
	path := s.nodeOverridesFile()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]nodeOverride), nil
		}
		return nil, err
	}
	var overrides map[string]nodeOverride
	if err := json.Unmarshal(data, &overrides); err != nil {
		return nil, err
	}
	if overrides == nil {
		overrides = make(map[string]nodeOverride)
	}
	return overrides, nil
}

func (s *Store) saveNodeOverrides(overrides map[string]nodeOverride) error {
	path := s.nodeOverridesFile()
	if len(overrides) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeJSONAtomic(path, overrides)
}

func (s *Store) applyNodeOverrides(nodes []models.Node) []models.Node {
	// No longer using manual overrides, just compute edge IPs
	for i := range nodes {
		nodes[i].ComputeEdgeIPs()
	}
	return nodes
}

// SaveLocalNodeSnapshot persists the simplified local node metadata for helper scripts.
func (s *Store) SaveLocalNodeSnapshot(node models.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := map[string]interface{}{
		"name":           node.Name,
		"node_id":        node.ID,
		"ips":            node.IPs,
		"ns_ips":         node.NSIPs,
		"edge_ips":       node.EdgeIPs,
		"ns_label":       node.NSLabel,
		"ns_base_domain": node.NSBase,
		"api_endpoint":   node.APIEndpoint,
	}
	path := filepath.Join(s.dataDir, "cluster", "node.json")
	return writeJSONAtomic(path, snapshot)
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

func dedupeNodes(nodes []models.Node) []models.Node {
	if len(nodes) <= 1 {
		return nodes
	}
	type chosen struct {
		index int
		node  models.Node
	}
	byName := make(map[string]chosen, len(nodes))
	out := make([]models.Node, 0, len(nodes))
	for _, node := range nodes {
		nameKey := strings.ToLower(strings.TrimSpace(node.Name))
		if nameKey == "" {
			out = append(out, node)
			continue
		}
		if existing, ok := byName[nameKey]; ok {
			if preferNode(node, existing.node) {
				out[existing.index] = node
				byName[nameKey] = chosen{index: existing.index, node: node}
			}
			continue
		}
		byName[nameKey] = chosen{index: len(out), node: node}
		out = append(out, node)
	}
	return out
}

func preferNode(candidate, current models.Node) bool {
	if current.IsDeleted() && candidate.IsDeleted() {
		return compareTimestamps(candidate.DeletedAt, current.DeletedAt)
	}
	if current.IsDeleted() != candidate.IsDeleted() {
		return !candidate.IsDeleted()
	}
	if !candidate.UpdatedAt.Equal(current.UpdatedAt) {
		return candidate.UpdatedAt.After(current.UpdatedAt)
	}
	if candidate.Version.Counter != current.Version.Counter {
		return candidate.Version.Counter > current.Version.Counter
	}
	return strings.Compare(candidate.ID, current.ID) > 0
}

func compareTimestamps(a, b time.Time) bool {
	if a.Equal(b) {
		return false
	}
	return a.After(b)
}
