package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

// Digest represents a snapshot hash of important datasets.
type Digest struct {
	Domains    map[string]models.ClockVersion `json:"domains"`
	Users      models.ClockVersion            `json:"users"`
	Nodes      models.ClockVersion            `json:"nodes"`
	EdgeHealth map[string]models.ClockVersion `json:"edge_health"`
}

// Snapshot bundles the full dataset for synchronization.
type Snapshot struct {
	Domains    []models.DomainRecord     `json:"domains"`
	Users      []models.User             `json:"users"`
	Nodes      []models.Node             `json:"nodes"`
	EdgeHealth []models.EdgeHealthStatus `json:"edge_health"`
}

// Service coordinates data synchronization.
type Service struct {
	store    *store.Store
	dataDir  string
	nodeID   string
	client   *http.Client
	secret   []byte
	baseURL  string
	onChange func()
}

// New creates a new sync service.
func New(st *store.Store, dataDir string, nodeID string, secret []byte) *Service {
	return &Service{
		store:   st,
		dataDir: dataDir,
		nodeID:  nodeID,
		client:  &http.Client{Timeout: 10 * time.Second},
		secret:  secret,
	}
}

// SetChangeHandler registers a callback invoked when remote data alters local state.
func (s *Service) SetChangeHandler(fn func()) {
	s.onChange = fn
}

func (s *Service) notifyChange() {
	if s.onChange != nil {
		s.onChange()
	}
}

// SetBaseURL configures the peer endpoint used for join/full sync.
func (s *Service) SetBaseURL(url string) {
	s.baseURL = strings.TrimSuffix(url, "/")
}

// ComputeDigest builds a digest representing local data state.
func (s *Service) ComputeDigest() (Digest, error) {
	domains, err := s.store.GetDomainsIncludingDeleted()
	if err != nil {
		return Digest{}, err
	}
	domainVersions := make(map[string]models.ClockVersion, len(domains))
	for _, d := range domains {
		domainVersions[d.Domain] = d.Version
	}

	users, err := s.store.GetUsers()
	if err != nil {
		return Digest{}, err
	}
	nodes, err := s.store.GetNodesIncludingDeleted()
	if err != nil {
		return Digest{}, err
	}
	healthStatuses, err := s.store.GetEdgeHealth()
	if err != nil {
		return Digest{}, err
	}
	userClock := aggregateClock(users, s.nodeID)
	nodeClock := aggregateClock(nodes, s.nodeID)
	healthClock := make(map[string]models.ClockVersion, len(healthStatuses))
	for _, status := range healthStatuses {
		healthClock[status.IP] = status.Version
	}
	return Digest{
		Domains:    domainVersions,
		Users:      userClock,
		Nodes:      nodeClock,
		EdgeHealth: healthClock,
	}, nil
}

func aggregateClock[T any](items []T, nodeID string) models.ClockVersion {
	payload, _ := json.Marshal(items)
	checksumBytes := sha256.Sum256(payload)
	return models.ClockVersion{
		Counter:  int64(len(items)),
		NodeID:   nodeID,
		Updated:  time.Now().UTC().Unix(),
		Checksum: hex.EncodeToString(checksumBytes[:]),
	}
}

// BuildSnapshot collects all data for transfer.
func (s *Service) BuildSnapshot() (Snapshot, error) {
	domains, err := s.store.GetDomainsIncludingDeleted()
	if err != nil {
		return Snapshot{}, err
	}
	users, err := s.store.GetUsers()
	if err != nil {
		return Snapshot{}, err
	}
	nodes, err := s.store.GetNodes()
	if err != nil {
		return Snapshot{}, err
	}
	healthStatuses, err := s.store.GetEdgeHealth()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Domains:    domains,
		Users:      users,
		Nodes:      nodes,
		EdgeHealth: healthStatuses,
	}, nil
}

// ApplySnapshot merges remote data using last-write-wins semantics.
func (s *Service) ApplySnapshot(snapshot Snapshot) error {
	// merge domains
	localDomains, err := s.store.GetDomainsIncludingDeleted()
	if err != nil {
		return err
	}
	domainMap := make(map[string]models.DomainRecord)
	for _, d := range localDomains {
		domainMap[d.Domain] = d
	}
	changed := false
	for _, remote := range snapshot.Domains {
		local := domainMap[remote.Domain]
		merged := mergeDomain(local, remote)
		if err := s.store.SaveDomain(merged); err != nil {
			return err
		}
		if merged.Domain != "" {
			changed = true
		}
	}

	// merge users
	if len(snapshot.Users) > 0 {
		if err := s.store.SaveUsers(snapshot.Users); err != nil {
			return err
		}
		changed = true
	}
	// merge nodes + peers
	localNodes, err := s.store.GetNodesIncludingDeleted()
	if err != nil {
		return err
	}
	mergedNodes := mergeNodes(localNodes, snapshot.Nodes)
	if err := s.store.SaveNodes(mergedNodes); err != nil {
		return err
	}
	activeNodes := filterActiveNodes(mergedNodes)
	for _, node := range mergedNodes {
		if node.ID == s.nodeID {
			if err := s.store.SaveLocalNodeSnapshot(node); err != nil {
				log.Printf("sync: save local node snapshot failed: %v", err)
			}
			break
		}
	}
	s.bootstrapPendingEdgeHealth(activeNodes)
	if err := s.updatePeers(activeNodes); err != nil {
		return err
	}
	if len(snapshot.Nodes) > 0 {
		changed = true
	}

	localHealthMap, err := s.store.GetEdgeHealthMap()
	if err != nil {
		return err
	}
	healthChanged := false
	for _, remote := range snapshot.EdgeHealth {
		local := localHealthMap[remote.IP]
		merged := models.MergeEdgeHealth(local, remote)
		if merged.IP == "" {
			continue
		}
		if err := s.store.UpsertEdgeHealth(merged); err != nil {
			return err
		}
		if merged.Healthy != local.Healthy || merged.FailureCount != local.FailureCount || merged.Message != local.Message || merged.Version != local.Version {
			healthChanged = true
		}
		delete(localHealthMap, remote.IP)
	}
	if healthChanged {
		changed = true
	}
	if changed {
		s.notifyChange()
	}
	return nil
}

// mergeDomain chooses between local and remote domain records.
func mergeDomain(local models.DomainRecord, remote models.DomainRecord) models.DomainRecord {
	if local.Domain == "" {
		return remote
	}
	lver := local.Version
	rver := remote.Version
	result := models.MergeClock(lver, rver)
	if result == rver {
		return remote
	}
	return local
}

func mergeNodes(local []models.Node, remote []models.Node) []models.Node {
	merged := make(map[string]models.Node, len(local)+len(remote))
	for _, node := range local {
		if node.ID == "" {
			continue
		}
		node.ComputeEdgeIPs()
		merged[node.ID] = node
	}
	for _, node := range remote {
		if node.ID == "" {
			continue
		}
		node.ComputeEdgeIPs()
		if existing, ok := merged[node.ID]; ok {
			if existing.Version.Counter == 0 && node.Version.Counter == 0 {
				if node.UpdatedAt.After(existing.UpdatedAt) {
					merged[node.ID] = node
				}
				continue
			}
			winner := models.MergeClock(existing.Version, node.Version)
			if winner == node.Version {
				merged[node.ID] = node
			}
			continue
		}
		merged[node.ID] = node
	}
	out := make([]models.Node, 0, len(merged))
	for _, node := range merged {
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func filterActiveNodes(nodes []models.Node) []models.Node {
	active := make([]models.Node, 0, len(nodes))
	for _, node := range nodes {
		if !node.DeletedAt.IsZero() {
			continue
		}
		active = append(active, node)
	}
	return active
}

// PullFromPeer fetches a snapshot from a peer URL.
func (s *Service) PullFromPeer(ctx context.Context, baseURL string) error {
	if baseURL == "" {
		baseURL = s.baseURL
	}
	if baseURL == "" {
		return errors.New("peer base url not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/sync/pull", baseURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", s.authHeader())
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var snapshot Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		return err
	}
	return s.ApplySnapshot(snapshot)
}

func (s *Service) authHeader() string {
	return fmt.Sprintf("Bearer %s", hex.EncodeToString(s.secret))
}

// ValidatePeerRequest ensures the cluster shared secret matches.
func (s *Service) ValidatePeerRequest(r *http.Request) bool {
	authz := r.Header.Get("Authorization")
	expected := s.authHeader()
	return authz == expected
}

func (s *Service) updatePeers(nodes []models.Node) error {
	unique := make(map[string]struct{}, len(nodes))
	peers := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if !node.DeletedAt.IsZero() {
			continue
		}
		if node.ID == s.nodeID {
			continue
		}
		endpoint := strings.TrimSpace(node.APIEndpoint)
		if endpoint == "" {
			continue
		}
		if _, ok := unique[endpoint]; ok {
			continue
		}
		unique[endpoint] = struct{}{}
		peers = append(peers, endpoint)
	}
	sort.Strings(peers)
	return s.store.SavePeers(peers)
}

func (s *Service) bootstrapPendingEdgeHealth(nodes []models.Node) {
	healthMap, err := s.store.GetEdgeHealthMap()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, node := range nodes {
		node.ComputeEdgeIPs()
		for _, ip := range node.EdgeIPs {
			if _, exists := healthMap[ip]; exists {
				continue
			}
			status := models.EdgeHealthStatus{
				IP:           ip,
				Healthy:      false,
				LastChecked:  time.Time{},
				FailureCount: 0,
				Message:      "awaiting first health check",
				Version: models.ClockVersion{
					Counter: 1,
					NodeID:  s.nodeID,
					Updated: now.Unix(),
				},
			}
			if err := s.store.UpsertEdgeHealth(status); err == nil {
				healthMap[ip] = status
			}
		}
	}
}
