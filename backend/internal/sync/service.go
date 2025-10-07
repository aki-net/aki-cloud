package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

// Digest represents a snapshot hash of important datasets.
type Digest struct {
	Domains map[string]models.ClockVersion `json:"domains"`
	Users   models.ClockVersion            `json:"users"`
	Nodes   models.ClockVersion            `json:"nodes"`
}

// Snapshot bundles the full dataset for synchronization.
type Snapshot struct {
	Domains []models.DomainRecord `json:"domains"`
	Users   []models.User         `json:"users"`
	Nodes   []models.Node         `json:"nodes"`
}

// Service coordinates data synchronization.
type Service struct {
	store   *store.Store
	dataDir string
	nodeID  string
	client  *http.Client
	secret  []byte
	baseURL string
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

// SetBaseURL configures the peer endpoint used for join/full sync.
func (s *Service) SetBaseURL(url string) {
	s.baseURL = strings.TrimSuffix(url, "/")
}

// ComputeDigest builds a digest representing local data state.
func (s *Service) ComputeDigest() (Digest, error) {
	domains, err := s.store.GetDomains()
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
	nodes, err := s.store.GetNodes()
	if err != nil {
		return Digest{}, err
	}
	userClock := aggregateClock(users, s.nodeID)
	nodeClock := aggregateClock(nodes, s.nodeID)
	return Digest{
		Domains: domainVersions,
		Users:   userClock,
		Nodes:   nodeClock,
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
	domains, err := s.store.GetDomains()
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
	return Snapshot{
		Domains: domains,
		Users:   users,
		Nodes:   nodes,
	}, nil
}

// ApplySnapshot merges remote data using last-write-wins semantics.
func (s *Service) ApplySnapshot(snapshot Snapshot) error {
	// merge domains
	localDomains, err := s.store.GetDomains()
	if err != nil {
		return err
	}
	domainMap := make(map[string]models.DomainRecord)
	for _, d := range localDomains {
		domainMap[d.Domain] = d
	}
	for _, remote := range snapshot.Domains {
		local := domainMap[remote.Domain]
		merged := mergeDomain(local, remote)
		if err := s.store.SaveDomain(merged); err != nil {
			return err
		}
	}

	// merge users
	if len(snapshot.Users) > 0 {
		if err := s.store.SaveUsers(snapshot.Users); err != nil {
			return err
		}
	}
	// merge nodes + peers
	if err := s.store.SaveNodes(snapshot.Nodes); err != nil {
		return err
	}
	if err := s.updatePeers(snapshot.Nodes); err != nil {
		return err
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
