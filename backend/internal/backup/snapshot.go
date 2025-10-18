package backup

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	mega "github.com/t3rm1n4l/go-mega"

	"aki-cloud/backend/internal/models"
)

type backupBundle struct {
	SchemaVersion string                     `json:"schema_version"`
	CreatedAt     time.Time                  `json:"created_at"`
	NodeID        string                     `json:"node_id"`
	NodeName      string                     `json:"node_name"`
	NSLabel       string                     `json:"ns_label"`
	NSBaseDomain  string                     `json:"ns_base_domain"`
	Includes      []string                   `json:"includes"`
	Domains       []models.DomainRecord      `json:"domains,omitempty"`
	Users         []models.User              `json:"users,omitempty"`
	Extensions    *models.ExtensionsState    `json:"extensions,omitempty"`
	Nodes         []models.Node              `json:"nodes,omitempty"`
	EdgeHealth    []models.EdgeHealthStatus  `json:"edge_health,omitempty"`
	Notes         map[string]string          `json:"notes,omitempty"`
	Metadata      map[string]interface{}     `json:"metadata,omitempty"`
	VersionInfo   map[string]string          `json:"version,omitempty"`
	Reserved      map[string]json.RawMessage `json:"reserved,omitempty"`
}

func (s *Service) buildBundle(ctx context.Context, includes []string) (backupBundle, error) {
	incSet := make(map[string]struct{}, len(includes))
	for _, item := range includes {
		incSet[item] = struct{}{}
	}
	bundle := backupBundle{
		SchemaVersion: schemaVersion,
		CreatedAt:     s.clock().UTC(),
		NodeID:        s.cfg.NodeID,
		NodeName:      s.cfg.NodeName,
		NSLabel:       s.cfg.NSLabel,
		NSBaseDomain:  s.cfg.NSBaseDomain,
		Includes:      includes,
		VersionInfo: map[string]string{
			"generator": "aki-cloud",
		},
	}

	if _, ok := incSet[DatasetDomains]; ok {
		domains, err := s.store.GetDomainsIncludingDeleted()
		if err != nil {
			return bundle, fmt.Errorf("collect domains: %w", err)
		}
		sort.Slice(domains, func(i, j int) bool {
			return domains[i].Domain < domains[j].Domain
		})
		bundle.Domains = domains
	}
	if _, ok := incSet[DatasetUsers]; ok {
		users, err := s.store.GetUsers()
		if err != nil {
			return bundle, fmt.Errorf("collect users: %w", err)
		}
		bundle.Users = users
	}
	if _, ok := incSet[DatasetExtensions]; ok {
		state, err := s.store.GetExtensionsState()
		if err != nil {
			return bundle, fmt.Errorf("collect extensions: %w", err)
		}
		bundle.Extensions = &state
	}
	if _, ok := incSet[DatasetNodes]; ok {
		nodes, err := s.store.GetNodesIncludingDeleted()
		if err != nil {
			return bundle, fmt.Errorf("collect nodes: %w", err)
		}
		bundle.Nodes = nodes
	}
	if _, ok := incSet[DatasetEdgeHealth]; ok {
		health, err := s.store.GetEdgeHealth()
		if err != nil {
			return bundle, fmt.Errorf("collect edge health: %w", err)
		}
		bundle.EdgeHealth = health
	}
	return bundle, nil
}

func (s *Service) writeBundle(bundle backupBundle) (string, int64, error) {
	filename := fmt.Sprintf("backup-%s-%s.json.gz", s.cfg.NodeName, bundle.CreatedAt.UTC().Format("20060102T150405Z"))
	path := filepath.Join(s.localDir, filename)
	temp := path + ".tmp"
	file, err := os.Create(temp)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()

	gz := gzip.NewWriter(file)
	gz.Name = strings.TrimSuffix(filename, ".gz")
	gz.ModTime = bundle.CreatedAt.UTC()
	encoder := json.NewEncoder(gz)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bundle); err != nil {
		_ = gz.Close()
		return "", 0, err
	}
	if err := gz.Close(); err != nil {
		return "", 0, err
	}
	if err := file.Close(); err != nil {
		return "", 0, err
	}
	if err := os.Rename(temp, path); err != nil {
		return "", 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	return path, info.Size(), nil
}

func readBundle(path string) (backupBundle, error) {
	file, err := os.Open(path)
	if err != nil {
		return backupBundle{}, err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return backupBundle{}, err
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		return backupBundle{}, err
	}
	var bundle backupBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return backupBundle{}, err
	}
	return bundle, nil
}

func (s *Service) uploadToMega(client *mega.Mega, localPath string, preferName string) (string, error) {
	name := strings.TrimSpace(preferName)
	if name == "" {
		name = filepath.Base(localPath)
	}
	targetParts := []string{
		s.cfg.NSBaseDomain,
		s.cfg.NSLabel,
		s.cfg.NodeName,
	}
	parent, err := ensurePath(client, targetParts)
	if err != nil {
		return "", err
	}
	if _, err := client.UploadFile(localPath, parent, name, nil); err != nil {
		return "", err
	}
	return name, nil
}

func (s *Service) enforceRetention(client *mega.Mega, settings nodeSettings) error {
	if settings.Retention <= 0 {
		return nil
	}
	parent, err := ensurePath(client, []string{
		s.cfg.NSBaseDomain,
		s.cfg.NSLabel,
		s.cfg.NodeName,
	})
	if err != nil {
		return err
	}
	files, err := collectFiles(client, parent)
	if err != nil {
		return err
	}
	if len(files) <= settings.Retention {
		return nil
	}
	for i := settings.Retention; i < len(files); i++ {
		if err := client.Delete(files[i], true); err != nil {
			return fmt.Errorf("delete old backup %s: %w", files[i].GetName(), err)
		}
	}
	return nil
}

func (s *Service) restoreDatasets(bundle backupBundle, req RestoreRequest) (RestoreResult, error) {
	result := RestoreResult{
		RestoredDatasets: make([]string, 0, len(req.Include)),
		StartedAt:        s.clock().UTC(),
	}
	incSet := make(map[string]struct{}, len(req.Include))
	for _, item := range req.Include {
		incSet[item] = struct{}{}
	}
	now := s.clock().UTC()
	seed := now.UnixNano()
	if _, ok := incSet[DatasetDomains]; ok {
		if req.WipeDomains {
			if err := wipeDirectory(filepath.Join(s.cfg.DataDir, "domains")); err != nil {
				return result, fmt.Errorf("wipe domains: %w", err)
			}
		}
		for _, domain := range bundle.Domains {
			domain.EnsureTLSDefaults()
			domain.EnsureCacheVersion()
			domain.Version.NodeID = s.cfg.NodeID
			domain.Version.Counter = s.nextVersionCounter(&seed)
			domain.Version.Updated = now.Unix()
			domain.UpdatedAt = now
			if err := s.store.SaveDomain(domain); err != nil {
				return result, fmt.Errorf("restore domain %s: %w", domain.Domain, err)
			}
			result.Domains++
		}
		result.RestoredDatasets = append(result.RestoredDatasets, DatasetDomains)
	}
	if _, ok := incSet[DatasetUsers]; ok && len(bundle.Users) > 0 {
		if req.WipeUsers {
			if err := s.store.SaveUsers([]models.User{}); err != nil {
				return result, fmt.Errorf("clear users: %w", err)
			}
		}
		if err := s.store.SaveUsers(bundle.Users); err != nil {
			return result, fmt.Errorf("restore users: %w", err)
		}
		result.Users = len(bundle.Users)
		result.RestoredDatasets = append(result.RestoredDatasets, DatasetUsers)
	}
	if _, ok := incSet[DatasetExtensions]; ok && bundle.Extensions != nil {
		if req.WipeExt {
			empty := models.ExtensionsState{}
			if err := s.store.SaveExtensionsState(empty); err != nil {
				return result, fmt.Errorf("clear extensions: %w", err)
			}
		}
		bundle.Extensions.Version.NodeID = s.cfg.NodeID
		bundle.Extensions.Version.Counter = s.nextVersionCounter(&seed)
		bundle.Extensions.Version.Updated = now.Unix()
		if err := s.store.SaveExtensionsState(*bundle.Extensions); err != nil {
			return result, fmt.Errorf("restore extensions: %w", err)
		}
		result.Extensions = true
		result.RestoredDatasets = append(result.RestoredDatasets, DatasetExtensions)
	}
	if _, ok := incSet[DatasetNodes]; ok && len(bundle.Nodes) > 0 {
		if req.WipeNodes {
			if err := s.store.SaveNodes([]models.Node{}); err != nil {
				return result, fmt.Errorf("clear nodes: %w", err)
			}
		}
		nodes := make([]models.Node, 0, len(bundle.Nodes))
		for _, node := range bundle.Nodes {
			node.Version.NodeID = s.cfg.NodeID
			node.Version.Counter = s.nextVersionCounter(&seed)
			node.Version.Updated = now.Unix()
			if node.UpdatedAt.IsZero() || node.UpdatedAt.Before(now) {
				node.UpdatedAt = now
			}
			node.ComputeEdgeIPs()
			nodes = append(nodes, node)
		}
		if err := s.store.SaveNodes(nodes); err != nil {
			return result, fmt.Errorf("restore nodes: %w", err)
		}
		result.Nodes = len(bundle.Nodes)
		result.RestoredDatasets = append(result.RestoredDatasets, DatasetNodes)
	}
	if _, ok := incSet[DatasetEdgeHealth]; ok && len(bundle.EdgeHealth) > 0 {
		if req.WipeEdge {
			if err := s.store.SaveEdgeHealth([]models.EdgeHealthStatus{}); err != nil {
				return result, fmt.Errorf("clear edge health: %w", err)
			}
		}
		health := make([]models.EdgeHealthStatus, 0, len(bundle.EdgeHealth))
		for _, status := range bundle.EdgeHealth {
			status.Version.NodeID = s.cfg.NodeID
			status.Version.Counter = s.nextVersionCounter(&seed)
			status.Version.Updated = now.Unix()
			health = append(health, status)
		}
		if err := s.store.SaveEdgeHealth(health); err != nil {
			return result, fmt.Errorf("restore edge health: %w", err)
		}
		result.EdgeHealth = len(bundle.EdgeHealth)
		result.RestoredDatasets = append(result.RestoredDatasets, DatasetEdgeHealth)
	}
	result.CompletedAt = s.clock().UTC()
	return result, nil
}

func wipeDirectory(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0o755)
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return os.MkdirAll(path, 0o755)
}
