package backup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	mega "github.com/t3rm1n4l/go-mega"

	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/extensions"
	"aki-cloud/backend/internal/store"
)

// Supported dataset names for backup/restore operations.
const (
	DatasetDomains     = "domains"
	DatasetUsers       = "users"
	DatasetExtensions  = "extensions"
	DatasetNodes       = "nodes"
	DatasetEdgeHealth  = "edge_health"
	DatasetSearchBots  = "searchbot"
	DefaultScheduleRaw = "24h"
	defaultRetention   = 14
	schemaVersion      = "1.0"
)

var (
	ErrBackupsDisabled    = errors.New("backups disabled for this node")
	ErrCredentialsMissing = errors.New("mega credentials not configured")
	ErrBackupInProgress   = errors.New("backup already running")
	ErrUnknownDataset     = errors.New("unknown dataset requested")
)

// RunRequest controls manual backup execution.
type RunRequest struct {
	Include []string
	Force   bool
	Reason  string
}

// RunResult captures artefacts from a backup run.
type RunResult struct {
	BackupName  string
	Includes    []string
	Bytes       int64
	Uploaded    bool
	LocalPath   string
	StartedAt   time.Time
	CompletedAt time.Time
}

// RestoreRequest describes a restore operation.
type RestoreRequest struct {
	BackupName  string
	Include     []string
	WipeDomains bool
	WipeUsers   bool
	WipeExt     bool
	WipeNodes   bool
	WipeEdge    bool
}

// RestoreResult summarises datasets restored.
type RestoreResult struct {
	RestoredDatasets []string
	Domains          int
	Users            int
	Extensions       bool
	Nodes            int
	EdgeHealth       int
	StartedAt        time.Time
	CompletedAt      time.Time
}

// BackupDescriptor advertises remote backup artefacts.
type BackupDescriptor struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	Includes  []string  `json:"includes,omitempty"`
}

// NodeStatus exposes scheduling metadata for the local node.
type NodeStatus struct {
	Enabled         bool       `json:"enabled"`
	HasCredentials  bool       `json:"has_credentials"`
	Running         bool       `json:"running"`
	LastRunStarted  *time.Time `json:"last_run_started_at,omitempty"`
	LastRunFinished *time.Time `json:"last_run_completed_at,omitempty"`
	LastResult      string     `json:"last_result,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	LastBackupName  string     `json:"last_backup_name,omitempty"`
	NextRunDue      *time.Time `json:"next_run_at,omitempty"`
	Frequency       string     `json:"frequency"`
	Include         []string   `json:"include"`
}

// Service wires extension configuration, Mega uploads, and dataset extraction.
type Service struct {
	cfg        *config.Config
	store      *store.Store
	extensions *extensions.Service

	localDir   string
	statusPath string

	mu      sync.Mutex
	running bool

	loginFn megaLoginFunc
	clock   func() time.Time
	logger  *log.Logger
}

// New constructs a backup service for the node.
func New(cfg *config.Config, st *store.Store, ext *extensions.Service) (*Service, error) {
	if cfg == nil || st == nil {
		return nil, errors.New("backup: config and store required")
	}
	localDir := filepath.Join(cfg.DataDir, "backups")
	statusDir := filepath.Join(cfg.DataDir, "cluster", "backups")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return nil, fmt.Errorf("backup: create local dir: %w", err)
	}
	if err := os.MkdirAll(statusDir, 0o755); err != nil {
		return nil, fmt.Errorf("backup: create status dir: %w", err)
	}
	svc := &Service{
		cfg:        cfg,
		store:      st,
		extensions: ext,
		localDir:   localDir,
		statusPath: filepath.Join(statusDir, "status.json"),
		loginFn:    loginToMega,
		clock:      time.Now,
		logger:     log.New(os.Stdout, "backup ", log.LstdFlags),
	}
	return svc, nil
}

// Start launches the scheduling loop. Non-blocking.
func (s *Service) Start(ctx context.Context) {
	if s.extensions == nil {
		s.logger.Printf("mega-backups: extensions service unavailable; skipping scheduler")
		return
	}
	go s.scheduler(ctx)
}

// Trigger executes a backup immediately according to the request parameters.
func (s *Service) Trigger(ctx context.Context, req RunRequest) (RunResult, error) {
	settings, status, err := s.loadConfig()
	if err != nil {
		return RunResult{}, err
	}
	if !settings.Enabled() && !req.Force {
		return RunResult{}, ErrBackupsDisabled
	}
	if !settings.HasCredentials() {
		return RunResult{}, ErrCredentialsMissing
	}
	includes, err := s.resolveIncludes(req.Include, settings.Include)
	if err != nil {
		return RunResult{}, err
	}

	status, err = s.markRunning(status, "manual", includes)
	if err != nil {
		return RunResult{}, err
	}
	defer s.clearRunning()

	result, execErr := s.executeBackup(ctx, settings, status, includes)
	return result, execErr
}

// List enumerates available backups in remote storage for this node.
func (s *Service) List(ctx context.Context) ([]BackupDescriptor, error) {
	settings, _, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	if !settings.HasCredentials() {
		return nil, ErrCredentialsMissing
	}
	client, cleanup, err := s.login(ctx, settings)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return s.listRemote(ctx, client)
}

// Restore downloads a backup artefact and applies selected datasets.
func (s *Service) Restore(ctx context.Context, req RestoreRequest) (RestoreResult, error) {
	settings, _, err := s.loadConfig()
	if err != nil {
		return RestoreResult{}, err
	}
	if !settings.HasCredentials() {
		return RestoreResult{}, ErrCredentialsMissing
	}
	includes, err := s.resolveIncludes(req.Include, nil)
	if err != nil {
		return RestoreResult{}, err
	}

	client, cleanup, err := s.login(ctx, settings)
	if err != nil {
		return RestoreResult{}, err
	}
	defer cleanup()

	return s.restoreFromRemote(ctx, client, req, includes)
}

// Status exposes scheduler metadata for UI consumption.
func (s *Service) Status() (NodeStatus, error) {
	settings, status, err := s.loadConfig()
	if err != nil {
		return NodeStatus{}, err
	}
	return s.buildStatus(settings, status), nil
}

// scheduler wakes periodically and launches backups when due.
func (s *Service) scheduler(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		if err := s.tryScheduled(ctx); err != nil {
			s.logger.Printf("mega-backups: scheduled run skipped: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) resolveIncludes(requested, defaultSet []string) ([]string, error) {
	base := defaultSet
	if len(requested) > 0 {
		base = requested
	}
	outSet := make(map[string]struct{}, len(base)+1)
	for _, item := range base {
		normalised := normaliseDataset(item)
		if normalised == "" {
			return nil, fmt.Errorf("%w: %s", ErrUnknownDataset, item)
		}
		outSet[normalised] = struct{}{}
	}
	outSet[DatasetDomains] = struct{}{}
	includes := make([]string, 0, len(outSet))
	for key := range outSet {
		includes = append(includes, key)
	}
	sort.Strings(includes)
	return includes, nil
}

func (s *Service) executeBackup(ctx context.Context, settings nodeSettings, doc statusDocument, includes []string) (RunResult, error) {
	result := RunResult{
		Includes:  includes,
		StartedAt: s.clock().UTC(),
	}
	var execErr error
	defer func() {
		if result.LocalPath != "" && !result.Uploaded {
			if err := os.Remove(result.LocalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.logger.Printf("mega-backups: failed to remove local artefact %s: %v", result.LocalPath, err)
			}
		}
	}()
	defer func() {
		next := s.clock().UTC().Add(settings.Schedule)
		if _, err := s.updateStatusAfterRun(doc, result, execErr, next); err != nil {
			s.logger.Printf("mega-backups: failed to persist status: %v", err)
		}
	}()

	bundle, err := s.buildBundle(ctx, includes)
	if err != nil {
		execErr = err
		return result, err
	}
	localPath, size, err := s.writeBundle(bundle)
	if err != nil {
		execErr = err
		return result, err
	}
	result.LocalPath = localPath
	result.Bytes = size

	client, cleanup, err := s.login(ctx, settings)
	if err != nil {
		execErr = err
		return result, err
	}
	defer cleanup()

	remoteName, err := s.uploadToMega(client, localPath)
	if err != nil {
		execErr = err
		return result, err
	}
	result.BackupName = remoteName
	result.Uploaded = true
	if err := s.enforceRetention(client, settings); err != nil {
		s.logger.Printf("mega-backups: retention enforcement failed: %v", err)
	}
	if err := os.Remove(localPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Printf("mega-backups: remove local artefact failed: %v", err)
	}
	result.CompletedAt = s.clock().UTC()
	execErr = nil
	return result, nil
}

func (s *Service) listRemote(ctx context.Context, client *mega.Mega) ([]BackupDescriptor, error) {
	parent, err := ensurePath(client, []string{s.cfg.NSBaseDomain, s.cfg.NSLabel, s.cfg.NodeName})
	if err != nil {
		return nil, err
	}
	files, err := collectFiles(client, parent)
	if err != nil {
		return nil, err
	}
	descriptors := make([]BackupDescriptor, 0, len(files))
	for _, file := range files {
		descriptors = append(descriptors, BackupDescriptor{
			Name:      file.GetName(),
			SizeBytes: file.GetSize(),
			CreatedAt: file.GetTimeStamp(),
		})
	}
	return descriptors, nil
}

func (s *Service) restoreFromRemote(ctx context.Context, client *mega.Mega, req RestoreRequest, includes []string) (RestoreResult, error) {
	parent, err := ensurePath(client, []string{s.cfg.NSBaseDomain, s.cfg.NSLabel, s.cfg.NodeName})
	if err != nil {
		return RestoreResult{}, err
	}
	files, err := collectFiles(client, parent)
	if err != nil {
		return RestoreResult{}, err
	}
	var target *mega.Node
	for _, node := range files {
		if node.GetName() == req.BackupName {
			target = node
			break
		}
	}
	if target == nil {
		return RestoreResult{}, fmt.Errorf("backup %s not found", req.BackupName)
	}
	tempPath := filepath.Join(s.localDir, fmt.Sprintf("restore-%s", target.GetName()))
	defer os.Remove(tempPath)
	if err := client.DownloadFile(target, tempPath, nil); err != nil {
		return RestoreResult{}, fmt.Errorf("download %s: %w", target.GetName(), err)
	}
	bundle, err := readBundle(tempPath)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("read backup bundle: %w", err)
	}
	req.Include = includes
	result, err := s.restoreDatasets(bundle, req)
	if err != nil {
		return RestoreResult{}, err
	}
	return result, nil
}

func (s *Service) tryScheduled(ctx context.Context) error {
	settings, doc, err := s.loadConfig()
	if err != nil {
		return err
	}
	if !settings.Enabled() {
		return nil
	}
	if !settings.HasCredentials() {
		return ErrCredentialsMissing
	}
	if s.running {
		return nil
	}
	entry := doc.Nodes[s.cfg.NodeName]
	now := s.clock().UTC()
	var nextRun time.Time
	if entry.NextRunDue != "" {
		if parsed, err := time.Parse(time.RFC3339, entry.NextRunDue); err == nil {
			nextRun = parsed
		}
	}
	if nextRun.IsZero() && entry.LastRunCompleted != "" {
		if parsed, err := time.Parse(time.RFC3339, entry.LastRunCompleted); err == nil {
			nextRun = parsed.Add(settings.Schedule)
		}
	}
	if nextRun.IsZero() {
		nextRun = now
	}
	if now.Before(nextRun) {
		return nil
	}
	doc, err = s.markRunning(doc, "scheduled", settings.Include)
	if err != nil {
		return err
	}
	defer s.clearRunning()
	_, execErr := s.executeBackup(ctx, settings, doc, settings.Include)
	return execErr
}
