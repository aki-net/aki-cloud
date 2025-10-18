package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type statusDocument struct {
	Nodes map[string]nodeStatus `json:"nodes"`
}

type nodeStatus struct {
	LastRunStarted   string `json:"last_run_started_at,omitempty"`
	LastRunCompleted string `json:"last_run_completed_at,omitempty"`
	LastResult       string `json:"last_result,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	LastBackupName   string `json:"last_backup_name,omitempty"`
	NextRunDue       string `json:"next_run_at,omitempty"`
}

func (s *Service) readStatus() (statusDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc := statusDocument{
		Nodes: make(map[string]nodeStatus),
	}
	path := s.statusPath
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return doc, nil
		}
		return doc, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return doc, err
	}
	if len(data) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return statusDocument{Nodes: make(map[string]nodeStatus)}, err
	}
	if doc.Nodes == nil {
		doc.Nodes = make(map[string]nodeStatus)
	}
	return doc, nil
}

func (s *Service) writeStatus(doc statusDocument) error {
	if doc.Nodes == nil {
		doc.Nodes = make(map[string]nodeStatus)
	}
	tmp := filepath.Join(filepath.Dir(s.statusPath), "status.json.tmp")
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.statusPath)
}

func (s *Service) markRunning(doc statusDocument, reason string, includes []string) (statusDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return doc, ErrBackupInProgress
	}
	now := s.clock().UTC()
	entry := doc.Nodes[s.cfg.NodeName]
	entry.LastRunStarted = now.Format(time.RFC3339)
	entry.LastResult = "running"
	entry.LastError = ""
	entry.NextRunDue = ""
	doc.Nodes[s.cfg.NodeName] = entry
	if err := s.writeStatus(doc); err != nil {
		return doc, err
	}
	s.running = true
	return doc, nil
}

func (s *Service) updateStatusAfterRun(doc statusDocument, result RunResult, runErr error, next time.Time) (statusDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := doc.Nodes[s.cfg.NodeName]
	if result.StartedAt.IsZero() {
		result.StartedAt = s.clock().UTC()
	}
	entry.LastRunStarted = result.StartedAt.UTC().Format(time.RFC3339)
	if !result.CompletedAt.IsZero() {
		entry.LastRunCompleted = result.CompletedAt.UTC().Format(time.RFC3339)
	}
	if runErr != nil {
		entry.LastResult = "failed"
		entry.LastError = runErr.Error()
	} else {
		entry.LastResult = "success"
		entry.LastError = ""
		entry.LastBackupName = result.BackupName
	}
	if !next.IsZero() {
		entry.NextRunDue = next.UTC().Format(time.RFC3339)
	}
	doc.Nodes[s.cfg.NodeName] = entry
	s.running = false
	return doc, s.writeStatus(doc)
}

func (s *Service) clearRunning() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

func (s *Service) buildStatus(settings nodeSettings, doc statusDocument) NodeStatus {
	entry := doc.Nodes[s.cfg.NodeName]
	status := NodeStatus{
		Enabled:        settings.Enabled(),
		HasCredentials: settings.HasCredentials(),
		Running:        s.running,
		Frequency:      settings.ScheduleRaw,
		Include:        settings.Include,
	}
	if entry.LastRunStarted != "" {
		if parsed, err := time.Parse(time.RFC3339, entry.LastRunStarted); err == nil {
			status.LastRunStarted = &parsed
		}
	}
	if entry.LastRunCompleted != "" {
		if parsed, err := time.Parse(time.RFC3339, entry.LastRunCompleted); err == nil {
			status.LastRunFinished = &parsed
		}
	}
	if entry.NextRunDue != "" {
		if parsed, err := time.Parse(time.RFC3339, entry.NextRunDue); err == nil {
			status.NextRunDue = &parsed
		}
	}
	status.LastResult = entry.LastResult
	status.LastError = entry.LastError
	status.LastBackupName = entry.LastBackupName
	return status
}
