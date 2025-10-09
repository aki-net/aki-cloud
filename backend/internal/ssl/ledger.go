package ssl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type issuanceLedger struct {
	path string
	mu   sync.Mutex
}

func newIssuanceLedger(dataDir string) *issuanceLedger {
	path := filepath.Join(dataDir, "cluster", "acme_issuance.json")
	return &issuanceLedger{path: path}
}

func (l *issuanceLedger) reserve(limit int, window time.Duration, now time.Time) (bool, time.Time, error) {
	if limit <= 0 || window <= 0 {
		return true, time.Time{}, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.load()
	if err != nil {
		return false, time.Time{}, err
	}

	cutoff := now.Add(-window)
	pruned := make([]time.Time, 0, len(entries))
	for _, ts := range entries {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	sort.Slice(pruned, func(i, j int) bool { return pruned[i].Before(pruned[j]) })

	if len(pruned) >= limit {
		next := pruned[0].Add(window)
		if err := l.save(pruned); err != nil {
			return false, time.Time{}, err
		}
		return false, next, nil
	}

	pruned = append(pruned, now.UTC())
	sort.Slice(pruned, func(i, j int) bool { return pruned[i].Before(pruned[j]) })
	if err := l.save(pruned); err != nil {
		return false, time.Time{}, err
	}
	return true, time.Time{}, nil
}

func (l *issuanceLedger) load() ([]time.Time, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []time.Time{}, nil
		}
		return nil, err
	}
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, len(raw))
	for _, item := range raw {
		if item == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339, item); err == nil {
			out = append(out, ts.UTC())
		}
	}
	return out, nil
}

func (l *issuanceLedger) save(entries []time.Time) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	raw := make([]string, 0, len(entries))
	for _, ts := range entries {
		raw = append(raw, ts.UTC().Format(time.RFC3339))
	}
	payload, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}
