package backup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"aki-cloud/backend/internal/extensions"
	"aki-cloud/backend/internal/models"
)

type nodeSettings struct {
	GlobalEnabled bool
	NodeEnabled   bool
	Username      string
	Password      string
	ScheduleRaw   string
	Schedule      time.Duration
	Include       []string
	Retention     int
}

func (cfg nodeSettings) Enabled() bool {
	return cfg.GlobalEnabled && cfg.NodeEnabled
}

func (cfg nodeSettings) HasCredentials() bool {
	return strings.TrimSpace(cfg.Username) != "" && strings.TrimSpace(cfg.Password) != ""
}

func (cfg nodeSettings) HasSchedule() bool {
	return cfg.Schedule > 0
}

func (cfg nodeSettings) includeSet() map[string]struct{} {
	out := make(map[string]struct{}, len(cfg.Include))
	for _, item := range cfg.Include {
		item = normaliseDataset(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	return out
}

func (cfg nodeSettings) validate() error {
	if len(cfg.Include) == 0 {
		return errors.New("no datasets configured")
	}
	if _, ok := cfg.includeSet()[DatasetDomains]; !ok {
		return errors.New("domains dataset must always be included")
	}
	if cfg.Retention <= 0 {
		return fmt.Errorf("retention must be > 0 (got %d)", cfg.Retention)
	}
	return nil
}

func (s *Service) loadConfig() (nodeSettings, statusDocument, error) {
	settings := nodeSettings{
		GlobalEnabled: false,
		NodeEnabled:   false,
		ScheduleRaw:   DefaultScheduleRaw,
		Schedule:      24 * time.Hour,
		Include:       []string{DatasetDomains},
		Retention:     defaultRetention,
	}

	doc, err := s.extensions.GetGlobal(models.ExtensionMegaBackups)
	if err != nil {
		if errors.Is(err, extensions.ErrNotFound) {
			status, statErr := s.readStatus()
			return settings, status, statErr
		}
		return settings, statusDocument{}, err
	}
	settings.GlobalEnabled = doc.State.Enabled
	if cfg := doc.State.Config; cfg != nil {
		if v, ok := cfg["schedule_default"].(string); ok && strings.TrimSpace(v) != "" {
			settings.ScheduleRaw = strings.TrimSpace(v)
		}
		if list, ok := cfg["include"]; ok {
			settings.Include = dedupeDatasets(list, settings.Include)
		}
		if nodes, ok := cfg["nodes"].(map[string]interface{}); ok {
			if raw, ok := nodes[s.cfg.NodeName]; ok {
				if nodeCfg, ok := raw.(map[string]interface{}); ok {
					settings.NodeEnabled = boolFrom(nodeCfg, "enabled", settings.GlobalEnabled)
					if val, ok := nodeCfg["username"].(string); ok {
						settings.Username = strings.TrimSpace(val)
					}
					if val, ok := nodeCfg["password"].(string); ok {
						settings.Password = val
					}
					if list, ok := nodeCfg["include"]; ok {
						settings.Include = dedupeDatasets(list, settings.Include)
					}
					if freq, ok := nodeCfg["schedule"].(string); ok && strings.TrimSpace(freq) != "" {
						settings.ScheduleRaw = strings.TrimSpace(freq)
					}
					if ret, ok := numericInt(nodeCfg["retention"]); ok && ret > 0 {
						settings.Retention = ret
					}
				}
			}
		}
	}
	if settings.NodeEnabled == false {
		settings.NodeEnabled = settings.GlobalEnabled
	}
	if d, err := time.ParseDuration(settings.ScheduleRaw); err == nil && d > 0 {
		settings.Schedule = d
	}
	if err := settings.validate(); err != nil {
		return settings, statusDocument{}, err
	}
	status, err := s.readStatus()
	return settings, status, err
}

func dedupeDatasets(value interface{}, fallback []string) []string {
	out := make([]string, 0)
	switch typed := value.(type) {
	case []interface{}:
		for _, elem := range typed {
			if str, ok := elem.(string); ok {
				if normalised := normaliseDataset(str); normalised != "" {
					out = append(out, normalised)
				}
			}
		}
	case []string:
		for _, str := range typed {
			if normalised := normaliseDataset(str); normalised != "" {
				out = append(out, normalised)
			}
		}
	}
	if len(out) == 0 {
		return fallback
	}
	seen := make(map[string]struct{}, len(out))
	unique := make([]string, 0, len(out))
	for _, item := range out {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		unique = append(unique, item)
	}
	return unique
}

func boolFrom(m map[string]interface{}, key string, def bool) bool {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			switch strings.ToLower(strings.TrimSpace(t)) {
			case "1", "true", "yes", "on":
				return true
			case "0", "false", "no", "off":
				return false
			}
		case float64:
			return t != 0
		case int:
			return t != 0
		}
	}
	return def
}

func numericInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case float64:
		return int(val), true
	case int:
		return val, true
	case int64:
		return int(val), true
	case string:
		val = strings.TrimSpace(val)
		if val == "" {
			return 0, false
		}
		if strings.Contains(val, ".") {
			return 0, false
		}
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func normaliseDataset(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case DatasetDomains, "":
		return DatasetDomains
	case "domain":
		return DatasetDomains
	case DatasetUsers, "user":
		return DatasetUsers
	case DatasetExtensions, "extension":
		return DatasetExtensions
	case DatasetNodes, "node":
		return DatasetNodes
	case DatasetEdgeHealth, "edge-health", "edge":
		return DatasetEdgeHealth
	case DatasetSearchBots, "searchbots", "search-bots":
		return DatasetSearchBots
	default:
		return ""
	}
}
