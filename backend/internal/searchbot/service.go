package searchbot

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrDisabled indicates that search bot logging is not enabled.
	ErrDisabled = errors.New("search bot logging disabled")
	// ErrBotNotFound indicates an unknown bot key was requested.
	ErrBotNotFound = errors.New("search bot not found")
)

// BotDefinition describes the crawlers we capture.
type BotDefinition struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Icon    string   `json:"icon"`
	Regex   string   `json:"regex"`
	Matches []string `json:"matches,omitempty"`
	LogPath string   `json:"log_path"`
}

// Config captures runtime settings for the service.
type Config struct {
	Enabled        bool
	LogDir         string
	LogFile        string
	FileLimitBytes int64
	CacheTTL       time.Duration
	Bots           []BotDefinition
}

// PeriodStats bundles counters for current and previous periods.
type PeriodStats struct {
	Current  int64 `json:"current"`
	Previous int64 `json:"previous"`
	Delta    int64 `json:"delta"`
}

// BotStats captures counters for a specific crawler.
type BotStats struct {
	Key   string      `json:"key"`
	Label string      `json:"label"`
	Icon  string      `json:"icon"`
	Today PeriodStats `json:"today"`
	Month PeriodStats `json:"month"`
	Year  PeriodStats `json:"year"`
	Total int64       `json:"total"`
}

// DomainStats aggregates crawler activity for a domain.
type DomainStats struct {
	Domain      string     `json:"domain"`
	GeneratedAt time.Time  `json:"generated_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Bots        []BotStats `json:"bots"`
}

// BotUsage provides storage consumption per crawler.
type BotUsage struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Icon  string `json:"icon"`
	Bytes int64  `json:"bytes"`
	Path  string `json:"path"`
}

// NodeUsage describes cumulative log usage for the local node.
type NodeUsage struct {
	NodeID     string     `json:"node_id"`
	NodeName   string     `json:"node_name,omitempty"`
	LogDir     string     `json:"log_dir"`
	TotalBytes int64      `json:"total_bytes"`
	Bots       []BotUsage `json:"bots"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type cacheEntry struct {
	stats      DomainStats
	computedAt time.Time
}

// Service handles log accounting and export helpers.
type Service struct {
	nodeID string
	clock  func() time.Time

	mu     sync.RWMutex
	cfg    Config
	botMap map[string]BotDefinition

	cacheMu sync.RWMutex
	cache   map[string]cacheEntry
}

// New creates a new search bot service.
func New(nodeID string) *Service {
	return &Service{
		nodeID: nodeID,
		clock:  time.Now,
		cache:  make(map[string]cacheEntry),
		botMap: make(map[string]BotDefinition),
	}
}

// UpdateConfig applies a fresh runtime configuration.
func (s *Service) UpdateConfig(cfg Config) error {
	cfg.LogDir = strings.TrimSpace(cfg.LogDir)
	if cfg.LogDir == "" {
		cfg.LogDir = "/data/searchbot/logs"
	}
	cfg.LogDir = filepath.Clean(cfg.LogDir)
	cfg.LogFile = strings.TrimSpace(cfg.LogFile)
	if cfg.LogFile == "" {
		cfg.LogFile = filepath.Join(cfg.LogDir, "searchbots.log")
	}
	if cfg.FileLimitBytes <= 0 {
		cfg.FileLimitBytes = 1024 * 1024 * 1024 // default 1 GiB
	}
	if cfg.FileLimitBytes < 10*1024*1024 {
		cfg.FileLimitBytes = 10 * 1024 * 1024
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	seen := make(map[string]struct{}, len(cfg.Bots))
	outBots := make([]BotDefinition, 0, len(cfg.Bots))
	for _, bot := range cfg.Bots {
		key := strings.TrimSpace(strings.ToLower(bot.Key))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		if bot.Regex == "" {
			bot.Regex = key
		}
		bot.Key = key
		bot.LogPath = cfg.LogFile
		outBots = append(outBots, bot)
		seen[key] = struct{}{}
	}
	sort.SliceStable(outBots, func(i, j int) bool {
		if outBots[i].Key == outBots[j].Key {
			return outBots[i].Label < outBots[j].Label
		}
		return outBots[i].Key < outBots[j].Key
	})
	cfg.Bots = outBots
	if cfg.Enabled {
		if err := os.MkdirAll(cfg.LogDir, 0o777); err != nil {
			return fmt.Errorf("ensure searchbot log dir: %w", err)
		}
		if err := ensureWorldWritableDir(cfg.LogDir); err != nil {
			return err
		}
		if err := ensureWorldWritableFile(cfg.LogFile); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.botMap = make(map[string]BotDefinition, len(cfg.Bots))
	for _, bot := range cfg.Bots {
		s.botMap[bot.Key] = bot
	}
	s.mu.Unlock()
	s.cacheMu.Lock()
	s.cache = make(map[string]cacheEntry)
	s.cacheMu.Unlock()
	return nil
}

// Config returns a copy of the current configuration.
func (s *Service) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.Bots = append([]BotDefinition(nil), cfg.Bots...)
	return cfg
}

// Bots returns known crawler definitions.
func (s *Service) Bots() []BotDefinition {
	return s.Config().Bots
}

// LocalUsage computes storage usage for local crawler logs.
func (s *Service) LocalUsage() (NodeUsage, error) {
	cfg := s.Config()
	usage := NodeUsage{
		NodeID:    s.nodeID,
		LogDir:    cfg.LogDir,
		UpdatedAt: s.clock().UTC(),
	}
	if !cfg.Enabled {
		return usage, nil
	}
	sizeCache := make(map[string]int64, len(cfg.Bots))
	usage.Bots = make([]BotUsage, 0, len(cfg.Bots))
	for _, bot := range cfg.Bots {
		path := strings.TrimSpace(bot.LogPath)
		size, known := sizeCache[path]
		if !known {
			if path != "" {
				info, err := os.Stat(path)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return usage, err
					}
				} else {
					size = info.Size()
					if cfg.FileLimitBytes > 0 && size > cfg.FileLimitBytes+cfg.FileLimitBytes/10 {
						if err := s.trimLogIfNeeded(path, cfg.FileLimitBytes); err == nil {
							if updated, errStat := os.Stat(path); errStat == nil {
								size = updated.Size()
							}
						}
					}
				}
			}
			sizeCache[path] = size
		}
		usage.Bots = append(usage.Bots, BotUsage{
			Key:   bot.Key,
			Label: bot.Label,
			Icon:  bot.Icon,
			Bytes: size,
			Path:  path,
		})
	}
	total := int64(0)
	for path, size := range sizeCache {
		if path == "" {
			continue
		}
		total += size
	}
	usage.TotalBytes = total
	return usage, nil
}

// ClearLogs truncates crawler log files and resets cached counters.
func (s *Service) ClearLogs() error {
	cfg := s.Config()
	if !cfg.Enabled {
		return nil
	}
	seen := make(map[string]struct{}, len(cfg.Bots))
	for _, bot := range cfg.Bots {
		path := strings.TrimSpace(bot.LogPath)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		if err := truncateFile(path); err != nil {
			return err
		}
		seen[path] = struct{}{}
	}
	s.cacheMu.Lock()
	s.cache = make(map[string]cacheEntry)
	s.cacheMu.Unlock()
	return nil
}

// DomainStats returns crawler counters for the provided domain.
func (s *Service) DomainStats(domain string, refresh bool) (DomainStats, error) {
	cfg := s.Config()
	if !cfg.Enabled {
		return DomainStats{}, ErrDisabled
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return DomainStats{}, errors.New("domain required")
	}
	if !refresh && cfg.CacheTTL > 0 {
		s.cacheMu.RLock()
		entry, ok := s.cache[domain]
		s.cacheMu.RUnlock()
		if ok && s.clock().UTC().Before(entry.computedAt.Add(cfg.CacheTTL)) {
			return entry.stats, nil
		}
	}
	stats, err := s.computeDomainStats(cfg, domain)
	if err != nil {
		return DomainStats{}, err
	}
	if cfg.CacheTTL > 0 {
		s.cacheMu.Lock()
		s.cache[domain] = cacheEntry{
			stats:      stats,
			computedAt: stats.GeneratedAt,
		}
		s.cacheMu.Unlock()
	}
	return stats, nil
}

// ExportLogs streams crawler log lines for a given domain and bot into w.
func (s *Service) ExportLogs(domain string, botKey string, w io.Writer) (int64, error) {
	cfg := s.Config()
	if !cfg.Enabled {
		return 0, ErrDisabled
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return 0, errors.New("domain required")
	}
	bot, ok := s.lookupBot(botKey)
	if !ok {
		return 0, ErrBotNotFound
	}
	file, err := os.Open(bot.LogPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	writer := bufio.NewWriter(w)
	var written int64
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			entry, parseErr := parseLogLine(line)
			if parseErr == nil && strings.EqualFold(entry.BotKey, bot.Key) && strings.EqualFold(entry.Host, domain) {
				n, writeErr := writer.WriteString(line)
				written += int64(n)
				if writeErr != nil {
					return written, writeErr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return written, err
		}
	}
	if err := writer.Flush(); err != nil {
		return written, err
	}
	return written, nil
}

func (s *Service) computeDomainStats(cfg Config, domain string) (DomainStats, error) {
	now := s.clock().UTC()
	var stats DomainStats
	stats.Domain = domain
	stats.GeneratedAt = now
	stats.ExpiresAt = now.Add(cfg.CacheTTL)
	if !cfg.Enabled {
		return stats, nil
	}
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	yesterdayStart := todayStart.AddDate(0, 0, -1)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	prevMonthStart := monthStart.AddDate(0, -1, 0)
	yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	prevYearStart := yearStart.AddDate(-1, 0, 0)
	botStats := make([]BotStats, 0, len(cfg.Bots))
	for _, bot := range cfg.Bots {
		if cfg.FileLimitBytes > 0 {
			_ = s.trimLogIfNeeded(bot.LogPath, cfg.FileLimitBytes)
		}
		file, err := os.Open(bot.LogPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				botStats = append(botStats, BotStats{
					Key:   bot.Key,
					Label: bot.Label,
					Icon:  bot.Icon,
				})
				continue
			}
			return DomainStats{}, err
		}
		totals := struct {
			todayCurrent int64
			todayPrev    int64
			monthCurrent int64
			monthPrev    int64
			yearCurrent  int64
			yearPrev     int64
			total        int64
		}{}
		reader := bufio.NewReader(file)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				entry, parseErr := parseLogLine(line)
				if parseErr == nil && strings.EqualFold(entry.BotKey, bot.Key) && strings.EqualFold(entry.Host, domain) {
					ts := entry.Timestamp.UTC()
					if !ts.Before(todayStart) {
						totals.todayCurrent++
					} else if !ts.Before(yesterdayStart) && ts.Before(todayStart) {
						totals.todayPrev++
					}
					if !ts.Before(monthStart) {
						totals.monthCurrent++
					} else if !ts.Before(prevMonthStart) && ts.Before(monthStart) {
						totals.monthPrev++
					}
					if !ts.Before(yearStart) {
						totals.yearCurrent++
					} else if !ts.Before(prevYearStart) && ts.Before(yearStart) {
						totals.yearPrev++
					}
					totals.total++
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				_ = file.Close()
				return DomainStats{}, err
			}
		}
		_ = file.Close()
		botStats = append(botStats, BotStats{
			Key:   bot.Key,
			Label: bot.Label,
			Icon:  bot.Icon,
			Today: PeriodStats{
				Current:  totals.todayCurrent,
				Previous: totals.todayPrev,
				Delta:    totals.todayCurrent - totals.todayPrev,
			},
			Month: PeriodStats{
				Current:  totals.monthCurrent,
				Previous: totals.monthPrev,
				Delta:    totals.monthCurrent - totals.monthPrev,
			},
			Year: PeriodStats{
				Current:  totals.yearCurrent,
				Previous: totals.yearPrev,
				Delta:    totals.yearCurrent - totals.yearPrev,
			},
			Total: totals.total,
		})
	}
	stats.Bots = botStats
	return stats, nil
}

func (s *Service) lookupBot(key string) (BotDefinition, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bot, ok := s.botMap[strings.ToLower(strings.TrimSpace(key))]
	return bot, ok
}

func (s *Service) trimLogIfNeeded(path string, limit int64) error {
	if limit <= 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()
	if size <= limit {
		return nil
	}
	keep := limit - limit/5
	if keep <= 0 {
		keep = limit
	}
	if keep <= 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if size <= keep {
		return nil
	}
	start := size - keep
	section := io.NewSectionReader(file, start, keep)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(file, section); err != nil {
		return err
	}
	if err := file.Truncate(keep); err != nil {
		return err
	}
	return nil
}

type logEntry struct {
	BotKey    string
	Host      string
	Timestamp time.Time
}

func parseLogLine(line string) (logEntry, error) {
	line = strings.TrimRight(line, "\n")
	parts := strings.SplitN(line, "\t", 9)
	if len(parts) < 4 {
		return logEntry{}, errors.New("malformed log line")
	}
	entry := logEntry{
		BotKey: strings.TrimSpace(parts[1]),
		Host:   normalizeDomain(parts[3]),
	}
	if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[2])); err == nil {
		entry.Timestamp = ts.UTC()
		return entry, nil
	}
	if secs, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
		intPart := int64(secs)
		nano := int64((secs - float64(intPart)) * 1_000_000_000)
		entry.Timestamp = time.Unix(intPart, nano).UTC()
		return entry, nil
	}
	entry.Timestamp = time.Now().UTC()
	return entry, nil
}

func truncateFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.Trim(domain, ".")
}

func ensureWorldWritableDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("expected directory at %s", path)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		return fmt.Errorf("chmod searchbot log dir: %w", err)
	}
	return nil
}

func ensureWorldWritableFile(path string) error {
	if path == "" {
		return errors.New("log file path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return fmt.Errorf("ensure log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		return fmt.Errorf("chmod log file: %w", err)
	}
	return nil
}
