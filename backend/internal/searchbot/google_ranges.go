package searchbot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// googlePrefixes mirrors the JSON payload published by Google.
type googlePrefixes struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
		Service    string `json:"service"`
	} `json:"prefixes"`
}

// StartGoogleRangeUpdater launches a background routine that refreshes Googlebot IP ranges.
func (s *Service) StartGoogleRangeUpdater(ctx context.Context, interval time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		if err := s.RefreshGoogleRanges(ctx); err != nil {
			log.Printf("searchbot: initial google ranges refresh failed: %v", err)
		}
		if interval <= 0 {
			return
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.RefreshGoogleRanges(ctx); err != nil {
					log.Printf("searchbot: periodic google ranges refresh failed: %v", err)
				}
			}
		}
	}()
}

// RefreshGoogleRanges downloads the latest Googlebot CIDR ranges and writes geo/include files.
func (s *Service) RefreshGoogleRanges(ctx context.Context) error {
	cfg := s.Config()
	if !cfg.Enabled {
		return nil
	}
	if cfg.RangesURL == "" || cfg.GeoFile == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ranges, raw, err := downloadGooglebotRanges(ctx, cfg.RangesURL)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.JSONFile), 0o777); err != nil {
		return fmt.Errorf("ensure ranges dir: %w", err)
	}
	if err := writeFileAtomic(cfg.JSONFile, raw, 0o666); err != nil {
		return fmt.Errorf("write googlebot json: %w", err)
	}
	if err := writeGeoFile(cfg.GeoFile, ranges); err != nil {
		return err
	}
	if err := ensureWorldWritableFile(cfg.JSONFile); err != nil {
		return err
	}
	if err := ensureWorldWritableFile(cfg.GeoFile); err != nil {
		return err
	}
	s.mu.Lock()
	s.rangesUpdatedAt = s.clock()
	s.mu.Unlock()
	return nil
}

func downloadGooglebotRanges(ctx context.Context, url string) ([]string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch google ranges: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, nil, fmt.Errorf("fetch google ranges: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read google ranges: %w", err)
	}
	var payload googlePrefixes
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil, fmt.Errorf("parse google ranges: %w", err)
	}
	out := make([]string, 0, len(payload.Prefixes))
	for _, prefix := range payload.Prefixes {
		if !strings.EqualFold(prefix.Service, "Googlebot") {
			continue
		}
		if p := strings.TrimSpace(prefix.IPv4Prefix); p != "" {
			out = append(out, p)
		}
		if p := strings.TrimSpace(prefix.IPv6Prefix); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, raw, nil
}

func writeGeoFile(path string, ranges []string) error {
	builder := &strings.Builder{}
	builder.WriteString("# auto-generated googlebot ranges\n")
	for _, prefix := range ranges {
		if _, _, err := net.ParseCIDR(prefix); err != nil {
			continue
		}
		builder.WriteString(prefix)
		builder.WriteString(" 1;\n")
	}
	return writeFileAtomic(path, []byte(builder.String()), 0o666)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}
