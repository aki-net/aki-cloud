package orchestrator

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// Service renders DNS and proxy configuration using helper scripts.
type Service struct {
	scriptsDir     string
	debounceWindow time.Duration
	mu             sync.Mutex
	pending        bool
	timer          *time.Timer
}

// New creates an orchestrator service.
func New(dataDir string, debounce time.Duration) *Service {
	return &Service{
		scriptsDir:     filepath.Join(".", "scripts"),
		debounceWindow: debounce,
	}
}

// Trigger schedules regeneration for both CoreDNS and OpenResty.
func (s *Service) Trigger(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.debounceWindow, func() {
		s.Flush(context.Background())
	})
}

// Flush triggers the generation immediately.
func (s *Service) Flush(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pending {
		return
	}
	run := func(script string) error {
		cmd := exec.CommandContext(ctx, filepath.Join(s.scriptsDir, script))
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("PATH=%s", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
		)
		return cmd.Run()
	}
	if err := run("generate_coredns.sh"); err != nil {
		log.Printf("orchestrator: generate_coredns failed: %v", err)
	}
	if err := run("generate_openresty.sh"); err != nil {
		log.Printf("orchestrator: generate_openresty failed: %v", err)
	}
	if err := run("configure_firewall.sh"); err != nil {
		log.Printf("orchestrator: configure_firewall failed: %v", err)
	}
	_ = run("reload_coredns.sh")
	_ = run("reload_openresty.sh")
	s.pending = false
}

// FlushSync forces a synchronous regeneration, used for admin rebuild.
func (s *Service) FlushSync(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := func(script string) error {
		cmd := exec.CommandContext(ctx, filepath.Join(s.scriptsDir, script))
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("PATH=%s", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
		)
		return cmd.Run()
	}
	if err := run("generate_coredns.sh"); err != nil {
		return err
	}
	if err := run("generate_openresty.sh"); err != nil {
		return err
	}
	if err := run("configure_firewall.sh"); err != nil {
		return err
	}
	if err := run("reload_coredns.sh"); err != nil {
		return err
	}
	if err := run("reload_openresty.sh"); err != nil {
		return err
	}
	return nil
}

// PurgeEdgeCache clears the edge cache via helper script.
func (s *Service) PurgeEdgeCache(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, filepath.Join(s.scriptsDir, "purge_edge_cache.sh"))
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PATH=%s", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("purge edge cache: %w", err)
	}
	return nil
}
