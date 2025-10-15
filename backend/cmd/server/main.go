package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aki-cloud/backend/internal/api"
	"aki-cloud/backend/internal/auth"
	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/extensions"
	"aki-cloud/backend/internal/health"
	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/orchestrator"
	"aki-cloud/backend/internal/ssl"
	"aki-cloud/backend/internal/store"
	syncsvc "aki-cloud/backend/internal/sync"
	"aki-cloud/backend/internal/whois"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	st, err := store.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("failed to init store: %v", err)
	}

	authSvc := auth.New(cfg.JWTSecret)
	orch := orchestrator.New(cfg.DataDir, cfg.ReloadDebounce)

	secret, err := os.ReadFile(cfg.ClusterSecretFile)
	if err != nil {
		log.Fatalf("failed to read cluster secret: %v", err)
	}

	syncSvc := syncsvc.New(st, cfg.DataDir, cfg.NodeID, secret)
	infraCtl := infra.New(st, cfg.DataDir)
	extSvc := extensions.New(st, cfg.NodeID)
	whoisSvc := whois.New(15 * time.Second)

	healthMonitor := health.New(st, infraCtl, orch, cfg.NodeID, cfg.HealthInterval, cfg.HealthDialTimeout, cfg.HealthFailureThreshold, cfg.HealthFailureDecay)
	slSvc := ssl.New(cfg, st, orch)

	server := &api.Server{
		Config:       cfg,
		Store:        st,
		Auth:         authSvc,
		Orchestrator: orch,
		Sync:         syncSvc,
		Infra:        infraCtl,
		Extensions:   extSvc,
		Whois:        whoisSvc,
	}

	syncSvc.SetChangeHandler(func() {
		server.SyncLocalNodeCapabilities(context.Background())
		server.TriggerDomainReconcile("sync-change")
		orch.Trigger(context.Background())
	})

	if err := server.EnsurePeers(); err != nil {
		log.Printf("initial peer sync failed: %v", err)
	}

	server.SyncLocalNodeCapabilities(context.Background())
	server.TriggerDomainReconcile("startup")

	router := server.Routes()

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           router,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func(ctx context.Context) {
		if server.SyncLocalNodeCapabilities(context.Background()) {
			return
		}
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if server.SyncLocalNodeCapabilities(context.Background()) {
					return
				}
			}
		}
	}(ctx)

	syncCtx, syncCancel := context.WithCancel(ctx)
	go syncSvc.Start(syncCtx, cfg.SyncInterval)
	go healthMonitor.Start(syncCtx)
	go slSvc.Start(syncCtx)
	server.StartDomainReconciler(syncCtx, cfg.HealthInterval)

	go func() {
		log.Printf("backend listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	syncCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}
