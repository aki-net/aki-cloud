package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/orchestrator"
	"aki-cloud/backend/internal/store"
)

func TestSyncLocalNodeCapabilitiesPreservesExplicitRoles(t *testing.T) {
	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, "cluster"), 0o755); err != nil {
		t.Fatalf("mkdir cluster: %v", err)
	}
	secretFile := filepath.Join(dir, "cluster", "secret")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	node := models.Node{
		ID:      "node-a",
		Name:    "node-a",
		IPs:     []string{"10.0.0.1"},
		EdgeIPs: []string{"10.0.0.1"},
		Version: models.ClockVersion{
			Counter: 1,
			NodeID:  "seed",
			Updated: time.Now().Unix(),
		},
	}
	if err := st.UpsertNode(node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}

	if err := st.UpsertEdgeHealth(models.EdgeHealthStatus{
		IP:      "10.0.0.1",
		Healthy: true,
		Version: models.ClockVersion{Counter: 1, NodeID: "seed", Updated: time.Now().Unix()},
	}); err != nil {
		t.Fatalf("UpsertEdgeHealth: %v", err)
	}

	cfg := &config.Config{
		DataDir:           dir,
		ClusterSecretFile: secretFile,
		NodeID:            "node-a",
		NodeName:          "node-a",
		EnableOpenResty:   false,
		EnableCoreDNS:     false,
		Port:              8080,
		JWTSecret:         []byte("test"),
	}

	orch := orchestrator.New(dir, time.Millisecond)
	infraCtl := infra.New(st, dir)

	srv := &Server{
		Config:       cfg,
		Store:        st,
		Orchestrator: orch,
		Infra:        infraCtl,
	}

	changed := srv.SyncLocalNodeCapabilities(context.Background())
	if !changed {
		t.Fatalf("expected capabilities sync to report change")
	}

	nodes, err := st.GetNodesIncludingDeleted()
	if err != nil {
		t.Fatalf("GetNodesIncludingDeleted: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected single node, got %d", len(nodes))
	}
	synced := nodes[0]
	if len(synced.EdgeIPs) != 1 || synced.EdgeIPs[0] != "10.0.0.1" {
		t.Fatalf("expected edge IPs to be preserved, got %v", synced.EdgeIPs)
	}
	if !synced.HasRole(models.NodeRoleEdge) {
		t.Fatalf("expected edge role to remain active")
	}
	if synced.Version.NodeID != "node-a" {
		t.Fatalf("expected version node id to be local, got %s", synced.Version.NodeID)
	}

	health, err := st.GetEdgeHealth()
	if err != nil {
		t.Fatalf("GetEdgeHealth: %v", err)
	}
	if len(health) != 1 {
		t.Fatalf("expected edge health to remain, got %v", health)
	}
}
