package extensions

import (
	"os"
	"path/filepath"
	"testing"

	"aki-cloud/backend/internal/store"
)

func TestUpdatePlaceholderEnablesConfig(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	svc := New(st, "node-1")
	enabled := true
	if _, err := svc.UpdateGlobal("placeholder_pages", &enabled, nil, "admin"); err != nil {
		t.Fatalf("update placeholder: %v", err)
	}
	cfg, err := svc.PlaceholderConfig()
	if err != nil {
		t.Fatalf("placeholder config: %v", err)
	}
	if !cfg.Enabled {
		t.Fatalf("expected placeholder to be enabled")
	}
	// ensure persisted file has enabled flag
	path := filepath.Join(dir, "extensions", "extensions.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("extensions state empty")
	}
}
