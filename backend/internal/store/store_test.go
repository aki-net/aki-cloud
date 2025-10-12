package store_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "store-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestStoreUpsertDomain(t *testing.T) {
	dir := tempDir(t)
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	record := models.DomainRecord{
		Domain:    "example.test",
		Owner:     "user-1",
		OriginIP:  "203.0.113.5",
		Proxied:   false,
		TTL:       60,
		UpdatedAt: time.Now().UTC(),
		Version: models.ClockVersion{
			Counter: 1,
			NodeID:  "node-a",
			Updated: time.Now().Unix(),
		},
	}

	if err := st.UpsertDomain(record); err != nil {
		t.Fatalf("upsert domain: %v", err)
	}

	stored, err := st.GetDomain("example.test")
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}

	if stored.OriginIP != record.OriginIP {
		t.Fatalf("origin mismatch: got %s want %s", stored.OriginIP, record.OriginIP)
	}

	path := filepath.Join(dir, "domains", "example.test", "record.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected domain file to exist: %v", err)
	}
}

func TestMarkDomainDeleted(t *testing.T) {
	dir := tempDir(t)
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	now := time.Now().UTC()
	record := models.DomainRecord{
		Domain:   "delete.test",
		Owner:    "user-1",
		OriginIP: "203.0.113.5",
		Proxied:  true,
		TTL:      60,
		Version: models.ClockVersion{
			Counter: 1,
			NodeID:  "node-a",
			Updated: now.Unix(),
		},
	}
	record.EnsureTLSDefaults()
	if err := st.UpsertDomain(record); err != nil {
		t.Fatalf("upsert domain: %v", err)
	}
	if err := st.MarkDomainDeleted("delete.test", "node-b", now.Add(time.Second)); err != nil {
		t.Fatalf("mark deleted: %v", err)
	}
	if _, err := st.GetDomain("delete.test"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected deleted domain to be hidden, got %v", err)
	}
	active, err := st.GetDomains()
	if err != nil {
		t.Fatalf("GetDomains: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active domains, got %d", len(active))
	}
	all, err := st.GetDomainsIncludingDeleted()
	if err != nil {
		t.Fatalf("GetDomainsIncludingDeleted: %v", err)
	}
	found := false
	for _, rec := range all {
		if rec.Domain == "delete.test" {
			if rec.DeletedAt.IsZero() {
				t.Fatalf("expected tombstone to have DeletedAt set")
			}
			if rec.Version.NodeID != "node-b" {
				t.Fatalf("expected version node to propagate deletion")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tombstone record to exist")
	}
	if err := st.MarkDomainDeleted("missing.test", "node-c", now.Add(2*time.Second)); err != nil {
		t.Fatalf("mark deleted for missing domain: %v", err)
	}
	all, err = st.GetDomainsIncludingDeleted()
	if err != nil {
		t.Fatalf("GetDomainsIncludingDeleted: %v", err)
	}
	var missingTombstone *models.DomainRecord
	for i := range all {
		if all[i].Domain == "missing.test" {
			missingTombstone = &all[i]
			break
		}
	}
	if missingTombstone == nil || missingTombstone.DeletedAt.IsZero() {
		t.Fatalf("expected tombstone to be created for missing domain")
	}
}

func TestStoreUpsertUser(t *testing.T) {
	dir := tempDir(t)
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	user := models.User{ID: "admin", Email: "admin@example.com", Role: models.RoleAdmin, Password: "hash"}
	if err := st.UpsertUser(user); err != nil {
		t.Fatalf("upsert user: %v", err)
	}

	user.Password = "hash2"
	if err := st.UpsertUser(user); err != nil {
		t.Fatalf("update user: %v", err)
	}

	stored, err := st.GetUserByID("admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if stored.Password != "hash2" {
		t.Fatalf("password not updated")
	}
}
