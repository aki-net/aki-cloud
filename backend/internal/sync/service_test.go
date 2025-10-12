package sync

import (
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "sync-store-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	return st
}

func TestMergeDomainPrefersNewest(t *testing.T) {
	now := time.Now().UTC()
	local := models.DomainRecord{
		Domain:   "example.test",
		OriginIP: "203.0.113.10",
		Version:  models.ClockVersion{Counter: 1, NodeID: "node-a", Updated: now.Add(-time.Minute).Unix()},
	}
	remote := models.DomainRecord{
		Domain:   "example.test",
		OriginIP: "198.51.100.4",
		Version:  models.ClockVersion{Counter: 2, NodeID: "node-b", Updated: now.Unix()},
	}

	merged := mergeDomain(local, remote)
	if merged.OriginIP != remote.OriginIP {
		t.Fatalf("expected remote record to win")
	}
}

func TestServiceApplySnapshot(t *testing.T) {
	st := newTestStore(t)
	svc := New(st, t.TempDir(), "node-a", []byte("secret"))

	now := time.Now().UTC()
	snapshot := Snapshot{
		Domains: []models.DomainRecord{
			{
				Domain:   "example.test",
				OriginIP: "203.0.113.5",
				Proxied:  false,
				TTL:      60,
				Version: models.ClockVersion{
					Counter: 1,
					NodeID:  "seed",
					Updated: now.Unix(),
				},
			},
		},
		Users: []models.User{{ID: "admin", Email: "a@a", Role: models.RoleAdmin, Password: "hash"}},
		Nodes: []models.Node{{
			ID:          "node-1",
			Name:        "node-1",
			IPs:         []string{"10.0.0.1"},
			APIEndpoint: "http://10.0.0.1:8080",
			Version: models.ClockVersion{
				Counter: 1,
				NodeID:  "seed",
				Updated: now.Unix(),
			},
		}},
	}

	if err := svc.ApplySnapshot(snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	domain, err := st.GetDomain("example.test")
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}
	if domain.OriginIP != "203.0.113.5" {
		t.Fatalf("unexpected origin ip")
	}

	users, err := st.GetUsers()
	if err != nil || len(users) != 1 {
		t.Fatalf("users not merged")
	}

	peers, err := st.GetPeers()
	if err != nil {
		t.Fatalf("get peers: %v", err)
	}
	if len(peers) != 1 || peers[0] != "http://10.0.0.1:8080" {
		t.Fatalf("unexpected peers: %#v", peers)
	}
}

func TestApplySnapshotTombstone(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	rec := models.DomainRecord{
		Domain:   "remove.test",
		OriginIP: "203.0.113.10",
		TTL:      60,
		Proxied:  true,
		Version: models.ClockVersion{
			Counter: 1,
			NodeID:  "node-a",
			Updated: now.Unix(),
		},
	}
	rec.EnsureTLSDefaults()
	if err := st.SaveDomain(rec); err != nil {
		t.Fatalf("SaveDomain: %v", err)
	}
	svc := New(st, t.TempDir(), "node-b", []byte("secret"))

	tombstone := rec
	tombstone.Version = models.ClockVersion{
		Counter: 2,
		NodeID:  "node-b",
		Updated: now.Add(time.Second).Unix(),
	}
	tombstone.MarkDeleted(now.Add(time.Second))

	snapshot := Snapshot{
		Domains: []models.DomainRecord{tombstone},
	}
	if err := svc.ApplySnapshot(snapshot); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if _, err := st.GetDomain("remove.test"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected tombstoned domain to be hidden, got %v", err)
	}
	all, err := st.GetDomainsIncludingDeleted()
	if err != nil {
		t.Fatalf("GetDomainsIncludingDeleted: %v", err)
	}
	found := false
	for _, rec := range all {
		if rec.Domain == "remove.test" {
			if rec.DeletedAt.IsZero() {
				t.Fatalf("expected DeletedAt to be set")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tombstone to remain on disk")
	}
}

func TestApplySnapshotNodeDeletion(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	node := models.Node{
		ID:      "node-1",
		Name:    "node-1",
		IPs:     []string{"10.0.0.1"},
		EdgeIPs: []string{"10.0.0.1"},
		Version: models.ClockVersion{Counter: 1, NodeID: "local", Updated: now.Add(-time.Minute).Unix()},
	}
	if err := st.UpsertNode(node); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}

	svc := New(st, t.TempDir(), "node-b", []byte("secret"))

	deleted := node
	deleted.MarkDeleted(now)
	deleted.Version = models.ClockVersion{Counter: 2, NodeID: "remote", Updated: now.Unix()}

	snapshot := Snapshot{Nodes: []models.Node{deleted}}
	if err := svc.ApplySnapshot(snapshot); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}

	active, err := st.GetNodes()
	if err != nil {
		t.Fatalf("GetNodes: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active nodes, got %d", len(active))
	}

	all, err := st.GetNodesIncludingDeleted()
	if err != nil {
		t.Fatalf("GetNodesIncludingDeleted: %v", err)
	}
	if len(all) != 1 || !all[0].IsDeleted() {
		t.Fatalf("expected tombstoned node, got %#v", all)
	}
}

func TestMergeNodesPrefersNewest(t *testing.T) {
	now := time.Now().UTC()
	local := []models.Node{
		{
			ID:      "node-1",
			Name:    "node-1",
			IPs:     []string{"10.0.0.1"},
			Version: models.ClockVersion{Counter: 2, NodeID: "local", Updated: now.Unix()},
		},
	}
	remote := []models.Node{
		{
			ID:      "node-1",
			Name:    "node-1",
			IPs:     []string{"10.0.0.1"},
			NSIPs:   []string{"10.0.0.1"},
			Version: models.ClockVersion{Counter: 1, NodeID: "remote", Updated: now.Add(-time.Minute).Unix()},
		},
	}
	merged := mergeNodes(local, remote)
	if len(merged) != 1 {
		t.Fatalf("expected single node")
	}
	if merged[0].Version.NodeID != "local" {
		t.Fatalf("expected local version to win, got %#v", merged[0].Version)
	}

	remoteNew := []models.Node{
		{
			ID:      "node-2",
			Name:    "node-2",
			IPs:     []string{"10.0.0.2"},
			Version: models.ClockVersion{Counter: 1, NodeID: "remote", Updated: now.Unix()},
		},
	}
	merged = mergeNodes(merged, remoteNew)
	if len(merged) != 2 {
		t.Fatalf("expected merged to include new node")
	}
}

func TestMergeNodesTracksDeletion(t *testing.T) {
	now := time.Now().UTC()
	local := []models.Node{
		{
			ID:      "node-1",
			Name:    "node-1",
			IPs:     []string{"10.0.0.1"},
			Version: models.ClockVersion{Counter: 3, NodeID: "local", Updated: now.Unix()},
		},
	}
	remote := []models.Node{
		{
			ID:        "node-1",
			Name:      "node-1",
			IPs:       []string{"10.0.0.1"},
			DeletedAt: now,
			Version:   models.ClockVersion{Counter: 4, NodeID: "remote", Updated: now.Add(time.Second).Unix()},
		},
	}
	merged := mergeNodes(local, remote)
	if len(merged) != 1 {
		t.Fatalf("expected node to remain for tombstone")
	}
	if merged[0].DeletedAt.IsZero() {
		t.Fatalf("expected deletion to propagate")
	}
}

func TestComputeDigest(t *testing.T) {
	st := newTestStore(t)
	if err := st.UpsertUser(models.User{ID: "admin", Email: "admin", Role: models.RoleAdmin, Password: "hash"}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	dataDir := t.TempDir()
	svc := New(st, dataDir, "node-a", []byte("secret"))
	digest, err := svc.ComputeDigest()
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	if digest.Users.Counter == 0 {
		t.Fatalf("expected non-zero user counter")
	}
}
