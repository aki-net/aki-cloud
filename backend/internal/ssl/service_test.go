package ssl

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"errors"

	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

func newTestService(t *testing.T, dataDir string, st *store.Store, nodeID string) *Service {
	t.Helper()
	cfg := &config.Config{
		DataDir:        dataDir,
		NodeID:         nodeID,
		ACMELockTTL:    10 * time.Minute,
		ACMERetryAfter: 15 * time.Minute,
	}
	return &Service{
		cfg:        cfg,
		store:      st,
		account:    newAccountStore(cfg.DataDir),
		backoffs:   newBackoffStore(cfg.DataDir),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func TestShouldAttemptDomainPrefersCoordinator(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	nodes := []models.Node{
		{ID: "node-a", IPs: []string{"10.0.0.1"}, NSIPs: []string{}},
		{ID: "node-b", IPs: []string{"10.0.0.2"}, NSIPs: []string{}},
		{ID: "node-c", IPs: []string{"10.0.0.3"}, NSIPs: []string{}},
	}
	if err := st.SaveNodes(nodes); err != nil {
		t.Fatalf("SaveNodes: %v", err)
	}

	candidates := coordinatorCandidates(nodes, nil, "node-a")
	domain := "example.com"
	assigned := selectCoordinator(domain, candidates)
	if assigned == "" {
		t.Fatalf("no coordinator assigned for %q", domain)
	}

	var other string
	for _, node := range nodes {
		if node.ID != assigned {
			other = node.ID
			break
		}
	}
	if other == "" {
		t.Fatal("expected secondary node id")
	}

	rec := models.DomainRecord{Domain: domain, Proxied: true}
	rec.EnsureTLSDefaults()

	svcAssigned := newTestService(t, dir, st, assigned)
	if !svcAssigned.shouldAttemptDomain(rec) {
		t.Fatalf("expected assigned node %q to attempt", assigned)
	}

	svcOther := newTestService(t, dir, st, other)
	if svcOther.shouldAttemptDomain(rec) {
		t.Fatalf("expected non-assigned node %q to skip", other)
	}
}

func TestShouldAttemptDomainSkipsUnhealthyCoordinator(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	nodes := []models.Node{
		{ID: "node-a", IPs: []string{"10.1.0.1"}, NSIPs: []string{}},
		{ID: "node-b", IPs: []string{"10.1.0.2"}, NSIPs: []string{}},
	}
	if err := st.SaveNodes(nodes); err != nil {
		t.Fatalf("SaveNodes: %v", err)
	}

	candidates := coordinatorCandidates(nodes, nil, "node-a")
	var domain string
	target := "node-b"
	for i := 0; i < 512; i++ {
		name := fmt.Sprintf("test-%d.example.com", i)
		if selectCoordinator(name, candidates) == target {
			domain = name
			break
		}
	}
	if domain == "" {
		t.Fatalf("unable to find domain assigned to %q", target)
	}

	statuses := []models.EdgeHealthStatus{
		{IP: "10.1.0.1", Healthy: true},
		{IP: "10.1.0.2", Healthy: false},
	}
	if err := st.SaveEdgeHealth(statuses); err != nil {
		t.Fatalf("SaveEdgeHealth: %v", err)
	}

	rec := models.DomainRecord{Domain: domain, Proxied: true}
	rec.EnsureTLSDefaults()

	svcHealthy := newTestService(t, dir, st, "node-a")
	if !svcHealthy.shouldAttemptDomain(rec) {
		t.Fatalf("expected healthy node to take over for domain %q", domain)
	}

	svcUnhealthy := newTestService(t, dir, st, "node-b")
	if svcUnhealthy.shouldAttemptDomain(rec) {
		t.Fatalf("expected unhealthy node %q to skip domain %q", "node-b", domain)
	}
}

func TestShouldAttemptDomainAllowsStaleFallback(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	nodes := []models.Node{
		{ID: "node-a", IPs: []string{"10.2.0.1"}, NSIPs: []string{}},
		{ID: "node-b", IPs: []string{"10.2.0.2"}, NSIPs: []string{}},
	}
	if err := st.SaveNodes(nodes); err != nil {
		t.Fatalf("SaveNodes: %v", err)
	}

	candidates := coordinatorCandidates(nodes, nil, "node-a")
	domain := "fallback.example.com"
	assigned := selectCoordinator(domain, candidates)
	if assigned == "" {
		t.Fatalf("no coordinator assigned for %q", domain)
	}

	var other string
	for _, node := range nodes {
		if node.ID != assigned {
			other = node.ID
			break
		}
	}
	if other == "" {
		t.Fatal("expected alternative node id")
	}

	rec := models.DomainRecord{Domain: domain, Proxied: true}
	rec.EnsureTLSDefaults()
	svcAssigned := newTestService(t, dir, st, assigned)
	rec.TLS.LastAttemptAt = time.Now().Add(-svcAssigned.coordinatorStaleThreshold()).Add(-time.Minute)

	svcOther := newTestService(t, dir, st, other)
	if !svcOther.shouldAttemptDomain(rec) {
		t.Fatalf("expected node %q to take over after stale attempt", other)
	}
}

func TestNextRetryParsesRetryAfterTimestamp(t *testing.T) {
	now := time.Date(2025, 10, 9, 12, 0, 0, 0, time.UTC)
	msg := "acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2025-10-09 13:39:27 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"
	got := nextRetry(now, 15*time.Minute, errors.New(msg))
	want := time.Date(2025, 10, 9, 13, 39, 27, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("expected retry %v, got %v", want, got)
	}
}

func TestNextRetryFallsBackToMinimum(t *testing.T) {
	now := time.Now().UTC()
	got := nextRetry(now, 2*time.Minute, errors.New("random error"))
	min := now.Add(5 * time.Minute)
	if got.Before(min) {
		t.Fatalf("expected fallback retry >= %v, got %v", min, got)
	}
}

func TestRateLimitBackoffPersistsAcrossToggle(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	svc := newTestService(t, dir, st, "node-a")

	rec := models.DomainRecord{
		Domain:   "toggle.example.com",
		Owner:    "user",
		OriginIP: "203.0.113.10",
		Proxied:  true,
	}
	rec.EnsureTLSDefaults()
	if err := st.SaveDomain(rec); err != nil {
		t.Fatalf("SaveDomain: %v", err)
	}

	errMsg := "acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2025-10-09 13:39:27 UTC"
	svc.markError(rec.Domain, "lock-1", true, errors.New(errMsg))

	entry, err := svc.backoffs.Get(rec.Domain)
	if err != nil {
		t.Fatalf("backoffs.Get: %v", err)
	}
	if entry == nil {
		t.Fatalf("expected backoff entry to exist")
	}

	if _, err := st.MutateDomain(rec.Domain, func(r *models.DomainRecord) error {
		r.TLS.RetryAfter = time.Time{}
		r.TLS.LastError = ""
		r.TLS.Status = models.CertificateStatusNone
		return nil
	}); err != nil {
		t.Fatalf("MutateDomain reset: %v", err)
	}

	current, err := st.GetDomain(rec.Domain)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	issued := 0
	if err := svc.reconcileDomain(context.Background(), *current, &issued); err != nil {
		t.Fatalf("reconcileDomain: %v", err)
	}

	updated, err := st.GetDomain(rec.Domain)
	if err != nil {
		t.Fatalf("GetDomain post reconcile: %v", err)
	}
	if !updated.TLS.RetryAfter.Equal(entry.RetryAfter) {
		t.Fatalf("expected retryAfter %v, got %v", entry.RetryAfter, updated.TLS.RetryAfter)
	}
	if updated.TLS.LastError == "" {
		t.Fatalf("expected last error to be preserved")
	}
	if updated.TLS.Status != models.CertificateStatusErrored {
		t.Fatalf("expected status errored, got %s", updated.TLS.Status)
	}
}

func TestRateLimitBackoffCarriesThroughRecreate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	svc := newTestService(t, dir, st, "node-a")

	rec := models.DomainRecord{
		Domain:   "recreate.example.com",
		Owner:    "user",
		OriginIP: "198.51.100.10",
		Proxied:  true,
	}
	rec.EnsureTLSDefaults()
	if err := st.SaveDomain(rec); err != nil {
		t.Fatalf("SaveDomain: %v", err)
	}

	errMsg := "acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2025-10-09 13:39:27 UTC"
	svc.markError(rec.Domain, "lock-1", true, errors.New(errMsg))

	if err := st.DeleteDomain(rec.Domain); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}

	newRec := models.DomainRecord{
		Domain:   rec.Domain,
		Owner:    rec.Owner,
		OriginIP: rec.OriginIP,
		Proxied:  true,
	}
	newRec.EnsureTLSDefaults()
	if err := st.SaveDomain(newRec); err != nil {
		t.Fatalf("SaveDomain new rec: %v", err)
	}

	current, err := st.GetDomain(newRec.Domain)
	if err != nil {
		t.Fatalf("GetDomain new: %v", err)
	}
	issued := 0
	if err := svc.reconcileDomain(context.Background(), *current, &issued); err != nil {
		t.Fatalf("reconcileDomain: %v", err)
	}

	updated, err := st.GetDomain(newRec.Domain)
	if err != nil {
		t.Fatalf("GetDomain updated: %v", err)
	}
	entry, err := svc.backoffs.Get(newRec.Domain)
	if err != nil {
		t.Fatalf("backoffs.Get: %v", err)
	}
	if entry == nil {
		t.Fatalf("expected rate limit entry to remain after recreate")
	}
	if !updated.TLS.RetryAfter.Equal(entry.RetryAfter) {
		t.Fatalf("expected retryAfter %v, got %v", entry.RetryAfter, updated.TLS.RetryAfter)
	}
	if updated.TLS.LastError == "" {
		t.Fatalf("expected last error to be populated")
	}
}
