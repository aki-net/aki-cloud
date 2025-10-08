package ssl

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/orchestrator"
	"aki-cloud/backend/internal/store"

	"github.com/google/uuid"
)

const (
	recomputeRecommendationAfter = 12 * time.Hour
	reconcileInterval            = 1 * time.Minute
)

var (
	errLockHeld = errors.New("certificate issuance already in progress")
	errBackoff  = errors.New("waiting for retry window")
)

// Service orchestrates TLS recommendations, issuance, and renewals.
type Service struct {
	cfg        *config.Config
	store      *store.Store
	orch       *orchestrator.Service
	account    *accountStore
	httpClient *http.Client
}

// New constructs a TLS service bound to repository state.
func New(cfg *config.Config, st *store.Store, orch *orchestrator.Service) *Service {
	return &Service{
		cfg:        cfg,
		store:      st,
		orch:       orch,
		account:    newAccountStore(cfg.DataDir),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Start runs the reconciliation loop until context cancellation.
func (s *Service) Start(ctx context.Context) {
	if !s.cfg.ACMEEnabled {
		log.Println("tls: ACME disabled via configuration")
		return
	}
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	s.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcile(ctx)
		}
	}
}

func (s *Service) reconcile(ctx context.Context) {
	domains, err := s.store.GetDomains()
	if err != nil {
		log.Printf("tls: list domains failed: %v", err)
		return
	}
	for _, rec := range domains {
		if ctx.Err() != nil {
			return
		}
		if err := s.reconcileDomain(ctx, rec); err != nil {
			log.Printf("tls: domain %s reconciliation error: %v", rec.Domain, err)
		}
	}
}

func (s *Service) reconcileDomain(ctx context.Context, rec models.DomainRecord) error {
	rec.EnsureTLSDefaults()
	if !rec.Proxied {
		return nil
	}

	if updated, err := s.ensureRecommendation(ctx, rec); err != nil {
		return err
	} else if updated != nil {
		rec = *updated
	}

	mode := s.effectiveMode(rec)
	if mode == models.EncryptionOff {
		return nil
	}

	if !s.needsCertificate(rec, mode) {
		return nil
	}

	if !s.shouldAttemptDomain(rec) {
		return nil
	}

	lockID, lockedRec, err := s.acquireLock(rec.Domain)
	if err != nil {
		if errors.Is(err, errLockHeld) || errors.Is(err, errBackoff) {
			return nil
		}
		return err
	}
	if lockID == "" || lockedRec == nil {
		return nil
	}

	keepAuto := lockedRec.TLS.UseRecommended
	if err := s.issueCertificate(ctx, *lockedRec, mode, lockID); err != nil {
		s.markError(rec.Domain, lockID, keepAuto, err)
		return err
	}
	return nil
}

func (s *Service) effectiveMode(rec models.DomainRecord) models.EncryptionMode {
	if rec.TLS.UseRecommended && rec.TLS.RecommendedMode != "" {
		return rec.TLS.RecommendedMode
	}
	if rec.TLS.Mode == "" {
		return models.EncryptionFlexible
	}
	return rec.TLS.Mode
}

func (s *Service) ensureRecommendation(ctx context.Context, rec models.DomainRecord) (*models.DomainRecord, error) {
	if !s.cfg.TLSRecommender {
		return nil, nil
	}
	if !rec.TLS.UseRecommended {
		return nil, nil
	}
	now := time.Now().UTC()
	if !rec.TLS.RecommendedAt.IsZero() && now.Sub(rec.TLS.RecommendedAt) < recomputeRecommendationAfter {
		return nil, nil
	}
	mode := s.detectRecommendedMode(ctx, rec)
	updated, err := s.store.MutateDomain(rec.Domain, func(r *models.DomainRecord) error {
		r.EnsureTLSDefaults()
		r.TLS.RecommendedMode = mode
		r.TLS.RecommendedAt = now
		r.TLS.UpdatedAt = now
		r.UpdatedAt = now
		r.Version.Counter++
		r.Version.NodeID = s.cfg.NodeID
		r.Version.Updated = now.Unix()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *Service) detectRecommendedMode(ctx context.Context, rec models.DomainRecord) models.EncryptionMode {
	valid, any := s.probeOriginTLS(ctx, rec)
	if valid {
		return models.EncryptionFullStrict
	}
	if any {
		return models.EncryptionFull
	}
	if s.probeOriginHTTP(ctx, rec) {
		return models.EncryptionFlexible
	}
	return models.EncryptionOff
}

func (s *Service) probeOriginTLS(ctx context.Context, rec models.DomainRecord) (valid bool, any bool) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conf := &tls.Config{ServerName: rec.Domain}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(rec.OriginIP, "443"), conf)
	if err == nil {
		_ = conn.Close()
		return true, true
	}
	conf = &tls.Config{ServerName: rec.Domain, InsecureSkipVerify: true}
	conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(rec.OriginIP, "443"), conf)
	if err == nil {
		_ = conn.Close()
		return false, true
	}
	return false, false
}

func (s *Service) probeOriginHTTP(ctx context.Context, rec models.DomainRecord) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, fmt.Sprintf("http://%s", rec.OriginIP), nil)
	if err != nil {
		return false
	}
	req.Host = rec.Domain
	resp, err := s.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return true
		}
	}
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s", rec.OriginIP), nil)
	if err != nil {
		return false
	}
	getReq.Host = rec.Domain
	getResp, err := s.httpClient.Do(getReq)
	if err != nil {
		conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(rec.OriginIP, "80"), 5*time.Second)
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	getResp.Body.Close()
	return getResp.StatusCode < 500
}

func (s *Service) needsCertificate(rec models.DomainRecord, mode models.EncryptionMode) bool {
	now := time.Now().UTC()
	if rec.TLS.RetryAfter.After(now) {
		return false
	}
	if rec.TLS.Status == models.CertificateStatusPending && rec.TLS.LockExpiresAt.After(now) {
		return false
	}
	if rec.TLS.Certificate == nil || rec.TLS.Certificate.CertChainPEM == "" {
		return true
	}
	if rec.TLS.Certificate.NotAfter.IsZero() {
		return true
	}
	renewBefore := s.cfg.ACMERenewBefore
	if renewBefore <= 0 {
		renewBefore = 30 * 24 * time.Hour
	}
	return rec.TLS.Certificate.NotAfter.Sub(now) <= renewBefore
}

func (s *Service) acquireLock(domain string) (string, *models.DomainRecord, error) {
	now := time.Now().UTC()
	lockID := uuid.NewString()
	updated, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		rec.EnsureTLSDefaults()
		if rec.TLS.RetryAfter.After(now) {
			return errBackoff
		}
		if rec.TLS.LockID != "" && rec.TLS.LockNodeID != "" && rec.TLS.LockExpiresAt.After(now) && rec.TLS.LockNodeID != s.cfg.NodeID {
			return errLockHeld
		}
		rec.TLS.LockID = lockID
		rec.TLS.LockNodeID = s.cfg.NodeID
		rec.TLS.LockExpiresAt = now.Add(s.cfg.ACMELockTTL)
		rec.TLS.Status = models.CertificateStatusPending
		rec.TLS.LastAttemptAt = now
		rec.TLS.LastError = ""
		rec.TLS.RetryAfter = time.Time{}
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return lockID, updated, nil
}

func (s *Service) releaseLock(domain, lockID string) {
	now := time.Now().UTC()
	_, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		if rec.TLS.LockID != lockID {
			return nil
		}
		rec.TLS.LockID = ""
		rec.TLS.LockNodeID = ""
		rec.TLS.LockExpiresAt = time.Time{}
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	if err != nil {
		log.Printf("tls: release lock for %s failed: %v", domain, err)
	}
}

func (s *Service) markError(domain, lockID string, keepAuto bool, issueErr error) {
	now := time.Now().UTC()
	retry := nextRetry(now, s.retryInterval(), issueErr)
	_, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		if keepAuto {
			rec.TLS.UseRecommended = true
		}
		if rec.TLS.LockID == lockID {
			rec.TLS.LockID = ""
			rec.TLS.LockNodeID = ""
			rec.TLS.LockExpiresAt = time.Time{}
		}
		rec.TLS.Status = models.CertificateStatusErrored
		rec.TLS.LastError = issueErr.Error()
		rec.TLS.RetryAfter = retry
		rec.TLS.Challenges = nil
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	if err != nil {
		log.Printf("tls: mark error on %s failed: %v", domain, err)
	}
	s.orch.Trigger(context.Background())
}

func (s *Service) retryInterval() time.Duration {
	if s.cfg.ACMERetryAfter <= 0 {
		return 15 * time.Minute
	}
	return s.cfg.ACMERetryAfter
}

var retryAfterRegexp = regexp.MustCompile(`retry after ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) UTC`)

func nextRetry(now time.Time, fallback time.Duration, issueErr error) time.Time {
	if issueErr != nil {
		if match := retryAfterRegexp.FindStringSubmatch(issueErr.Error()); len(match) == 2 {
			if ts, err := time.ParseInLocation("2006-01-02 15:04:05", match[1], time.UTC); err == nil && ts.After(now) {
				return ts
			}
		}
	}
	retry := now.Add(fallback)
	minRetry := now.Add(5 * time.Minute)
	if retry.Before(minRetry) {
		return minRetry
	}
	return retry
}

func (s *Service) shouldAttemptDomain(rec models.DomainRecord) bool {
	if rec.TLS.LockNodeID != "" && rec.TLS.LockNodeID == s.cfg.NodeID {
		return true
	}

	nodes, err := s.store.GetNodes()
	if err != nil {
		log.Printf("tls: unable to list nodes: %v", err)
		return true
	}

	health, err := s.store.GetEdgeHealthMap()
	if err != nil {
		log.Printf("tls: unable to load edge health: %v", err)
		health = nil
	}

	candidates := coordinatorCandidates(nodes, health, s.cfg.NodeID)
	if len(candidates) == 0 {
		return true
	}

	assigned := selectCoordinator(rec.Domain, candidates)
	if assigned == "" || assigned == s.cfg.NodeID {
		return true
	}

	if !nodeHealthyByID(assigned, nodes, health) {
		return true
	}

	now := time.Now().UTC()
	threshold := s.coordinatorStaleThreshold()
	if threshold > 0 && !rec.TLS.LastAttemptAt.IsZero() && now.Sub(rec.TLS.LastAttemptAt) > threshold {
		return true
	}

	return false
}

func (s *Service) coordinatorStaleThreshold() time.Duration {
	lockTTL := s.cfg.ACMELockTTL
	if lockTTL <= 0 {
		lockTTL = 10 * time.Minute
	}
	retry := s.retryInterval()
	if retry <= 0 {
		retry = 15 * time.Minute
	}
	threshold := maxDuration(lockTTL, retry)
	if threshold < 5*time.Minute {
		threshold = 5 * time.Minute
	}
	return threshold
}

func coordinatorCandidates(nodes []models.Node, health map[string]models.EdgeHealthStatus, selfID string) []string {
	healthy := make([]string, 0, len(nodes))
	fallback := make([]string, 0, len(nodes))
	for _, node := range nodes {
		node.ComputeEdgeIPs()
		if len(node.EdgeIPs) == 0 {
			continue
		}
		fallback = append(fallback, node.ID)
		if nodeHealthy(node, health) {
			healthy = append(healthy, node.ID)
		}
	}
	ids := healthy
	if len(ids) == 0 {
		ids = fallback
	}
	if len(ids) == 0 && selfID != "" {
		ids = []string{selfID}
	}
	sort.Strings(ids)
	return uniqueStrings(ids)
}

func nodeHealthy(node models.Node, health map[string]models.EdgeHealthStatus) bool {
	if len(node.EdgeIPs) == 0 {
		return false
	}
	if len(health) == 0 {
		return true
	}
	for _, ip := range node.EdgeIPs {
		if status, ok := health[ip]; !ok || status.Healthy {
			return true
		}
	}
	return false
}

func nodeHealthyByID(id string, nodes []models.Node, health map[string]models.EdgeHealthStatus) bool {
	for _, node := range nodes {
		if node.ID != id {
			continue
		}
		node.ComputeEdgeIPs()
		return nodeHealthy(node, health)
	}
	return false
}

func selectCoordinator(domain string, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	hash := hashDomain(domain)
	index := hash % uint64(len(candidates))
	return candidates[index]
}

func hashDomain(domain string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(domain)))
	return h.Sum64()
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:0]
	prev := ""
	for i, val := range values {
		if i == 0 || val != prev {
			out = append(out, val)
			prev = val
		}
	}
	return out
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (s *Service) issueCertificate(ctx context.Context, rec models.DomainRecord, mode models.EncryptionMode, lockID string) error {
	defer s.releaseLock(rec.Domain, lockID)

	if err := ctx.Err(); err != nil {
		return err
	}

	client, user, err := s.newACMEClient()
	if err != nil {
		return fmt.Errorf("acme client: %w", err)
	}
	provider := &httpChallengeProvider{service: s}
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return fmt.Errorf("http-01 provider: %w", err)
	}

	obtained, err := s.obtainCertificate(client, rec)
	if err != nil {
		return err
	}

	if err := s.persistCertificate(rec.Domain, obtained, lockID); err != nil {
		return err
	}
	if err := s.account.Save(user); err != nil {
		log.Printf("tls: account save failed: %v", err)
	}
	if mode == models.EncryptionStrictOriginPull {
		if err := s.ensureOriginPullMaterial(rec.Domain); err != nil {
			log.Printf("tls: origin pull generation failed for %s: %v", rec.Domain, err)
		}
	}
	s.orch.Trigger(context.Background())
	return nil
}

// obtainCertificate lives in acme.go
// persistCertificate lives in acme.go
// ensureOriginPullMaterial lives in originpull.go
