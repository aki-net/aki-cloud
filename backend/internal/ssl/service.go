package ssl

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
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
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
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
	retry := now.Add(s.retryInterval())
	if retry.Before(now.Add(5 * time.Minute)) {
		retry = now.Add(5 * time.Minute)
	}
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
