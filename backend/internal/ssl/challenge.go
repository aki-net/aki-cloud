package ssl

import (
	"context"
	"time"

	"aki-cloud/backend/internal/models"

	"github.com/go-acme/lego/v4/challenge"
)

// httpChallengeProvider persists ACME http-01 responses via the shared store.
type httpChallengeProvider struct {
	service *Service
}

var _ challenge.Provider = (*httpChallengeProvider)(nil)

func (p *httpChallengeProvider) Present(domain, token, keyAuth string) error {
	return p.service.publishChallenge(domain, token, keyAuth)
}

func (p *httpChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	return p.service.cleanupChallenge(domain, token)
}

func (s *Service) publishChallenge(domain, token, keyAuth string) error {
	now := time.Now().UTC()
	_, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		filtered := rec.TLS.Challenges[:0]
		for _, ch := range rec.TLS.Challenges {
			if ch.Token == token {
				continue
			}
			if !ch.ExpiresAt.IsZero() && ch.ExpiresAt.Before(now.Add(-time.Minute)) {
				continue
			}
			filtered = append(filtered, ch)
		}
		rec.TLS.Challenges = append(filtered, models.ACMEChallenge{
			Token:     token,
			KeyAuth:   keyAuth,
			ExpiresAt: now.Add(20 * time.Minute),
		})
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	if err == nil {
		s.orch.Trigger(context.Background())
	}
	return err
}

func (s *Service) cleanupChallenge(domain, token string) error {
	now := time.Now().UTC()
	_, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		filtered := rec.TLS.Challenges[:0]
		for _, ch := range rec.TLS.Challenges {
			if ch.Token == token {
				continue
			}
			if !ch.ExpiresAt.IsZero() && ch.ExpiresAt.Before(now.Add(-time.Minute)) {
				continue
			}
			filtered = append(filtered, ch)
		}
		rec.TLS.Challenges = filtered
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	if err == nil {
		s.orch.Trigger(context.Background())
	}
	return err
}
