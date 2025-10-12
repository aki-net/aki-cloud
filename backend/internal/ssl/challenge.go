package ssl

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

const (
	challengeTypeHTTP = "http-01"
	challengeTypeDNS  = "dns-01"
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

type dnsChallengeProvider struct {
	service *Service
}

var _ challenge.Provider = (*dnsChallengeProvider)(nil)

func (p *dnsChallengeProvider) Present(domain, token, keyAuth string) error {
	return p.service.publishDNSChallenge(domain, token, keyAuth)
}

func (p *dnsChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	return p.service.cleanupChallenge(domain, token)
}

func (s *Service) publishChallenge(domain, token, keyAuth string) error {
	now := time.Now().UTC()
	challenge := models.ACMEChallenge{
		Token:         token,
		KeyAuth:       keyAuth,
		ChallengeType: challengeTypeHTTP,
		ExpiresAt:     now.Add(20 * time.Minute),
	}
	if err := s.addChallenge(domain, challenge, now); err != nil {
		return err
	}
	s.orch.Trigger(context.Background())
	return nil
}

func (s *Service) publishDNSChallenge(domain, token, keyAuth string) error {
	now := time.Now().UTC()
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.TrimSuffix(info.FQDN, ".")
	challenge := models.ACMEChallenge{
		Token:         token,
		KeyAuth:       keyAuth,
		ChallengeType: challengeTypeDNS,
		ExpiresAt:     now.Add(30 * time.Minute),
		DNSName:       fqdn,
		DNSValue:      info.Value,
	}
	if err := s.addChallenge(domain, challenge, now); err != nil {
		return err
	}
	s.orch.Trigger(context.Background())
	return nil
}

func (s *Service) addChallenge(domain string, challenge models.ACMEChallenge, now time.Time) error {
	if domain == "" {
		return errors.New("domain must be provided for challenge")
	}
	token := strings.TrimSpace(challenge.Token)
	if token == "" {
		return errors.New("challenge token missing")
	}
	if challenge.ExpiresAt.IsZero() {
		challenge.ExpiresAt = now.Add(20 * time.Minute)
	}
	challenge.Token = token
	_, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		rec.EnsureTLSDefaults()
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
		rec.TLS.Challenges = append(filtered, challenge)
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
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
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	s.orch.Trigger(context.Background())
	return nil
}
