package ssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func (s *Service) newACMEClient() (*lego.Client, *acmeUser, error) {
	user, err := s.account.Load()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if errors.Is(err, os.ErrNotExist) || user == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		user = &acmeUser{
			email: s.cfg.ACMEEmail,
			key:   key,
		}
	}
	conf := lego.NewConfig(user)
	conf.CADirURL = s.cfg.ACMEDirectory
	conf.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(conf)
	if err != nil {
		return nil, nil, err
	}
	if user.registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, err
		}
		user.registration = reg
		if err := s.account.Save(user); err != nil {
			log.Printf("tls: unable to persist acme account: %v", err)
		}
	}
	return client, user, nil
}

func (s *Service) obtainCertificate(client *lego.Client, rec models.DomainRecord) (*certificate.Resource, error) {
	domains := uniqueDomains(rec.Domain)
	if rec.TLS.Certificate != nil && rec.TLS.Certificate.CertChainPEM != "" {
		resource := certificate.Resource{
			Domain:            rec.Domain,
			Certificate:       []byte(rec.TLS.Certificate.CertChainPEM),
			PrivateKey:        []byte(rec.TLS.Certificate.PrivateKeyPEM),
			IssuerCertificate: []byte(rec.TLS.Certificate.IssuerPEM),
			CertURL:           rec.TLS.Certificate.CertURL,
			CertStableURL:     rec.TLS.Certificate.CertStableURL,
		}
		renewed, err := client.Certificate.Renew(resource, true, false, "")
		if err == nil {
			return renewed, nil
		}
		log.Printf("tls: renew failed for %s, requesting fresh order: %v", rec.Domain, err)
	}
	return client.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
}

func uniqueDomains(root string) []string {
	base := strings.TrimSpace(root)
	set := map[string]struct{}{}
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if _, ok := set[name]; !ok {
			set[name] = struct{}{}
		}
	}
	add(base)
	if !strings.HasPrefix(base, "*.") {
		add("www." + base)
	}
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (s *Service) persistCertificate(domain string, res *certificate.Resource, lockID string) error {
	if res == nil {
		return errors.New("empty certificate resource")
	}
	certs, err := certcrypto.ParsePEMBundle(res.Certificate)
	if err != nil || len(certs) == 0 {
		return fmt.Errorf("parse certificate chain: %w", err)
	}
	leaf := certs[0]
	issuerPEM := string(res.IssuerCertificate)
	if issuerPEM == "" {
		issuerPEM = string(res.Certificate)
	}
	now := time.Now().UTC()
	_, err = s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		rec.EnsureTLSDefaults()
		if rec.TLS.LockID == lockID {
			rec.TLS.LockID = ""
			rec.TLS.LockNodeID = ""
			rec.TLS.LockExpiresAt = time.Time{}
		}
		rec.TLS.Status = models.CertificateStatusActive
		rec.TLS.LastError = ""
		rec.TLS.RetryAfter = time.Time{}
		rec.TLS.Challenges = nil
		rec.TLS.Certificate = &models.TLSCertificate{
			PrivateKeyPEM: string(res.PrivateKey),
			CertChainPEM:  string(res.Certificate),
			IssuerPEM:     issuerPEM,
			NotBefore:     leaf.NotBefore.UTC(),
			NotAfter:      leaf.NotAfter.UTC(),
			Issuer:        leaf.Issuer.CommonName,
			SerialNumber:  leaf.SerialNumber.Text(16),
			CertURL:       res.CertURL,
			CertStableURL: res.CertStableURL,
		}
		rec.TLS.UpdatedAt = now
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.cfg.NodeID
		rec.Version.Updated = now.Unix()
		return nil
	})
	return err
}

// acmeUser implements lego.User.
type acmeUser struct {
	email        string
	key          *ecdsa.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string { return u.email }

func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey { return u.key }

func (u *acmeUser) toSerializable() (*accountPayload, error) {
	if u.key == nil {
		return nil, errors.New("missing private key")
	}
	keyBytes, err := x509.MarshalECPrivateKey(u.key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return &accountPayload{
		Email:        u.email,
		KeyPEM:       string(pemBytes),
		Registration: u.registration,
	}, nil
}

func (u *acmeUser) fromSerializable(payload *accountPayload) error {
	if payload == nil {
		return nil
	}
	block, _ := pem.Decode([]byte(payload.KeyPEM))
	if block == nil {
		return errors.New("invalid PEM data")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	u.email = payload.Email
	u.key = key
	u.registration = payload.Registration
	return nil
}
