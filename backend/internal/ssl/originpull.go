package ssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
)

func (s *Service) ensureOriginPullMaterial(domain string) error {
	now := time.Now().UTC()
	_, err := s.store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		rec.EnsureTLSDefaults()
		if rec.TLS.OriginPullSecret != nil && rec.TLS.OriginPullSecret.NotAfter.After(now.Add(90*24*time.Hour)) {
			return nil
		}
		bundle, err := generateOriginPullBundle(domain)
		if err != nil {
			return err
		}
		rec.TLS.OriginPullSecret = bundle
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

func generateOriginPullBundle(domain string) (*models.OriginPullMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "aki-cloud Origin Pull CA",
			Organization: []string{"aki-cloud"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	clientSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("aki-cloud Origin Pull %s", domain),
			Organization: []string{"aki-cloud"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	fingerprint := sha256.Sum256(clientDER)
	return &models.OriginPullMaterial{
		CertificatePEM: string(append(certPEM, caPEM...)),
		PrivateKeyPEM:  string(keyPEM),
		CAPEM:          string(caPEM),
		NotBefore:      clientTemplate.NotBefore.UTC(),
		NotAfter:       clientTemplate.NotAfter.UTC(),
		Fingerprint:    strings.ToUpper(hex.EncodeToString(fingerprint[:])),
	}, nil
}
