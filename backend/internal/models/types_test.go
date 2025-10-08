package models

import (
	"testing"
	"time"
)

func TestEnsureTLSDefaults(t *testing.T) {
	rec := &DomainRecord{TLS: DomainTLS{}}
	rec.EnsureTLSDefaults()
	if rec.TLS.Status != CertificateStatusNone {
		t.Fatalf("expected status none, got %s", rec.TLS.Status)
	}
	if rec.TLS.Mode != EncryptionOff {
		t.Fatalf("expected mode off, got %s", rec.TLS.Mode)
	}
}

func TestSanitizeRedactsSecrets(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour).UTC()
	rec := DomainRecord{
		Domain: "example.test",
		TLS: DomainTLS{
			Status: CertificateStatusActive,
			Certificate: &TLSCertificate{
				PrivateKeyPEM: "PRIVATE",
				CertChainPEM:  "CERT",
				NotAfter:      expiry,
			},
			OriginPullSecret: &OriginPullMaterial{
				PrivateKeyPEM:  "ORIGIN_PRIVATE",
				CertificatePEM: "ORIGIN_CERT",
			},
			LockID:        "lock",
			LockNodeID:    "node",
			LockExpiresAt: time.Now().Add(time.Hour),
		},
	}
	sanitized := rec.Sanitize()
	if sanitized.TLS.Certificate == nil {
		t.Fatalf("expected certificate to persist")
	}
	if sanitized.TLS.Certificate.PrivateKeyPEM != "" {
		t.Fatalf("expected private key to be redacted")
	}
	if sanitized.TLS.Certificate.CertChainPEM != "CERT" {
		t.Fatalf("expected certificate chain retained")
	}
	if sanitized.TLS.OriginPullSecret == nil || sanitized.TLS.OriginPullSecret.PrivateKeyPEM != "" {
		t.Fatalf("expected origin pull private key redacted")
	}
	if sanitized.TLS.LockID != "" || sanitized.TLS.LockNodeID != "" {
		t.Fatalf("expected lock metadata cleared")
	}
	if !sanitized.TLS.LockExpiresAt.IsZero() {
		t.Fatalf("expected lock expiry cleared")
	}
}
