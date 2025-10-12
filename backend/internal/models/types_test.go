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

func TestNodeComputeEdgeIPsAutoDetectsEdges(t *testing.T) {
	node := Node{
		ID:         "node-a",
		Name:       "node-a",
		IPs:        []string{"10.0.0.1", "10.0.0.2", " 10.0.0.2 "},
		NSIPs:      []string{"10.0.0.1"},
		EdgeManual: false,
	}
	node.ComputeEdgeIPs()
	if node.EdgeManual {
		t.Fatalf("expected edge manual to remain false for auto detection")
	}
	if len(node.EdgeIPs) != 1 || node.EdgeIPs[0] != "10.0.0.2" {
		t.Fatalf("expected auto edge ip 10.0.0.2, got %v", node.EdgeIPs)
	}
	if !node.HasRole(NodeRoleEdge) {
		t.Fatalf("expected node to have edge role")
	}
	if !node.HasRole(NodeRoleNameServer) {
		t.Fatalf("expected node to retain nameserver role")
	}
	if !containsString(node.IPs, "10.0.0.2") {
		t.Fatalf("expected computed edge ip to be included in general ip list")
	}
}

func TestNodeComputeEdgeIPsFallsBackToNameservers(t *testing.T) {
	node := Node{
		ID:         "node-b",
		Name:       "node-b",
		IPs:        []string{"10.0.0.3"},
		NSIPs:      []string{"10.0.0.3"},
		EdgeManual: false,
	}
	node.ComputeEdgeIPs()
	if node.EdgeManual {
		t.Fatalf("expected edge manual to remain false for auto detection")
	}
	if len(node.EdgeIPs) != 1 || node.EdgeIPs[0] != "10.0.0.3" {
		t.Fatalf("expected fallback edge ip 10.0.0.3, got %v", node.EdgeIPs)
	}
	if !node.HasRole(NodeRoleEdge) {
		t.Fatalf("expected node to have edge role when fallback occurs")
	}
}

func TestNodeComputeEdgeIPsRespectsManualConfiguration(t *testing.T) {
	node := Node{
		ID:         "node-c",
		Name:       "node-c",
		IPs:        []string{"10.0.0.4", "10.0.0.5"},
		NSIPs:      []string{"10.0.0.4"},
		EdgeIPs:    []string{"10.0.0.5"},
		EdgeManual: true,
	}
	node.ComputeEdgeIPs()
	if !node.EdgeManual {
		t.Fatalf("expected manual flag to be preserved")
	}
	if len(node.EdgeIPs) != 1 || node.EdgeIPs[0] != "10.0.0.5" {
		t.Fatalf("expected manual edge ip to be preserved, got %v", node.EdgeIPs)
	}
}
