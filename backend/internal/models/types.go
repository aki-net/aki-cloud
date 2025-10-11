package models

import (
	"net"
	"strings"
	"time"
)

// ClockVersion represents Lamport-style version metadata for eventual consistency.
type ClockVersion struct {
	Counter  int64  `json:"counter"`
	NodeID   string `json:"node_id"`
	Updated  int64  `json:"updated_unix"`
	Checksum string `json:"checksum,omitempty"`
}

// MergeClock applies a last-write-wins resolution between two versions.
func MergeClock(local ClockVersion, remote ClockVersion) ClockVersion {
	if remote.Counter > local.Counter {
		return remote
	}
	if remote.Counter < local.Counter {
		return local
	}
	if remote.Updated > local.Updated {
		return remote
	}
	if remote.Updated < local.Updated {
		return local
	}
	if strings.Compare(remote.NodeID, local.NodeID) > 0 {
		return remote
	}
	return local
}

// DomainRecord represents an apex A record for a managed zone.
type DomainRecord struct {
	Domain    string       `json:"domain"`
	Owner     string       `json:"owner"`
	OriginIP  string       `json:"origin_ip"`
	Proxied   bool         `json:"proxied"`
	TTL       int          `json:"ttl"`
	UpdatedAt time.Time    `json:"updated_at"`
	TLS       DomainTLS    `json:"tls,omitempty"`
	Version   ClockVersion `json:"version"`
}

// Validate performs minimal sanity checks.
func (d *DomainRecord) Validate() error {
	if d.Domain == "" {
		return ErrValidation("domain must be provided")
	}
	if net.ParseIP(d.OriginIP) == nil {
		return ErrValidation("origin_ip must be a valid IP address")
	}
	if d.TTL <= 0 {
		d.TTL = 60
	}
	if err := d.TLS.Validate(); err != nil {
		return err
	}
	return nil
}

// EnsureTLSDefaults normalises TLS defaults for backwards compatibility.
func (d *DomainRecord) EnsureTLSDefaults() {
	if d.TLS.Status == "" {
		d.TLS.Status = CertificateStatusNone
	}
	if d.TLS.Mode == "" {
		d.TLS.Mode = EncryptionOff
	}
	if d.TLS.UseRecommended && d.TLS.RecommendedMode == "" {
		d.TLS.RecommendedMode = EncryptionFlexible
	}
}

// Sanitize redacts sensitive TLS material before returning records via API.
func (d DomainRecord) Sanitize() DomainRecord {
	if d.TLS.Certificate != nil {
		cert := *d.TLS.Certificate
		cert.PrivateKeyPEM = ""
		d.TLS.Certificate = &cert
	}
	if d.TLS.OriginPullSecret != nil {
		secret := *d.TLS.OriginPullSecret
		secret.PrivateKeyPEM = ""
		d.TLS.OriginPullSecret = &secret
	}
	d.TLS.LockID = ""
	d.TLS.LockNodeID = ""
	d.TLS.LockExpiresAt = time.Time{}
	return d
}

// EncryptionMode describes client<->edge and edge<->origin TLS behaviour.
type EncryptionMode string

const (
	// EncryptionOff disables TLS at the edge.
	EncryptionOff EncryptionMode = "off"
	// EncryptionFlexible terminates TLS at the edge and talks plaintext to the origin.
	EncryptionFlexible EncryptionMode = "flexible"
	// EncryptionFull terminates TLS at the edge and speaks TLS to the origin without validation.
	EncryptionFull EncryptionMode = "full"
	// EncryptionFullStrict terminates TLS at the edge and enforces CA validation for origin TLS.
	EncryptionFullStrict EncryptionMode = "full_strict"
	// EncryptionStrictOriginPull enforces mutual TLS against the origin using generated client certs.
	EncryptionStrictOriginPull EncryptionMode = "strict_origin_pull"
)

// CertificateStatus captures lifecycle state for edge certificates.
type CertificateStatus string

const (
	// CertificateStatusNone indicates no certificate is provisioned.
	CertificateStatusNone CertificateStatus = "none"
	// CertificateStatusPending indicates an issuance or renewal is in-flight.
	CertificateStatusPending CertificateStatus = "pending"
	// CertificateStatusActive indicates a valid certificate is present.
	CertificateStatusActive CertificateStatus = "active"
	// CertificateStatusErrored indicates issuance failed and needs attention/backoff.
	CertificateStatusErrored CertificateStatus = "errored"
	// CertificateStatusAwaitingDNS indicates the domain has not yet delegated to the edge.
	CertificateStatusAwaitingDNS CertificateStatus = "awaiting_dns"
)

// DomainTLS holds per-domain TLS configuration and runtime status.
type DomainTLS struct {
	Mode             EncryptionMode      `json:"mode"`
	UseRecommended   bool                `json:"use_recommended"`
	RecommendedMode  EncryptionMode      `json:"recommended_mode,omitempty"`
	RecommendedAt    time.Time           `json:"recommended_at,omitempty"`
	Status           CertificateStatus   `json:"status"`
	Certificate      *TLSCertificate     `json:"certificate,omitempty"`
	LastError        string              `json:"last_error,omitempty"`
	LastAttemptAt    time.Time           `json:"last_attempt_at,omitempty"`
	RetryAfter       time.Time           `json:"retry_after,omitempty"`
	LockNodeID       string              `json:"lock_node_id,omitempty"`
	LockID           string              `json:"lock_id,omitempty"`
	LockExpiresAt    time.Time           `json:"lock_expires_at,omitempty"`
	Challenges       []ACMEChallenge     `json:"challenges,omitempty"`
	OriginPullSecret *OriginPullMaterial `json:"origin_pull_secret,omitempty"`
	UpdatedAt        time.Time           `json:"updated_at,omitempty"`
}

// Validate ensures TLS configuration uses supported values.
func (t *DomainTLS) Validate() error {
	switch t.Mode {
	case "", EncryptionOff, EncryptionFlexible, EncryptionFull, EncryptionFullStrict, EncryptionStrictOriginPull:
	default:
		return ErrValidation("invalid tls mode")
	}
	switch t.Status {
	case "", CertificateStatusNone, CertificateStatusPending, CertificateStatusActive, CertificateStatusErrored, CertificateStatusAwaitingDNS:
	default:
		return ErrValidation("invalid tls status")
	}
	return nil
}

// TLSCertificate stores issued certificate material.
type TLSCertificate struct {
	PrivateKeyPEM string    `json:"private_key_pem"`
	CertChainPEM  string    `json:"cert_chain_pem"`
	IssuerPEM     string    `json:"issuer_pem,omitempty"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Issuer        string    `json:"issuer,omitempty"`
	SerialNumber  string    `json:"serial_number,omitempty"`
	CertURL       string    `json:"cert_url,omitempty"`
	CertStableURL string    `json:"cert_stable_url,omitempty"`
}

// ACMEChallenge represents a pending HTTP-01 challenge that must be published.
type ACMEChallenge struct {
	Token          string    `json:"token"`
	KeyAuth        string    `json:"key_authorization"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	ChallengeType  string    `json:"challenge_type,omitempty"`
	Authorization  string    `json:"authorization_url,omitempty"`
	VerificationAt time.Time `json:"verification_at,omitempty"`
}

// OriginPullMaterial stores client certificate assets for strict origin pull.
type OriginPullMaterial struct {
	CertificatePEM string    `json:"certificate_pem"`
	PrivateKeyPEM  string    `json:"private_key_pem"`
	CAPEM          string    `json:"ca_pem"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	Fingerprint    string    `json:"fingerprint,omitempty"`
}

// UserRole describes supported account roles.
type UserRole string

const (
	// RoleAdmin is for cluster operators.
	RoleAdmin UserRole = "admin"
	// RoleUser is for regular domain owners.
	RoleUser UserRole = "user"
)

// User represents an authenticated operator.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      UserRole  `json:"role"`
	Password  string    `json:"password"` // hashed
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Sanitize clears sensitive fields before returning API payloads.
func (u User) Sanitize() User {
	u.Password = ""
	return u
}

// Node represents an infrastructure node managed by the admin.
type Node struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	IPs          []string   `json:"ips"`
	NSIPs        []string   `json:"ns_ips"`
	NSLabel      string     `json:"ns_label,omitempty"`
	NSBase       string     `json:"ns_base_domain,omitempty"`
	APIEndpoint  string     `json:"api_endpoint,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	ManagedNS    []string   `json:"managed_ns,omitempty"`
	EdgeIPs      []string   `json:"edge_ips,omitempty"`
	LastSeenAt   time.Time  `json:"last_seen_at,omitempty"`
	Status       NodeStatus `json:"status,omitempty"`
	StatusMsg    string     `json:"status_message,omitempty"`
	HealthyEdges int        `json:"healthy_edges,omitempty"`
	TotalEdges   int        `json:"total_edges,omitempty"`
	LastHealthAt time.Time  `json:"last_health_at,omitempty"`
}

// ComputeEdgeIPs populates EdgeIPs by removing NS IPs from the full list.
func (n *Node) ComputeEdgeIPs() {
	ns := make(map[string]struct{}, len(n.NSIPs))
	for _, ip := range n.NSIPs {
		ns[ip] = struct{}{}
	}
	edges := make([]string, 0, len(n.IPs))
	for _, ip := range n.IPs {
		if _, ok := ns[ip]; ok {
			continue
		}
		edges = append(edges, ip)
	}
	n.EdgeIPs = edges
}

// NodeStatus represents the current health gate for a node's edge capacity.
type NodeStatus string

const (
	NodeStatusPending  NodeStatus = "pending"
	NodeStatusHealthy  NodeStatus = "healthy"
	NodeStatusDegraded NodeStatus = "degraded"
	NodeStatusOffline  NodeStatus = "offline"
	NodeStatusIdle     NodeStatus = "idle"
)

// EdgeHealthStatus describes the current reachability of an edge IP.
type EdgeHealthStatus struct {
	IP           string       `json:"ip"`
	Healthy      bool         `json:"healthy"`
	LastChecked  time.Time    `json:"last_checked"`
	FailureCount int          `json:"failure_count"`
	Message      string       `json:"message,omitempty"`
	Version      ClockVersion `json:"version"`
}

// MergeEdgeHealth applies LWW semantics for edge health records.
func MergeEdgeHealth(local EdgeHealthStatus, remote EdgeHealthStatus) EdgeHealthStatus {
	if local.IP == "" {
		return remote
	}
	if remote.IP == "" {
		return local
	}
	winner := MergeClock(local.Version, remote.Version)
	if winner == remote.Version {
		return remote
	}
	return local
}

// NameServerHealth captures the latest health probe result for an NS endpoint.
type NameServerHealth struct {
	NodeID    string    `json:"node_id"`
	FQDN      string    `json:"fqdn"`
	IPv4      string    `json:"ipv4"`
	Healthy   bool      `json:"healthy"`
	LatencyMS int64     `json:"latency_ms"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// ErrValidation indicates input validation failure.
type ErrValidation string

func (e ErrValidation) Error() string {
	return string(e)
}
