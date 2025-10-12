package models

import (
	"net"
	"sort"
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
	Edge      DomainEdge   `json:"edge,omitempty"`
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
	d.Edge.Normalize()
	if err := d.Edge.Validate(); err != nil {
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
	d.Edge.Normalize()
}

// EnsureEdgeDefaults applies default values to edge settings.
func (d *DomainRecord) EnsureEdgeDefaults() {
	d.Edge.Normalize()
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

// DomainEdge captures edge assignment preferences and computed state.
type DomainEdge struct {
	Labels         []string  `json:"labels,omitempty"`
	AssignmentSalt string    `json:"assignment_salt,omitempty"`
	AssignedIP     string    `json:"assigned_ip,omitempty"`
	AssignedNodeID string    `json:"assigned_node_id,omitempty"`
	AssignedAt     time.Time `json:"assigned_at,omitempty"`
}

// Normalize trims, deduplicates, and sorts labels.
func (e *DomainEdge) Normalize() {
	e.Labels = normalizeLabels(e.Labels)
	if e.AssignedIP != "" {
		e.AssignedIP = strings.TrimSpace(e.AssignedIP)
	}
	if e.AssignedNodeID != "" {
		e.AssignedNodeID = strings.TrimSpace(e.AssignedNodeID)
	}
	if e.AssignmentSalt != "" {
		e.AssignmentSalt = strings.TrimSpace(e.AssignmentSalt)
	}
}

// Validate ensures assigned edge metadata is consistent.
func (e DomainEdge) Validate() error {
	if e.AssignedIP != "" && net.ParseIP(e.AssignedIP) == nil {
		return ErrValidation("assigned_ip must be a valid IP address")
	}
	return nil
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
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	IPs          []string     `json:"ips"`
	NSIPs        []string     `json:"ns_ips"`
	EdgeIPs      []string     `json:"edge_ips,omitempty"`
	EdgeManual   bool         `json:"edge_manual"`
	NSLabel      string       `json:"ns_label,omitempty"`
	NSBase       string       `json:"ns_base_domain,omitempty"`
	APIEndpoint  string       `json:"api_endpoint,omitempty"`
	Roles        []NodeRole   `json:"roles,omitempty"`
	Labels       []string     `json:"labels,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	DeletedAt    time.Time    `json:"deleted_at,omitempty"`
	Version      ClockVersion `json:"version"`
	ManagedNS    []string     `json:"managed_ns,omitempty"`
	LastSeenAt   time.Time    `json:"last_seen_at,omitempty"`
	Status       NodeStatus   `json:"status,omitempty"`
	StatusMsg    string       `json:"status_message,omitempty"`
	HealthyEdges int          `json:"healthy_edges,omitempty"`
	TotalEdges   int          `json:"total_edges,omitempty"`
	LastHealthAt time.Time    `json:"last_health_at,omitempty"`
}

// ComputeEdgeIPs normalises node metadata and ensures edge IPs are populated.
func (n *Node) ComputeEdgeIPs() {
	n.Name = strings.TrimSpace(n.Name)
	n.APIEndpoint = strings.TrimSpace(n.APIEndpoint)
	n.NSLabel = strings.TrimSpace(n.NSLabel)
	n.NSBase = strings.TrimSpace(n.NSBase)

	n.IPs = normalizeIPs(n.IPs)
	n.NSIPs = normalizeIPs(n.NSIPs)
	n.EdgeIPs = normalizeIPs(n.EdgeIPs)
	n.Labels = normalizeLabels(n.Labels)
	n.Roles = nil
	manual := n.EdgeManual
	if len(n.EdgeIPs) == 0 {
		manual = true
	}

	// Ensure NS and Edge IPs are part of the general IP list.
	for _, ip := range append(append([]string{}, n.NSIPs...), n.EdgeIPs...) {
		if ip == "" {
			continue
		}
		if !containsString(n.IPs, ip) {
			n.IPs = append(n.IPs, ip)
		}
	}
	n.IPs = normalizeIPs(n.IPs)

	if len(n.EdgeIPs) == 0 {
		if manual {
			n.EdgeIPs = []string{}
		} else {
			nsSet := make(map[string]struct{}, len(n.NSIPs))
			for _, ip := range n.NSIPs {
				if ip != "" {
					nsSet[ip] = struct{}{}
				}
			}
			candidates := make([]string, 0, len(n.IPs))
			for _, ip := range n.IPs {
				if ip == "" {
					continue
				}
				if _, isNS := nsSet[ip]; isNS {
					continue
				}
				candidates = append(candidates, ip)
			}
			if len(candidates) == 0 {
				candidates = append(candidates, n.NSIPs...)
			}
			n.EdgeIPs = normalizeIPs(candidates)
		}
	}

	n.EdgeManual = manual

	roles := make([]NodeRole, 0, 2)
	if len(n.EdgeIPs) > 0 {
		roles = append(roles, NodeRoleEdge)
	}
	if len(n.NSIPs) > 0 {
		roles = append(roles, NodeRoleNameServer)
	}
	n.Roles = roles
}

// HasRole reports whether the node is configured for the given role.
func (n Node) HasRole(role NodeRole) bool {
	for _, r := range n.Roles {
		if r == role {
			return true
		}
	}
	return false
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

func normalizeIPs(values []string) []string {
	out := uniqueStrings(normalizeStrings(values))
	sort.Strings(out)
	return out
}

func normalizeLabels(values []string) []string {
	labels := normalizeStrings(values)
	for i := range labels {
		labels[i] = strings.ToLower(labels[i])
	}
	return uniqueStrings(labels)
}

func normalizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeRoles(values []NodeRole) []NodeRole {
	if len(values) == 0 {
		return values
	}
	out := make([]NodeRole, 0, len(values))
	seen := make(map[NodeRole]struct{}, len(values))
	for _, role := range values {
		switch role {
		case NodeRoleEdge, NodeRoleNameServer:
		default:
			continue
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, role)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func containsRole(values []NodeRole, target NodeRole) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// NodeRole defines supported infrastructure responsibilities for a node.
type NodeRole string

const (
	// NodeRoleEdge indicates the node participates in edge HTTP proxying.
	NodeRoleEdge NodeRole = "edge"
	// NodeRoleNameServer indicates the node answers authoritative DNS.
	NodeRoleNameServer NodeRole = "nameserver"
)
