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
	return nil
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
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	IPs         []string  `json:"ips"`
	NSIPs       []string  `json:"ns_ips"`
	NSLabel     string    `json:"ns_label,omitempty"`
	NSBase      string    `json:"ns_base_domain,omitempty"`
	APIEndpoint string    `json:"api_endpoint,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ManagedNS   []string  `json:"managed_ns,omitempty"`
	EdgeIPs     []string  `json:"edge_ips,omitempty"`
	LastSeenAt  time.Time `json:"last_seen_at,omitempty"`
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

// ErrValidation indicates input validation failure.
type ErrValidation string

func (e ErrValidation) Error() string {
	return string(e)
}
