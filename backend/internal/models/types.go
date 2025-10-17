package models

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
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

// DomainRole represents high-level domain behaviour (primary, alias, redirect).
type DomainRole string

const (
	DomainRolePrimary  DomainRole = "primary"
	DomainRoleAlias    DomainRole = "alias"
	DomainRoleRedirect DomainRole = "redirect"
)

// SystemOwnerID marks resources maintained by the control plane itself.
const SystemOwnerID = "system"

// Valid reports whether the role is recognised.
func (r DomainRole) Valid() bool {
	switch r {
	case DomainRolePrimary, DomainRoleAlias, DomainRoleRedirect:
		return true
	default:
		return false
	}
}

// DomainAlias declares an alias relation to a primary domain.
type DomainAlias struct {
	Target string `json:"target"`
}

// DomainRedirectRule describes a redirect instruction for a domain or path.
type DomainRedirectRule struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	StatusCode    int    `json:"status_code"`
	PreservePath  bool   `json:"preserve_path"`
	PreserveQuery bool   `json:"preserve_query"`
}

// Normalize trims and standardises rule metadata.
func (r *DomainRedirectRule) Normalize() {
	if r == nil {
		return
	}
	r.ID = strings.TrimSpace(r.ID)
	source := strings.TrimSpace(r.Source)
	if source != "" {
		if !strings.HasPrefix(source, "/") {
			source = "/" + strings.TrimLeft(source, "/")
		}
	}
	r.Source = source
	r.Target = CanonicalRedirectTarget(r.Target)
	if r.StatusCode == 0 {
		r.StatusCode = 301
	}
}

// TargetHost extracts the hostname portion of the redirect target, if any.
func (r DomainRedirectRule) TargetHost() string {
	target := strings.TrimSpace(r.Target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" {
			return ""
		}
		host := strings.ToLower(parsed.Host)
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		return host
	}
	host := strings.ToLower(target)
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	return host
}

// CanonicalRedirectTarget ensures redirect targets include an explicit protocol when required.
func CanonicalRedirectTarget(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "/") {
		return trimmed
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return trimmed
	}
	if strings.HasPrefix(trimmed, "//") {
		return "https:" + trimmed
	}
	if strings.Contains(trimmed, "://") {
		return trimmed
	}
	if idx := strings.Index(trimmed, ":"); idx > 0 && idx < strings.Index(trimmed+"#", "#") {
		// Allow schemes like mailto:, ftp:, etc.
		return trimmed
	}
	return "https://" + trimmed
}

// IsDomainRule reports whether the rule applies to the entire domain.
func (r DomainRedirectRule) IsDomainRule() bool {
	return strings.TrimSpace(r.Source) == ""
}

// IsPathRule reports whether the rule applies to a specific path.
func (r DomainRedirectRule) IsPathRule() bool {
	return strings.HasPrefix(strings.TrimSpace(r.Source), "/")
}

func normalizeDomainRole(role DomainRole) (DomainRole, bool) {
	switch strings.ToLower(strings.TrimSpace(string(role))) {
	case "", "primary":
		return DomainRolePrimary, true
	case "alias":
		return DomainRoleAlias, true
	case "redirect":
		return DomainRoleRedirect, true
	default:
		return DomainRole(""), false
	}
}

// DomainRecord represents an apex A record for a managed zone.
type DomainRecord struct {
	Domain        string               `json:"domain"`
	Owner         string               `json:"owner"`
	OwnerEmail    string               `json:"owner_email,omitempty"`
	OriginIP      string               `json:"origin_ip"`
	DNSRecords    []DomainDNSRecord    `json:"dns_records,omitempty"`
	Proxied       bool                 `json:"proxied"`
	TTL           int                  `json:"ttl"`
	CacheVersion  int64                `json:"cache_version,omitempty"`
	VanityNS      []string             `json:"vanity_ns,omitempty"`
	UpdatedAt     time.Time            `json:"updated_at"`
	DeletedAt     time.Time            `json:"deleted_at,omitempty"`
	TLS           DomainTLS            `json:"tls,omitempty"`
	Edge          DomainEdge           `json:"edge,omitempty"`
	Whois         DomainWhois          `json:"whois,omitempty"`
	WAF           DomainWAF            `json:"waf,omitempty"`
	Version       ClockVersion         `json:"version"`
	Role          DomainRole           `json:"role,omitempty"`
	Alias         *DomainAlias         `json:"alias,omitempty"`
	RedirectRules []DomainRedirectRule `json:"redirect_rules,omitempty"`
}

// DNSRecordType enumerates supported DNS record kinds.
type DNSRecordType string

const (
	DNSRecordTypeA          DNSRecordType = "A"
	DNSRecordTypeAAAA       DNSRecordType = "AAAA"
	DNSRecordTypeCAA        DNSRecordType = "CAA"
	DNSRecordTypeCERT       DNSRecordType = "CERT"
	DNSRecordTypeCNAME      DNSRecordType = "CNAME"
	DNSRecordTypeDNSKEY     DNSRecordType = "DNSKEY"
	DNSRecordTypeDS         DNSRecordType = "DS"
	DNSRecordTypeHTTPS      DNSRecordType = "HTTPS"
	DNSRecordTypeLOC        DNSRecordType = "LOC"
	DNSRecordTypeMX         DNSRecordType = "MX"
	DNSRecordTypeNAPTR      DNSRecordType = "NAPTR"
	DNSRecordTypeNS         DNSRecordType = "NS"
	DNSRecordTypeOPENPGPKEY DNSRecordType = "OPENPGPKEY"
	DNSRecordTypePTR        DNSRecordType = "PTR"
	DNSRecordTypeSMIMEA     DNSRecordType = "SMIMEA"
	DNSRecordTypeSRV        DNSRecordType = "SRV"
	DNSRecordTypeSSHFP      DNSRecordType = "SSHFP"
	DNSRecordTypeSVCB       DNSRecordType = "SVCB"
	DNSRecordTypeTLSA       DNSRecordType = "TLSA"
	DNSRecordTypeTXT        DNSRecordType = "TXT"
	DNSRecordTypeURI        DNSRecordType = "URI"
)

// Valid reports whether the DNS record type is supported.
func (t DNSRecordType) Valid() bool {
	switch t {
	case DNSRecordTypeA,
		DNSRecordTypeAAAA,
		DNSRecordTypeCAA,
		DNSRecordTypeCERT,
		DNSRecordTypeCNAME,
		DNSRecordTypeDNSKEY,
		DNSRecordTypeDS,
		DNSRecordTypeHTTPS,
		DNSRecordTypeLOC,
		DNSRecordTypeMX,
		DNSRecordTypeNAPTR,
		DNSRecordTypeNS,
		DNSRecordTypeOPENPGPKEY,
		DNSRecordTypePTR,
		DNSRecordTypeSMIMEA,
		DNSRecordTypeSRV,
		DNSRecordTypeSSHFP,
		DNSRecordTypeSVCB,
		DNSRecordTypeTLSA,
		DNSRecordTypeTXT,
		DNSRecordTypeURI:
		return true
	default:
		return false
	}
}

// SupportsProxy reports whether records of this type may be proxied.
func (t DNSRecordType) SupportsProxy() bool {
	switch t {
	case DNSRecordTypeA, DNSRecordTypeAAAA, DNSRecordTypeCNAME:
		return true
	default:
		return false
	}
}

// RequiresPriority indicates whether the record type mandates a priority value.
func (t DNSRecordType) RequiresPriority() bool {
	return t == DNSRecordTypeMX || t == DNSRecordTypeSRV
}

// DomainDNSRecord describes a DNS resource record managed under a domain.
type DomainDNSRecord struct {
	ID        string        `json:"id,omitempty"`
	Name      string        `json:"name"`
	Type      DNSRecordType `json:"type"`
	Content   string        `json:"content"`
	TTL       int           `json:"ttl,omitempty"`
	Priority  *int          `json:"priority,omitempty"`
	Proxied   bool          `json:"proxied"`
	Comment   string        `json:"comment,omitempty"`
	CreatedAt time.Time     `json:"created_at,omitempty"`
	UpdatedAt time.Time     `json:"updated_at,omitempty"`
}

// Normalize standardises record metadata.
func (r *DomainDNSRecord) Normalize() {
	if r == nil {
		return
	}
	r.ID = strings.TrimSpace(r.ID)
	name := strings.TrimSpace(r.Name)
	if name == "" || name == "@" {
		r.Name = "@"
	} else {
		name = strings.TrimSuffix(name, ".")
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "*.") {
			r.Name = "*." + strings.TrimPrefix(lower, "*.")
		} else {
			r.Name = lower
		}
		if r.Name == "" {
			r.Name = "@"
		}
	}
	r.Type = DNSRecordType(strings.ToUpper(strings.TrimSpace(string(r.Type))))
	r.Content = strings.TrimSpace(r.Content)
	if r.TTL < 0 {
		r.TTL = 0
	}
	if r.Comment != "" {
		r.Comment = strings.TrimSpace(r.Comment)
		if len(r.Comment) > 512 {
			r.Comment = r.Comment[:512]
		}
	}
	if r.Priority != nil && *r.Priority < 0 {
		zero := 0
		*r.Priority = zero
	}
}

// nameTypeKey returns a stable dedupe key for the record.
func (r DomainDNSRecord) nameTypeKey() string {
	name := r.Name
	if name == "" {
		name = "@"
	}
	return strings.ToLower(name) + "|" + strings.ToUpper(string(r.Type))
}

// Validate ensures the record is internally consistent.
func (r DomainDNSRecord) Validate(domain string, domainProxied bool, originIP string) error {
	if !r.Type.Valid() {
		return ErrValidation("unsupported dns record type")
	}
	if !validRecordName(r.Name) {
		return ErrValidation("invalid dns record name")
	}
	if r.Proxied {
		if !domainProxied {
			return ErrValidation("proxied dns records require the domain proxy to be enabled")
		}
		if !r.Type.SupportsProxy() {
			return ErrValidation("record type does not support proxying")
		}
	}
	switch r.Type {
	case DNSRecordTypeA:
		value := strings.TrimSpace(r.Content)
		if value == "@" {
			value = ""
		}
		if value == "" {
			if !r.Proxied && originIP == "" {
				return ErrValidation("dns record content required for A record")
			}
		} else {
			ip := net.ParseIP(value)
			if ip == nil || ip.To4() == nil {
				return ErrValidation("dns record content must be a valid IPv4 address")
			}
		}
	case DNSRecordTypeAAAA:
		value := strings.TrimSpace(r.Content)
		if value == "@" {
			value = ""
		}
		if value == "" {
			if !r.Proxied {
				return ErrValidation("dns record content required for AAAA record")
			}
		} else {
			ip := net.ParseIP(value)
			if ip == nil || ip.To16() == nil || ip.To4() != nil {
				return ErrValidation("dns record content must be a valid IPv6 address")
			}
		}
	case DNSRecordTypeCNAME, DNSRecordTypeNS, DNSRecordTypePTR:
		value := strings.TrimSpace(r.Content)
		if value == "" {
			return ErrValidation("dns record content required")
		}
		if value != "@" && !validHostname(value) {
			return ErrValidation("dns record content must be a valid hostname")
		}
	case DNSRecordTypeMX:
		value := strings.TrimSpace(r.Content)
		if value == "" {
			return ErrValidation("dns record content required")
		}
		if value != "@" && !validHostname(value) {
			return ErrValidation("mx record content must be a valid hostname")
		}
		if r.Priority == nil {
			return ErrValidation("mx record priority required")
		}
	case DNSRecordTypeTXT,
		DNSRecordTypeCAA,
		DNSRecordTypeCERT,
		DNSRecordTypeDNSKEY,
		DNSRecordTypeDS,
		DNSRecordTypeHTTPS,
		DNSRecordTypeLOC,
		DNSRecordTypeNAPTR,
		DNSRecordTypeOPENPGPKEY,
		DNSRecordTypeSMIMEA,
		DNSRecordTypeSRV,
		DNSRecordTypeSSHFP,
		DNSRecordTypeSVCB,
		DNSRecordTypeTLSA,
		DNSRecordTypeURI:
		if strings.TrimSpace(r.Content) == "" {
			return ErrValidation("dns record content required")
		}
	default:
		if strings.TrimSpace(r.Content) == "" {
			return ErrValidation("dns record content required")
		}
	}
	if !r.Type.RequiresPriority() && r.Priority != nil && *r.Priority < 0 {
		*r.Priority = 0
	}
	if r.Type.RequiresPriority() && r.Priority != nil && *r.Priority < 0 {
		return ErrValidation("record priority must be zero or positive")
	}
	return nil
}

func validRecordName(name string) bool {
	if name == "" || name == "@" {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	lower = strings.TrimSuffix(lower, ".")
	if lower == "" {
		return false
	}
	if lower == "*" {
		return true
	}
	if strings.HasPrefix(lower, "*.") {
		lower = lower[2:]
		if lower == "" {
			return false
		}
	}
	parts := strings.Split(lower, ".")
	for _, part := range parts {
		if !validDNSLabel(part, true) {
			return false
		}
	}
	return true
}

func validHostname(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	lower = strings.TrimSuffix(lower, ".")
	if lower == "" {
		return false
	}
	if lower == "*" {
		return false
	}
	if strings.HasPrefix(lower, "*.") {
		lower = lower[2:]
		if lower == "" {
			return false
		}
	}
	parts := strings.Split(lower, ".")
	for _, part := range parts {
		if !validDNSLabel(part, true) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string, allowUnderscore bool) bool {
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		ch := label[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			continue
		case ch >= '0' && ch <= '9':
			continue
		case ch == '-':
			if i == 0 || i == len(label)-1 {
				return false
			}
		case allowUnderscore && ch == '_':
			continue
		default:
			return false
		}
	}
	return true
}

// Validate performs minimal sanity checks.
func (d *DomainRecord) Validate() error {
	if d.Domain == "" {
		return ErrValidation("domain must be provided")
	}
	if !d.DeletedAt.IsZero() {
		d.EnsureCacheVersion()
		return nil
	}
	origin := strings.TrimSpace(d.OriginIP)
	if origin != "" && net.ParseIP(origin) == nil {
		return ErrValidation("origin_ip must be a valid IP address")
	}
	d.OriginIP = origin
	if d.TTL <= 0 {
		d.TTL = 60
	}
	d.NormalizeLinks()
	if strings.TrimSpace(string(d.Role)) == "" {
		d.Role = DomainRolePrimary
	}
	if !d.Role.Valid() {
		return ErrValidation("invalid domain role")
	}
	switch d.Role {
	case DomainRoleAlias:
		if d.Alias == nil || d.Alias.Target == "" {
			return ErrValidation("alias target must be provided")
		}
		if d.Alias.Target == d.Domain {
			return ErrValidation("alias target must differ from domain")
		}
	case DomainRoleRedirect:
		if len(d.RedirectRules) == 0 {
			return ErrValidation("redirect domains require a domain redirect rule")
		}
	default:
		d.Alias = nil
	}
	if d.Role == DomainRoleAlias {
		d.RedirectRules = nil
	} else if len(d.RedirectRules) > 0 {
		domainRuleCount := 0
		for i := range d.RedirectRules {
			rule := &d.RedirectRules[i]
			rule.Normalize()
			if rule.ID == "" {
				return ErrValidation("redirect rule id required")
			}
			if rule.Target == "" {
				return ErrValidation("redirect rule target must be provided")
			}
			if !validRedirectStatus(rule.StatusCode) {
				return ErrValidation("invalid redirect status code")
			}
			if rule.IsDomainRule() {
				domainRuleCount++
			} else if !rule.IsPathRule() {
				return ErrValidation("redirect rule source must be empty or start with '/'")
			}
		}
		if domainRuleCount > 1 {
			return ErrValidation("only one domain redirect rule supported")
		}
		if d.Role == DomainRoleRedirect {
			if domainRuleCount != 1 {
				return ErrValidation("redirect domains require a domain redirect rule")
			}
			if len(d.RedirectRules) != domainRuleCount {
				return ErrValidation("redirect domains cannot define path redirect rules")
			}
		}
	} else {
		d.RedirectRules = nil
	}
	d.EnsureCacheVersion()
	d.WAF.Normalize()
	if err := d.WAF.Validate(); err != nil {
		return err
	}
	if err := d.TLS.Validate(); err != nil {
		return err
	}
	d.Edge.Normalize()
	if err := d.Edge.Validate(); err != nil {
		return err
	}
	d.Whois.Normalize()
	if len(d.DNSRecords) > 0 {
		records := make([]DomainDNSRecord, 0, len(d.DNSRecords))
		seen := make(map[string]struct{}, len(d.DNSRecords))
		for i := range d.DNSRecords {
			rec := d.DNSRecords[i]
			rec.Normalize()
			if strings.TrimSpace(rec.ID) == "" {
				rec.ID = uuid.NewString()
			}
			if rec.TTL <= 0 {
				rec.TTL = d.TTL
			}
			if err := rec.Validate(d.Domain, d.Proxied, d.OriginIP); err != nil {
				return err
			}
			key := rec.nameTypeKey()
			if _, exists := seen[key]; exists {
				return ErrValidation("duplicate dns record name and type")
			}
			seen[key] = struct{}{}
			records = append(records, rec)
		}
		sort.Slice(records, func(i, j int) bool {
			if records[i].Name == records[j].Name {
				return records[i].Type < records[j].Type
			}
			return records[i].Name < records[j].Name
		})
		d.DNSRecords = records
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
	d.EnsureCacheVersion()
	d.Whois.Normalize()
	d.WAF.Normalize()
}

// EnsureEdgeDefaults applies default values to edge settings.
func (d *DomainRecord) EnsureEdgeDefaults() {
	d.Edge.Normalize()
	d.EnsureCacheVersion()
	d.Whois.Normalize()
	d.WAF.Normalize()
}

// EnsureCacheVersion initialises cache version if unset.
func (d *DomainRecord) EnsureCacheVersion() {
	if d.CacheVersion <= 0 {
		d.CacheVersion = 1
	}
	sort.Strings(d.VanityNS)
	d.Whois.Normalize()
	d.WAF.Normalize()
	d.NormalizeLinks()
}

// IsSystemManaged reports whether the record is owned by the control plane.
func (d DomainRecord) IsSystemManaged() bool {
	return strings.EqualFold(strings.TrimSpace(d.Owner), SystemOwnerID)
}

// MatchesOwner reports whether the record belongs to the provided owner id or email.
func (d DomainRecord) MatchesOwner(ownerID, ownerEmail string) bool {
	if ownerID != "" && d.Owner == ownerID {
		return true
	}
	if ownerEmail != "" {
		lower := strings.ToLower(ownerEmail)
		if d.OwnerEmail != "" && strings.EqualFold(d.OwnerEmail, ownerEmail) {
			return true
		}
		if strings.Contains(d.Owner, "@") && strings.EqualFold(d.Owner, lower) {
			return true
		}
	}
	return false
}

// IsDeleted reports whether the domain has been marked as deleted.
func (d DomainRecord) IsDeleted() bool {
	return !d.DeletedAt.IsZero()
}

// MarkDeleted normalises the record for deletion tombstones.
func (d *DomainRecord) MarkDeleted(ts time.Time) {
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	d.DeletedAt = ts
	d.Proxied = false
	d.CacheVersion = 0
	if d.TTL <= 0 {
		d.TTL = 60
	}
	d.Edge.AssignedIP = ""
	d.Edge.AssignedNodeID = ""
	d.Edge.AssignedAt = time.Time{}
	d.Edge.Normalize()
	d.TLS.Mode = EncryptionOff
	d.TLS.UseRecommended = false
	d.TLS.Status = CertificateStatusNone
	d.TLS.RecommendedMode = ""
	d.TLS.RecommendedAt = time.Time{}
	d.TLS.LastError = ""
	d.TLS.LastAttemptAt = time.Time{}
	d.TLS.RetryAfter = time.Time{}
	d.TLS.LockID = ""
	d.TLS.LockNodeID = ""
	d.TLS.LockExpiresAt = time.Time{}
	d.TLS.Challenges = nil
	d.TLS.UpdatedAt = ts
	d.TLS.Certificate = nil
	d.TLS.OriginPullSecret = nil
	d.UpdatedAt = ts
	d.Whois = DomainWhois{}
	d.WAF = DomainWAF{}
	d.Role = DomainRolePrimary
	d.Alias = nil
	d.RedirectRules = nil
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
	d.NormalizeLinks()
	return d
}

// NormalizeLinks standardises role, alias, and redirect rule metadata.
func (d *DomainRecord) NormalizeLinks() {
	if d == nil {
		return
	}
	if normalized, ok := normalizeDomainRole(d.Role); ok {
		d.Role = normalized
	} else {
		d.Role = DomainRole(strings.ToLower(strings.TrimSpace(string(d.Role))))
	}
	if d.Role != DomainRoleAlias {
		d.Alias = nil
	} else if d.Alias != nil {
		d.Alias.Target = strings.ToLower(strings.TrimSpace(d.Alias.Target))
	}
	if d.Role == DomainRoleAlias {
		d.RedirectRules = nil
		return
	}
	if len(d.RedirectRules) == 0 {
		d.RedirectRules = nil
		return
	}
	normalized := make([]DomainRedirectRule, 0, len(d.RedirectRules))
	for _, rule := range d.RedirectRules {
		rule.Normalize()
		normalized = append(normalized, rule)
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].Source == normalized[j].Source {
			return normalized[i].ID < normalized[j].ID
		}
		return normalized[i].Source < normalized[j].Source
	})
	d.RedirectRules = normalized
}

func validRedirectStatus(code int) bool {
	switch code {
	case 301, 302, 307, 308:
		return true
	default:
		return false
	}
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

// DomainWhois captures WHOIS-derived renewal metadata.
type DomainWhois struct {
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	CheckedAt  time.Time `json:"checked_at,omitempty"`
	Source     string    `json:"source,omitempty"`
	RawExpires string    `json:"raw_expires,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

// Normalize standardises string fields and collapses empty values.
func (w *DomainWhois) Normalize() {
	if w == nil {
		return
	}
	w.Source = strings.ToLower(strings.TrimSpace(w.Source))
	w.RawExpires = strings.TrimSpace(w.RawExpires)
	w.LastError = strings.TrimSpace(w.LastError)
	if w.Source == "" && w.RawExpires == "" && w.LastError == "" && w.ExpiresAt.IsZero() && w.CheckedAt.IsZero() {
		*w = DomainWhois{}
	}
}

// IsZero reports whether the WHOIS state carries any data.
func (w DomainWhois) IsZero() bool {
	return w == (DomainWhois{})
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

// ACMEChallenge represents a pending ACME challenge that must be published.
type ACMEChallenge struct {
	Token          string    `json:"token"`
	KeyAuth        string    `json:"key_authorization"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	ChallengeType  string    `json:"challenge_type,omitempty"`
	Authorization  string    `json:"authorization_url,omitempty"`
	VerificationAt time.Time `json:"verification_at,omitempty"`
	DNSName        string    `json:"dns_name,omitempty"`
	DNSValue       string    `json:"dns_value,omitempty"`
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
	NSLabel      string       `json:"ns_label,omitempty"`
	NSBase       string       `json:"ns_base_domain,omitempty"`
	APIEndpoint  string       `json:"api_endpoint,omitempty"`
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

	// Computed field for JSON serialization
	Roles []NodeRole `json:"roles,omitempty"`
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

	if n.IsDeleted() {
		n.EdgeIPs = nil
		n.NSIPs = nil
		n.Roles = nil
		return
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

	// Compute roles based on IP configuration
	n.Roles = n.GetRoles()
}

// GetRoles returns computed roles based on IP configuration
func (n Node) GetRoles() []NodeRole {
	if n.IsDeleted() {
		return nil
	}

	roles := make([]NodeRole, 0, 2)
	if len(n.EdgeIPs) > 0 {
		roles = append(roles, NodeRoleEdge)
	}
	if len(n.NSIPs) > 0 {
		roles = append(roles, NodeRoleNameServer)
	}
	return roles
}

// HasRole reports whether the node is configured for the given role.
func (n Node) HasRole(role NodeRole) bool {
	if n.IsDeleted() {
		return false
	}

	switch role {
	case NodeRoleEdge:
		return len(n.EdgeIPs) > 0
	case NodeRoleNameServer:
		return len(n.NSIPs) > 0
	default:
		return false
	}
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

// IsDeleted reports whether the node has been marked as removed.
func (n Node) IsDeleted() bool {
	return !n.DeletedAt.IsZero()
}

// MarkDeleted applies tombstone semantics to the node.
func (n *Node) MarkDeleted(ts time.Time) {
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	n.DeletedAt = ts
	n.UpdatedAt = ts
	n.EdgeIPs = nil
	n.NSIPs = nil
	n.Roles = nil
	n.Labels = nil
}

// NodeRole defines supported infrastructure responsibilities for a node.
type NodeRole string

const (
	// NodeRoleEdge indicates the node participates in edge HTTP proxying.
	NodeRoleEdge NodeRole = "edge"
	// NodeRoleNameServer indicates the node answers authoritative DNS.
	NodeRoleNameServer NodeRole = "nameserver"
)

// LoginAttempt captures brute-force mitigation metadata.
type LoginAttempt struct {
	Key         string    `json:"key"`
	Scope       string    `json:"scope"`
	Failures    int       `json:"failures"`
	LastFailure time.Time `json:"last_failure,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}
