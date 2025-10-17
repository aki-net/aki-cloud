package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"aki-cloud/backend/internal/auth"
	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/extensions"
	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/orchestrator"
	"aki-cloud/backend/internal/searchbot"
	"aki-cloud/backend/internal/store"
	syncsvc "aki-cloud/backend/internal/sync"
	"aki-cloud/backend/internal/waf"
	"aki-cloud/backend/internal/whois"

	"github.com/araddon/dateparse"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
	"sync"
)

// Server holds routing dependencies.
type Server struct {
	Config          *config.Config
	Store           *store.Store
	Auth            *auth.Service
	Orchestrator    *orchestrator.Service
	Sync            *syncsvc.Service
	Infra           *infra.Controller
	Extensions      *extensions.Service
	Whois           *whois.Service
	SearchBot       *searchbot.Service
	edgeReconcileMu sync.Mutex
}

const (
	loginScopeEmail = "email"
	loginScopeIP    = "ip"
)

type loginAttemptDescriptor struct {
	Scope string
	Key   string
}

type domainOverview struct {
	Domain        string                      `json:"domain"`
	OwnerID       string                      `json:"owner_id"`
	OwnerEmail    string                      `json:"owner_email,omitempty"`
	OwnerExists   bool                        `json:"owner_exists"`
	OriginIP      string                      `json:"origin_ip"`
	Proxied       bool                        `json:"proxied"`
	TTL           int                         `json:"ttl"`
	CacheVersion  int64                       `json:"cache_version,omitempty"`
	UpdatedAt     time.Time                   `json:"updated_at"`
	Role          models.DomainRole           `json:"role"`
	Alias         *models.DomainAlias         `json:"alias,omitempty"`
	RedirectRules []models.DomainRedirectRule `json:"redirect_rules,omitempty"`
	TLSMode       models.EncryptionMode       `json:"tls_mode,omitempty"`
	TLSStatus     models.CertificateStatus    `json:"tls_status,omitempty"`
	TLSUseRec     bool                        `json:"tls_use_recommended"`
	TLSRecMode    models.EncryptionMode       `json:"tls_recommended_mode,omitempty"`
	TLSExpires    *time.Time                  `json:"tls_expires_at,omitempty"`
	TLSError      string                      `json:"tls_last_error,omitempty"`
	TLSRetryAt    *time.Time                  `json:"tls_retry_after,omitempty"`
	EdgeIP        string                      `json:"edge_ip,omitempty"`
	EdgeNodeID    string                      `json:"edge_node_id,omitempty"`
	EdgeLabels    []string                    `json:"edge_labels,omitempty"`
	EdgeUpdated   *time.Time                  `json:"edge_assigned_at,omitempty"`
	DNSRecords    []models.DomainDNSRecord    `json:"dns_records,omitempty"`
	Nameservers   *domainNameServerSet        `json:"nameservers,omitempty"`
	Whois         *models.DomainWhois         `json:"whois,omitempty"`
	WAF           models.DomainWAF            `json:"waf,omitempty"`
}

type nsCheckRequest struct {
	Targets []string `json:"targets"`
}

type nsCheckResult struct {
	NodeID    string    `json:"node_id"`
	Name      string    `json:"name"`
	FQDN      string    `json:"fqdn"`
	IPv4      string    `json:"ipv4"`
	Healthy   bool      `json:"healthy"`
	LatencyMS int64     `json:"latency_ms"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

type domainTLSPayload struct {
	Mode           string `json:"mode,omitempty"`
	UseRecommended *bool  `json:"use_recommended,omitempty"`
}

type domainEdgePayload struct {
	Labels []string `json:"labels,omitempty"`
}

type domainWAFPayload struct {
	Enabled *bool     `json:"enabled,omitempty"`
	Presets *[]string `json:"presets,omitempty"`
}

type domainAliasPayload struct {
	Target string `json:"target"`
}

type domainRedirectRulePayload struct {
	ID            string `json:"id,omitempty"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	StatusCode    *int   `json:"status_code,omitempty"`
	PreservePath  *bool  `json:"preserve_path,omitempty"`
	PreserveQuery *bool  `json:"preserve_query,omitempty"`
}

type domainDNSRecordPayload struct {
	ID       string  `json:"id,omitempty"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Content  string  `json:"content"`
	TTL      *int    `json:"ttl,omitempty"`
	Priority *int    `json:"priority,omitempty"`
	Proxied  *bool   `json:"proxied,omitempty"`
	Comment  *string `json:"comment,omitempty"`
}

type domainWhoisManualPayload struct {
	ExpiresAt string `json:"expires_at"`
	RawInput  string `json:"raw_input,omitempty"`
}

type createDomainPayload struct {
	Domain        string                      `json:"domain"`
	Owner         string                      `json:"owner,omitempty"`
	OriginIP      *string                     `json:"origin_ip"`
	Proxied       *bool                       `json:"proxied,omitempty"`
	TTL           *int                        `json:"ttl,omitempty"`
	TLS           *domainTLSPayload           `json:"tls,omitempty"`
	Edge          *domainEdgePayload          `json:"edge,omitempty"`
	WAF           *domainWAFPayload           `json:"waf,omitempty"`
	Role          string                      `json:"role,omitempty"`
	Alias         *domainAliasPayload         `json:"alias,omitempty"`
	RedirectRules []domainRedirectRulePayload `json:"redirect_rules,omitempty"`
	DNSRecords    []domainDNSRecordPayload    `json:"dns_records,omitempty"`
}

const (
	maxBulkDomains          = 1000
	installScriptURL        = "https://raw.githubusercontent.com/aki-net/aki-cloud/main/install.sh"
	automationQueuedMessage = "automation queued"
)

var (
	errForbiddenDomainOwner = errors.New("cannot create domain for another user")
)

type bulkDomainPayload struct {
	Domains       []string                    `json:"domains"`
	Owner         string                      `json:"owner,omitempty"`
	OriginIP      *string                     `json:"origin_ip"`
	Proxied       *bool                       `json:"proxied,omitempty"`
	TTL           *int                        `json:"ttl,omitempty"`
	TLS           *domainTLSPayload           `json:"tls,omitempty"`
	Edge          *domainEdgePayload          `json:"edge,omitempty"`
	WAF           *domainWAFPayload           `json:"waf,omitempty"`
	Role          string                      `json:"role,omitempty"`
	Alias         *domainAliasPayload         `json:"alias,omitempty"`
	RedirectRules []domainRedirectRulePayload `json:"redirect_rules,omitempty"`
	DNSRecords    []domainDNSRecordPayload    `json:"dns_records,omitempty"`
}

type nameServerEntryDTO struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4,omitempty"`
}

type domainNameServerSet struct {
	Default []nameServerEntryDTO `json:"default,omitempty"`
	Anycast []nameServerEntryDTO `json:"anycast,omitempty"`
	Vanity  []nameServerEntryDTO `json:"vanity,omitempty"`
}

type domainResponse struct {
	models.DomainRecord
	Nameservers *domainNameServerSet `json:"nameservers,omitempty"`
}

func prepareDefaultNameServers(nsList []infra.NameServer) []nameServerEntryDTO {
	if len(nsList) == 0 {
		return nil
	}
	entries := make([]nameServerEntryDTO, 0, len(nsList))
	for _, ns := range nsList {
		name := strings.TrimSpace(ns.FQDN)
		if name == "" {
			continue
		}
		entries = append(entries, nameServerEntryDTO{
			Name: name,
			IPv4: strings.TrimSpace(ns.IPv4),
		})
	}
	return entries
}

func (s *Server) composeNameserverSet(domain string, nsList []infra.NameServer, defaults []nameServerEntryDTO) (domainNameServerSet, []string) {
	nsSet := domainNameServerSet{}
	if len(defaults) > 0 {
		nsSet.Default = append(nsSet.Default, defaults...)
	}
	var anycastNames []string
	if s.Extensions == nil {
		return nsSet, anycastNames
	}
	set, err := s.Extensions.VanityNameServersForDomain(domain, nsList)
	if err != nil {
		log.Printf("domains: vanity names for %s failed: %v", domain, err)
		return nsSet, anycastNames
	}
	if len(set.Anycast) > 0 {
		entries := make([]nameServerEntryDTO, 0, len(set.Anycast))
		names := make([]string, 0, len(set.Anycast))
		for _, ns := range set.Anycast {
			name := strings.TrimSpace(ns.Name)
			ip := strings.TrimSpace(ns.IPv4)
			if name == "" {
				continue
			}
			entries = append(entries, nameServerEntryDTO{Name: name, IPv4: ip})
			names = append(names, name)
		}
		if len(entries) > 0 {
			nsSet.Anycast = entries
			anycastNames = names
		}
	}
	if len(set.Domain) > 0 {
		entries := make([]nameServerEntryDTO, 0, len(set.Domain))
		for _, ns := range set.Domain {
			name := strings.TrimSpace(ns.Name)
			ip := strings.TrimSpace(ns.IPv4)
			if name == "" {
				continue
			}
			entries = append(entries, nameServerEntryDTO{Name: name, IPv4: ip})
		}
		if len(entries) > 0 {
			nsSet.Vanity = entries
		}
	}
	return nsSet, anycastNames
}

func (s *Server) handleListWAFDefinitions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, waf.Definitions())
}

type bulkUpdateDomainPayload struct {
	Domains       []string                     `json:"domains"`
	OriginIP      *string                      `json:"origin_ip,omitempty"`
	Proxied       *bool                        `json:"proxied,omitempty"`
	TTL           *int                         `json:"ttl,omitempty"`
	TLS           *domainTLSPayload            `json:"tls,omitempty"`
	Owner         *string                      `json:"owner,omitempty"`
	Edge          *domainEdgePayload           `json:"edge,omitempty"`
	WAF           *domainWAFPayload            `json:"waf,omitempty"`
	Role          *string                      `json:"role,omitempty"`
	Alias         *domainAliasPayload          `json:"alias,omitempty"`
	RedirectRules *[]domainRedirectRulePayload `json:"redirect_rules,omitempty"`
}

type bulkDomainResult struct {
	Domain string               `json:"domain"`
	Status string               `json:"status"`
	Error  string               `json:"error,omitempty"`
	Record *models.DomainRecord `json:"record,omitempty"`
}

type bulkDomainResponse struct {
	Results []bulkDomainResult `json:"results"`
	Success int                `json:"success"`
	Failed  int                `json:"failed"`
	Skipped int                `json:"skipped"`
}

type extensionActionDTO struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

type extensionDTO struct {
	Key         string                 `json:"key"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Scope       models.ExtensionScope  `json:"scope"`
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Actions     []extensionActionDTO   `json:"actions,omitempty"`
	UpdatedAt   string                 `json:"updated_at,omitempty"`
	UpdatedBy   string                 `json:"updated_by,omitempty"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

type updateExtensionPayload struct {
	Enabled *bool                  `json:"enabled,omitempty"`
	Config  map[string]interface{} `json:"config,omitempty"`
}

func disableTLSForDNS(rec *models.DomainRecord) {
	rec.TLS.UseRecommended = false
	rec.TLS.Mode = models.EncryptionOff
	rec.TLS.Status = models.CertificateStatusNone
	rec.TLS.RecommendedMode = ""
	rec.TLS.RecommendedAt = time.Time{}
	rec.TLS.LastError = ""
	rec.TLS.RetryAfter = time.Time{}
	rec.TLS.LockID = ""
	rec.TLS.LockNodeID = ""
	rec.TLS.LockExpiresAt = time.Time{}
	rec.TLS.Challenges = nil
	rec.TLS.UpdatedAt = time.Now().UTC()
}

func queueTLSAutomation(rec *models.DomainRecord, ts time.Time) {
	if rec == nil {
		return
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if certificateUsable(rec, ts) {
		rec.TLS.Status = models.CertificateStatusActive
		if rec.TLS.RetryAfter.Before(ts) {
			rec.TLS.RetryAfter = time.Time{}
		}
		if rec.TLS.LastError == automationQueuedMessage {
			rec.TLS.LastError = ""
		}
		rec.TLS.LastAttemptAt = time.Time{}
		rec.TLS.UpdatedAt = ts
		return
	}
	if rec.TLS.RetryAfter.After(ts) {
		// Respect existing retry/backoff window: leave status/error untouched.
		return
	}
	rec.TLS.Status = models.CertificateStatusPending
	rec.TLS.LastAttemptAt = time.Time{}
	rec.TLS.UpdatedAt = ts
	rec.TLS.RetryAfter = time.Time{}
	rec.TLS.LastError = automationQueuedMessage
}

func certificateUsable(rec *models.DomainRecord, now time.Time) bool {
	if rec.TLS.Certificate == nil {
		return false
	}
	cert := rec.TLS.Certificate
	if cert.CertChainPEM == "" || cert.NotAfter.IsZero() {
		return false
	}
	return cert.NotAfter.After(now)
}

func ensureTLSProxyCompatibility(rec *models.DomainRecord) error {
	rec.EnsureTLSDefaults()
	if rec.Proxied {
		if !rec.TLS.UseRecommended && rec.TLS.Mode == "" {
			rec.TLS.Mode = models.EncryptionFlexible
		}
		return nil
	}
	if rec.TLS.UseRecommended {
		return models.ErrValidation("TLS automation requires proxying to be enabled")
	}
	if rec.TLS.Mode != "" && rec.TLS.Mode != models.EncryptionOff {
		return models.ErrValidation("TLS must be set to off when proxying is disabled")
	}
	return nil
}

type updateDomainPayload struct {
	OriginIP      *string                      `json:"origin_ip"`
	Proxied       *bool                        `json:"proxied,omitempty"`
	TTL           *int                         `json:"ttl,omitempty"`
	TLS           *domainTLSPayload            `json:"tls,omitempty"`
	Owner         *string                      `json:"owner,omitempty"`
	Edge          *domainEdgePayload           `json:"edge,omitempty"`
	WAF           *domainWAFPayload            `json:"waf,omitempty"`
	Role          *string                      `json:"role,omitempty"`
	Alias         *domainAliasPayload          `json:"alias,omitempty"`
	RedirectRules *[]domainRedirectRulePayload `json:"redirect_rules,omitempty"`
}

// Routes constructs the HTTP router.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	allowedSuffix := fmt.Sprintf(".%s.%s", strings.ToLower(strings.TrimSpace(s.Config.NSLabel)), strings.ToLower(strings.TrimSpace(s.Config.NSBaseDomain)))
	if allowedSuffix == "." {
		allowedSuffix = ".dns.aki.cloud"
	}
	r.Use(cors.Handler(cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			if origin == "" {
				return false
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := strings.ToLower(u.Hostname())
			if host == "" {
				return false
			}
			if host == "localhost" || host == "127.0.0.1" {
				return true
			}
			return strings.HasSuffix(host, allowedSuffix)
		},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	if s.Config.MaxRequestBodyBytes > 0 {
		r.Use(limitBodySize(s.Config.MaxRequestBodyBytes))
	}

	apiRPS, apiBurst := computeRateLimits(s.Config.APIRatePerMinute, s.Config.APIRateBurst)
	if apiRPS > 0 && apiBurst > 0 {
		rps := apiRPS
		burst := apiBurst
		r.Use(func(next http.Handler) http.Handler {
			limitNext := httprate.LimitByIP(rps, burst)(next)
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if skipRateLimitedPaths(req) {
					next.ServeHTTP(w, req)
					return
				}
				limitNext.ServeHTTP(w, req)
			})
		})
	}

	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/.well-known/acme-challenge/{token}", s.handleACMEChallenge)

	loginHandler := http.HandlerFunc(s.handleLogin)
	loginRPS, loginBurst := computeRateLimits(s.Config.LoginRatePerMinute, s.Config.LoginRateBurst)
	if loginRPS > 0 && loginBurst > 0 {
		r.With(httprate.LimitByIP(loginRPS, loginBurst)).Post("/auth/login", loginHandler)
	} else {
		r.Post("/auth/login", loginHandler)
	}

	// Sync endpoints use shared secret auth instead of JWT
	r.Route("/api/v1/sync", func(r chi.Router) {
		r.Get("/digest", s.handleSyncDigest)
		r.Post("/pull", s.handleSyncPull)
		r.Post("/push", s.handleSyncPush)
	})

	r.Route("/api/v1/internal/searchbot", func(r chi.Router) {
		r.Get("/usage", s.handleInternalSearchBotUsage)
		r.Get("/domains/{domain}/stats", s.handleInternalSearchBotStats)
		r.Get("/domains/{domain}/logs/{bot}", s.handleInternalSearchBotExport)
		r.Post("/logs/clear", s.handleInternalSearchBotClear)
	})

	tokenAuth := s.Auth.TokenAuth()

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)

		r.Route("/api/v1", func(r chi.Router) {
			r.Get("/domains", s.authorizeUser(s.handleListDomains))
			r.Post("/domains", s.authorizeUser(s.handleCreateDomain))
			r.Post("/domains/bulk", s.authorizeUser(s.handleBulkCreateDomains))
			r.Patch("/domains/bulk", s.authorizeUser(s.handleBulkUpdateDomains))
			r.Put("/domains/{domain}", s.authorizeUser(s.handleUpdateDomain))
			r.Post("/domains/{domain}/cache/purge", s.authorizeUser(s.handlePurgeDomainCache))
			r.Post("/domains/{domain}/whois/refresh", s.authorizeUser(s.handleRefreshDomainWhois))
			r.Put("/domains/{domain}/whois", s.authorizeUser(s.handleOverrideDomainWhois))
			r.Route("/domains/{domain}/dns-records", func(r chi.Router) {
				r.Get("/", s.authorizeUser(s.handleListDomainDNSRecords))
				r.Post("/", s.authorizeUser(s.handleCreateDomainDNSRecord))
				r.Put("/{id}", s.authorizeUser(s.handleUpdateDomainDNSRecord))
				r.Delete("/{id}", s.authorizeUser(s.handleDeleteDomainDNSRecord))
			})
			r.Get("/domains/{domain}/searchbots/stats", s.authorizeUser(s.handleDomainSearchBotStats))
			r.Get("/domains/{domain}/searchbots/logs/{bot}", s.authorizeUser(s.handleDomainSearchBotExport))
			r.Post("/domains/{domain}/edge/reassign", func(w http.ResponseWriter, req *http.Request) {
				s.requireAdmin(http.HandlerFunc(s.handleReassignDomainEdge)).ServeHTTP(w, req)
			})
			r.Post("/domains/edge/reassign-all", func(w http.ResponseWriter, req *http.Request) {
				s.requireAdmin(http.HandlerFunc(s.handleReassignAllDomainEdges)).ServeHTTP(w, req)
			})
			r.Delete("/domains/{domain}", s.authorizeUser(s.handleDeleteDomain))

			r.Get("/infra/nameservers", s.requireRole(models.RoleUser, s.handleInfraNS))
			r.Get("/infra/edges", func(w http.ResponseWriter, req *http.Request) {
				s.requireAdmin(http.HandlerFunc(s.handleInfraEdges)).ServeHTTP(w, req)
			})
			r.Get("/waf/definitions", s.authorizeUser(s.handleListWAFDefinitions))

			// admin subroutes
			r.Route("/admin", func(r chi.Router) {
				r.Use(s.requireAdmin)
				r.Get("/users", s.handleListUsers)
				r.Post("/users", s.handleCreateUser)
				r.Put("/users/{id}", s.handleUpdateUser)
				r.Delete("/users/{id}", s.handleDeleteUser)

				r.Get("/nodes", s.handleListNodes)
				r.Post("/nodes", s.handleCreateNode)
				r.Put("/nodes/{id}", s.handleUpdateNode)
				r.Delete("/nodes/{id}", s.handleDeleteNode)
				r.Get("/nodes/join-command", s.handleNodeJoinCommand)

				r.Get("/domains/overview", s.handleDomainsOverview)
				r.Post("/infra/nameservers/check", s.handleNameServerCheck)
				r.Get("/infra/nameservers/status", s.handleNameServerStatus)
				r.Get("/extensions", s.handleListExtensions)
				r.Put("/extensions/{key}", s.handleUpdateExtension)
				r.Post("/extensions/{key}/actions/{action}", s.handleExtensionAction)
				r.Get("/searchbots/usage", s.handleAdminSearchBotUsage)

				r.Post("/ops/rebuild", s.handleRebuild)
			})
		})
	})

	return r
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	type componentStatus struct {
		Name  string
		Check func() error
	}
	components := []componentStatus{
		{
			Name: "store",
			Check: func() error {
				_, err := s.Store.GetUsers()
				return err
			},
		},
		{
			Name: "sync",
			Check: func() error {
				_, err := s.Sync.ComputeDigest()
				return err
			},
		},
		{
			Name: "coredns_config",
			Check: func() error {
				_, err := os.Stat(filepath.Join(s.Config.DataDir, "dns", "Corefile"))
				return err
			},
		},
		{
			Name: "openresty_config",
			Check: func() error {
				_, err := os.Stat(filepath.Join(s.Config.DataDir, "openresty", "nginx.conf"))
				return err
			},
		},
	}
	status := make(map[string]string, len(components))
	healthy := true
	for _, comp := range components {
		if err := comp.Check(); err != nil {
			status[comp.Name] = fmt.Sprintf("error: %v", err)
			healthy = false
		} else {
			status[comp.Name] = "ok"
		}
	}
	payload := map[string]interface{}{
		"status":     "ready",
		"components": status,
		"node_id":    s.Config.NodeID,
	}
	code := http.StatusOK
	if !healthy {
		payload["status"] = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, payload)
}

func (s *Server) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if host == "" {
		http.NotFound(w, r)
		return
	}
	token := chi.URLParam(r, "token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	record, err := s.Store.GetDomain(host)
	if err != nil || record == nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	for _, challenge := range record.TLS.Challenges {
		if challenge.ChallengeType != "" && challenge.ChallengeType != "http-01" {
			continue
		}
		if challenge.Token != token {
			continue
		}
		if !challenge.ExpiresAt.IsZero() && challenge.ExpiresAt.Before(now.Add(-1*time.Minute)) {
			continue
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, challenge.KeyAuth)
		return
	}
	if r.Header.Get("X-Acme-Proxied") == "" {
		client := &http.Client{Timeout: 2 * time.Second}
		nodes, err := s.Store.GetNodes()
		if err == nil {
			type target struct {
				id       string
				endpoint string
			}
			nodeMap := make(map[string]target, len(nodes))
			order := make([]target, 0, len(nodes))
			for _, node := range nodes {
				endpoint := strings.TrimSuffix(node.APIEndpoint, "/")
				if endpoint == "" {
					continue
				}
				if node.ID == s.Config.NodeID {
					continue
				}
				t := target{id: node.ID, endpoint: endpoint}
				nodeMap[node.ID] = t
				order = append(order, t)
			}
			if lockID := record.TLS.LockNodeID; lockID != "" {
				if t, ok := nodeMap[lockID]; ok {
					order = append([]target{t}, order...)
				}
			}
			seen := make(map[string]struct{}, len(order))
			for _, node := range order {
				if _, ok := seen[node.endpoint]; ok {
					continue
				}
				seen[node.endpoint] = struct{}{}
				req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, fmt.Sprintf("%s/.well-known/acme-challenge/%s", node.endpoint, token), nil)
				if err != nil {
					continue
				}
				req.Host = host
				req.Header.Set("Host", host)
				req.Header.Set("X-Acme-Proxied", "1")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				if resp.StatusCode == http.StatusOK {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = w.Write(body)
					return
				}
			}
		}
	}
	http.NotFound(w, r)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string          `json:"token"`
	User  models.User     `json:"user"`
	Role  models.UserRole `json:"role"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ip := strings.TrimSpace(clientIPFromRequest(r))
	hashedIP := s.hashIP(ip)
	attempts := buildAttemptDescriptors(email, hashedIP)
	now := time.Now().UTC()
	if locked, lockUntil, _ := s.loginAttemptsLocked(attempts, now); locked {
		retryAfter := int(time.Until(lockUntil).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "login temporarily locked")
		return
	}
	user, err := s.Store.FindUserByEmail(email)
	if err != nil {
		s.recordLoginFailure(attempts, now)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.recordLoginFailure(attempts, now)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.resetLoginAttempts(attempts)
	token, err := s.Auth.IssueToken(*user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{
		Token: token,
		User:  user.Sanitize(),
		Role:  user.Role,
	})
}

func (s *Server) authorizeUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_, claims, err := jwtauth.FromContext(ctx)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		role, _ := claims["role"].(string)
		email, _ := claims["email"].(string)
		email = strings.ToLower(strings.TrimSpace(email))
		ctx = withUserContext(ctx, sub, email, models.UserRole(role))
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_, claims, err := jwtauth.FromContext(ctx)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		role, _ := claims["role"].(string)
		if models.UserRole(role) != models.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin required")
			return
		}
		sub, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
		email = strings.ToLower(strings.TrimSpace(email))
		ctx = withUserContext(ctx, sub, email, models.RoleAdmin)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireRole(role models.UserRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_, claims, err := jwtauth.FromContext(ctx)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sub, _ := claims["sub"].(string)
		got, _ := claims["role"].(string)
		email, _ := claims["email"].(string)
		email = strings.ToLower(strings.TrimSpace(email))
		ctx = withUserContext(ctx, sub, email, models.UserRole(got))
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var (
		records []models.DomainRecord
		err     error
	)
	if user.Role == models.RoleAdmin {
		records, err = s.Store.GetDomains()
	} else {
		records, err = s.Store.ListDomainsForUser(user.ID, user.Email)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.populateDomainOwners(&records)
	nsList, nsErr := s.Infra.ActiveNameServers()
	if nsErr != nil {
		log.Printf("domains: load active nameservers failed: %v", nsErr)
		nsList = nil
	}
	defaultEntries := prepareDefaultNameServers(nsList)
	response := make([]domainResponse, 0, len(records))
	for i := range records {
		if records[i].IsSystemManaged() {
			continue
		}
		edge := records[i].Edge
		sanitized := records[i].Sanitize()
		sanitized.Edge = edge
		nsSet, anycastNames := s.composeNameserverSet(records[i].Domain, nsList, defaultEntries)
		sanitized.VanityNS = anycastNames
		var nsPtr *domainNameServerSet
		if len(nsSet.Default) > 0 || len(nsSet.Anycast) > 0 || len(nsSet.Vanity) > 0 {
			nsPtr = &nsSet
		}
		response = append(response, domainResponse{
			DomainRecord: sanitized,
			Nameservers:  nsPtr,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) populateDomainOwners(records *[]models.DomainRecord) {
	if records == nil || len(*records) == 0 {
		return
	}
	users, err := s.Store.GetUsers()
	if err != nil {
		log.Printf("domains: fetch users for owner metadata failed: %v", err)
		return
	}
	emailByID := make(map[string]string, len(users))
	for _, u := range users {
		if u.ID == "" {
			continue
		}
		if u.Email == "" {
			continue
		}
		emailByID[u.ID] = strings.ToLower(u.Email)
	}
	for i := range *records {
		rec := &(*records)[i]
		if rec.OwnerEmail != "" {
			rec.OwnerEmail = strings.ToLower(rec.OwnerEmail)
			continue
		}
		if email, ok := emailByID[rec.Owner]; ok {
			rec.OwnerEmail = email
			continue
		}
		if strings.Contains(rec.Owner, "@") {
			rec.OwnerEmail = strings.ToLower(rec.Owner)
		}
	}
}

func userOwnsDomain(user userContext, domain models.DomainRecord) bool {
	if user.Role == models.RoleAdmin {
		return true
	}
	return domain.MatchesOwner(user.ID, user.Email)
}

func (s *Server) attachOwnerMetadata(domain *models.DomainRecord) {
	if domain == nil {
		return
	}
	if domain.OwnerEmail != "" {
		domain.OwnerEmail = strings.ToLower(domain.OwnerEmail)
		return
	}
	if strings.Contains(domain.Owner, "@") {
		domain.OwnerEmail = strings.ToLower(domain.Owner)
		return
	}
	users, err := s.Store.GetUsers()
	if err != nil {
		log.Printf("domains: fetch users for owner lookup failed: %v", err)
		return
	}
	for _, u := range users {
		if u.ID == domain.Owner {
			domain.OwnerEmail = strings.ToLower(u.Email)
			return
		}
	}
}

func applyDomainWAFPayload(rec *models.DomainRecord, payload *domainWAFPayload) error {
	if rec == nil || payload == nil {
		return nil
	}
	if payload.Enabled != nil {
		rec.WAF.Enabled = *payload.Enabled
		if !rec.WAF.Enabled && payload.Presets == nil {
			rec.WAF.Presets = nil
		}
	}
	if payload.Presets != nil {
		values := make([]models.DomainWAFPreset, 0, len(*payload.Presets))
		for _, preset := range *payload.Presets {
			key := models.DomainWAFPreset(strings.TrimSpace(strings.ToLower(preset)))
			if key == "" {
				continue
			}
			values = append(values, key)
		}
		rec.WAF.Presets = values
	}
	rec.WAF.Normalize()
	return rec.WAF.Validate()
}

func applyDomainRoleUpdate(rec *models.DomainRecord, requestedRole *string, aliasPayload *domainAliasPayload, redirectPayload *[]domainRedirectRulePayload) error {
	if rec == nil {
		return nil
	}
	currentRole := rec.Role
	if !currentRole.Valid() {
		currentRole = models.DomainRolePrimary
	}
	targetRole := currentRole
	if requestedRole != nil {
		value := strings.ToLower(strings.TrimSpace(*requestedRole))
		role := models.DomainRole(value)
		if value == "" {
			role = models.DomainRolePrimary
		}
		if !role.Valid() {
			return models.ErrValidation("invalid domain role")
		}
		targetRole = role
	}
	switch targetRole {
	case models.DomainRoleAlias:
		var target string
		if aliasPayload != nil {
			target = strings.ToLower(strings.TrimSpace(aliasPayload.Target))
		} else if rec.Role == models.DomainRoleAlias && rec.Alias != nil {
			target = rec.Alias.Target
		}
		if target == "" {
			return models.ErrValidation("alias target must be provided")
		}
		rec.Role = models.DomainRoleAlias
		rec.Alias = &models.DomainAlias{Target: target}
		rec.RedirectRules = nil
	case models.DomainRoleRedirect:
		if redirectPayload != nil {
			rules, err := buildRedirectRulesFromPayload(rec.RedirectRules, *redirectPayload)
			if err != nil {
				return err
			}
			rec.RedirectRules = rules
		} else if rec.Role != models.DomainRoleRedirect || len(rec.RedirectRules) == 0 {
			return models.ErrValidation("redirect domains require redirect rules")
		}
		rec.Role = models.DomainRoleRedirect
		rec.Alias = nil
	case models.DomainRolePrimary:
		rec.Role = models.DomainRolePrimary
		rec.Alias = nil
		if redirectPayload != nil {
			rules, err := buildRedirectRulesFromPayload(rec.RedirectRules, *redirectPayload)
			if err != nil {
				return err
			}
			rec.RedirectRules = rules
		}
	default:
		return models.ErrValidation("invalid domain role")
	}
	if redirectPayload != nil && len(rec.RedirectRules) == 0 && targetRole != models.DomainRoleAlias {
		rec.RedirectRules = nil
	}
	return nil
}

func buildRedirectRulesFromPayload(existing []models.DomainRedirectRule, payload []domainRedirectRulePayload) ([]models.DomainRedirectRule, error) {
	if len(payload) == 0 {
		return []models.DomainRedirectRule{}, nil
	}
	existingByID := make(map[string]models.DomainRedirectRule, len(existing))
	for _, rule := range existing {
		existingByID[rule.ID] = rule
	}
	result := make([]models.DomainRedirectRule, 0, len(payload))
	seen := make(map[string]struct{}, len(payload))
	for _, item := range payload {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			id = generateRedirectRuleID()
		}
		if _, dup := seen[id]; dup {
			return nil, models.ErrValidation("duplicate redirect rule id")
		}
		seen[id] = struct{}{}
		rule := models.DomainRedirectRule{
			ID:     id,
			Source: strings.TrimSpace(item.Source),
			Target: strings.TrimSpace(item.Target),
		}
		if item.StatusCode != nil {
			rule.StatusCode = *item.StatusCode
		} else if prev, ok := existingByID[id]; ok {
			rule.StatusCode = prev.StatusCode
		}
		if rule.StatusCode == 0 {
			rule.StatusCode = 301
		}
		if item.PreservePath != nil {
			rule.PreservePath = *item.PreservePath
		} else if prev, ok := existingByID[id]; ok {
			rule.PreservePath = prev.PreservePath
		}
		if item.PreserveQuery != nil {
			rule.PreserveQuery = *item.PreserveQuery
		} else if prev, ok := existingByID[id]; ok {
			rule.PreserveQuery = prev.PreserveQuery
		} else {
			rule.PreserveQuery = true
		}
		rule.Normalize()
		result = append(result, rule)
	}
	return result, nil
}

func generateRedirectRuleID() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

func (s *Server) validateDomainLinkTargets(subject *models.DomainRecord, cache map[string]models.DomainRecord) (*models.DomainRecord, error) {
	if subject == nil {
		return nil, nil
	}
	var aliasPrimary *models.DomainRecord
	if subject.Role == models.DomainRoleAlias && subject.Alias != nil {
		target := strings.ToLower(strings.TrimSpace(subject.Alias.Target))
		if target == "" {
			return nil, models.ErrValidation("alias target must be provided")
		}
		if target == subject.Domain {
			return nil, models.ErrValidation("alias target must differ from domain")
		}
		primary, err := s.lookupDomainForLinks(target, cache)
		if err != nil {
			return nil, err
		}
		if primary.Role != models.DomainRolePrimary {
			return nil, models.ErrValidation("alias target must be a primary domain")
		}
		aliasPrimary = primary
	}
	for _, rule := range subject.RedirectRules {
		if !rule.IsDomainRule() {
			continue
		}
		target := strings.TrimSpace(rule.Target)
		if target == "" {
			return nil, models.ErrValidation("redirect rule target must be provided")
		}
		var parsed *url.URL
		if strings.Contains(target, "://") {
			p, err := url.Parse(target)
			if err != nil {
				return nil, models.ErrValidation("redirect rule target must be a valid URL")
			}
			if p.Scheme == "" {
				return nil, models.ErrValidation("redirect rule target must include a scheme")
			}
			scheme := strings.ToLower(p.Scheme)
			if scheme != "http" && scheme != "https" {
				return nil, models.ErrValidation("redirect rule target must use http or https scheme")
			}
			if p.Hostname() == "" {
				return nil, models.ErrValidation("redirect rule target must include a host")
			}
			parsed = p
		}
		host := rule.TargetHost()
		if host == "" {
			return nil, models.ErrValidation("redirect rule target must include a host")
		}
		if strings.EqualFold(host, subject.Domain) {
			return nil, models.ErrValidation("redirect rule cannot target the same domain")
		}
		if parsed != nil && parsed.Hostname() != "" && !strings.EqualFold(parsed.Hostname(), host) {
			// URL points at a specific subdomain; treat as external without further validation.
			continue
		}
		targetRec, err := s.lookupDomainForLinks(host, cache)
		if err != nil {
			if _, ok := err.(models.ErrValidation); ok {
				// Domain not managed locally – treat as external destination.
				continue
			}
			return nil, err
		}
		if strings.EqualFold(targetRec.Domain, subject.Domain) {
			return nil, models.ErrValidation("redirect rule cannot target the same domain")
		}
	}
	return aliasPrimary, nil
}

func (s *Server) lookupDomainForLinks(name string, cache map[string]models.DomainRecord) (*models.DomainRecord, error) {
	domain := strings.ToLower(strings.TrimSpace(name))
	if domain == "" {
		return nil, models.ErrValidation("domain target must be provided")
	}
	if cache != nil {
		if rec, ok := cache[domain]; ok {
			copy := rec
			return &copy, nil
		}
	}
	rec, err := s.Store.GetDomain(domain)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, models.ErrValidation("domain target not found")
		}
		return nil, err
	}
	if cache != nil {
		cache[domain] = *rec
	}
	return rec, nil
}

func (s *Server) findDomainDependents(primary string) ([]string, error) {
	primary = strings.ToLower(strings.TrimSpace(primary))
	if primary == "" {
		return nil, nil
	}
	domains, err := s.Store.GetDomains()
	if err != nil {
		return nil, err
	}
	dependents := make([]string, 0)
	for _, rec := range domains {
		if strings.EqualFold(rec.Domain, primary) {
			continue
		}
		if rec.Role == models.DomainRoleAlias && rec.Alias != nil && rec.Alias.Target == primary {
			dependents = append(dependents, rec.Domain)
			continue
		}
		if len(rec.RedirectRules) == 0 {
			continue
		}
		for _, rule := range rec.RedirectRules {
			if !rule.IsDomainRule() {
				continue
			}
			target := rule.TargetHost()
			if target == "" {
				continue
			}
			if target == primary {
				dependents = append(dependents, rec.Domain)
				break
			}
		}
	}
	return dependents, nil
}

func uniqueLowerStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func (s *Server) resolveDomainParents(record models.DomainRecord) []string {
	switch record.Role {
	case models.DomainRoleAlias:
		if record.Alias != nil {
			return uniqueLowerStrings([]string{record.Alias.Target})
		}
	case models.DomainRoleRedirect:
		candidates := make([]string, 0, len(record.RedirectRules))
		for _, rule := range record.RedirectRules {
			if !rule.IsDomainRule() {
				continue
			}
			host := rule.TargetHost()
			if host != "" {
				candidates = append(candidates, host)
			}
		}
		return uniqueLowerStrings(candidates)
	default:
		parents := []string{record.Domain}
		if len(record.RedirectRules) > 0 {
			for _, rule := range record.RedirectRules {
				if !rule.IsDomainRule() {
					continue
				}
				if host := rule.TargetHost(); host != "" {
					parents = append(parents, host)
				}
			}
		}
		return uniqueLowerStrings(parents)
	}
	return nil
}

func (s *Server) invalidateDomainFamilyCache(updated models.DomainRecord, previousParents []string) error {
	currentParents := s.resolveDomainParents(updated)
	parentSet := make(map[string]struct{}, len(previousParents)+len(currentParents))
	for _, parent := range previousParents {
		parent = strings.ToLower(strings.TrimSpace(parent))
		if parent != "" {
			parentSet[parent] = struct{}{}
		}
	}
	for _, parent := range currentParents {
		parentSet[parent] = struct{}{}
	}
	if len(parentSet) == 0 {
		return nil
	}
	members := make(map[string]struct{})
	members[strings.ToLower(strings.TrimSpace(updated.Domain))] = struct{}{}
	for parent := range parentSet {
		members[parent] = struct{}{}
		dependents, err := s.findDomainDependents(parent)
		if err != nil {
			return err
		}
		for _, dep := range dependents {
			members[strings.ToLower(strings.TrimSpace(dep))] = struct{}{}
		}
	}
	now := time.Now().UTC()
	for name := range members {
		if name == strings.ToLower(strings.TrimSpace(updated.Domain)) {
			continue
		}
		rec, err := s.Store.GetDomain(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return err
		}
		copy := *rec
		copy.CacheVersion++
		copy.EnsureCacheVersion()
		copy.UpdatedAt = now
		copy.Version.Counter++
		if copy.Version.Counter <= 0 {
			copy.Version.Counter = 1
		}
		copy.Version.NodeID = s.Config.NodeID
		copy.Version.Updated = now.Unix()
		if err := s.Store.UpsertDomain(copy); err != nil {
			return err
		}
	}
	return nil
}

func ensureRootDomain(name string) error {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if domain == "" {
		return models.ErrValidation("domain must be provided")
	}
	if net.ParseIP(domain) != nil {
		return models.ErrValidation("domain must be a hostname, not an IP address")
	}
	if strings.Contains(domain, "..") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return models.ErrValidation("invalid domain name")
	}
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		if domain != strings.ToLower(etld1) {
			return models.ErrValidation("please provide the root domain (e.g., example.com, not subdomain.example.com)")
		}
		return nil
	}
	parts := strings.Split(domain, ".")
	if len(parts) != 2 {
		return models.ErrValidation("please provide the root domain (e.g., example.com, not subdomain.example.com)")
	}
	for _, part := range parts {
		if part == "" {
			return models.ErrValidation("invalid domain name")
		}
	}
	return nil
}

func (s *Server) prepareDomainRecord(user userContext, domain string, owner string, origin string, proxied *bool, ttl *int, tlsPayload *domainTLSPayload, edgePayload *domainEdgePayload, wafPayload *domainWAFPayload, dnsRecords []domainDNSRecordPayload) (models.DomainRecord, error) {
	record := models.DomainRecord{
		Domain:       strings.ToLower(strings.TrimSpace(domain)),
		Owner:        strings.TrimSpace(owner),
		OriginIP:     strings.TrimSpace(origin),
		TTL:          60,
		Proxied:      true,
		OwnerEmail:   strings.ToLower(strings.TrimSpace(user.Email)),
		CacheVersion: 1,
		Role:         models.DomainRolePrimary,
	}
	if record.Domain == "" {
		return models.DomainRecord{}, models.ErrValidation("domain must be provided")
	}
	if err := ensureRootDomain(record.Domain); err != nil {
		return models.DomainRecord{}, err
	}
	if record.Owner == "" {
		record.Owner = user.ID
	} else {
		if user.Role == models.RoleAdmin {
			resolvedOwner, err := s.resolveOwnerDetails(record.Owner)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return models.DomainRecord{}, models.ErrValidation("owner not found")
				}
				return models.DomainRecord{}, err
			}
			record.Owner = resolvedOwner.ID
			record.OwnerEmail = strings.ToLower(strings.TrimSpace(resolvedOwner.Email))
		} else if record.Owner != user.ID && !strings.EqualFold(record.Owner, user.Email) {
			return models.DomainRecord{}, errForbiddenDomainOwner
		} else {
			// Non-admin referencing themselves via email.
			record.Owner = user.ID
			record.OwnerEmail = strings.ToLower(strings.TrimSpace(user.Email))
		}
	}
	if proxied != nil {
		record.Proxied = *proxied
	}
	if ttl != nil && *ttl > 0 {
		record.TTL = *ttl
	}
	if record.Proxied {
		record.TLS.Mode = models.EncryptionFlexible
		record.TLS.UseRecommended = true
	} else {
		record.TLS.Mode = models.EncryptionOff
		record.TLS.UseRecommended = false
	}
	record.TLS.Status = models.CertificateStatusNone
	if record.TLS.UseRecommended {
		queueTLSAutomation(&record, time.Time{})
	}
	if tlsPayload != nil {
		if tlsPayload.Mode != "" {
			record.TLS.Mode = models.EncryptionMode(strings.ToLower(tlsPayload.Mode))
		}
		if tlsPayload.UseRecommended != nil {
			record.TLS.UseRecommended = *tlsPayload.UseRecommended
		}
	}
	if edgePayload != nil && user.Role == models.RoleAdmin {
		record.Edge.Labels = append([]string{}, edgePayload.Labels...)
	}
	record.Edge.Normalize()
	if err := applyDomainWAFPayload(&record, wafPayload); err != nil {
		return models.DomainRecord{}, err
	}
	if err := ensureTLSProxyCompatibility(&record); err != nil {
		return models.DomainRecord{}, err
	}
	if !record.Proxied {
		disableTLSForDNS(&record)
	}
	now := time.Now().UTC()
	if len(dnsRecords) == 0 {
		record.DNSRecords = defaultDomainDNSRecords(record.Domain, record.OriginIP, record.Proxied, record.TTL, now)
	} else {
		custom, err := buildDomainDNSRecords(record.TTL, record.Proxied, dnsRecords, now)
		if err != nil {
			return models.DomainRecord{}, err
		}
		record.DNSRecords = custom
	}
	record.TLS.UpdatedAt = now
	if err := record.Validate(); err != nil {
		return models.DomainRecord{}, err
	}
	if existing, err := s.Store.GetDomainIncludingDeleted(record.Domain); err == nil && existing != nil {
		record.Version = existing.Version
		record.CacheVersion = existing.CacheVersion
	}
	record.EnsureCacheVersion()
	record.UpdatedAt = now
	record.Version.Counter++
	record.Version.NodeID = s.Config.NodeID
	record.Version.Updated = now.Unix()
	return record, nil
}

func defaultDomainDNSRecords(domain string, origin string, proxied bool, defaultTTL int, now time.Time) []models.DomainDNSRecord {
	if defaultTTL <= 0 {
		defaultTTL = 300
	}
	base := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	apex := models.DomainDNSRecord{
		ID:        uuid.NewString(),
		Name:      "@",
		Type:      models.DNSRecordTypeA,
		Content:   strings.TrimSpace(origin),
		Proxied:   proxied,
		TTL:       defaultTTL,
		CreatedAt: now,
		UpdatedAt: now,
	}
	www := models.DomainDNSRecord{
		ID:        uuid.NewString(),
		Name:      "www",
		Type:      models.DNSRecordTypeCNAME,
		Content:   base,
		Proxied:   proxied,
		TTL:       defaultTTL,
		CreatedAt: now,
		UpdatedAt: now,
	}
	records := make([]models.DomainDNSRecord, 0, 2)
	if strings.TrimSpace(origin) != "" {
		records = append(records, apex)
	}
	records = append(records, www)
	return records
}

func buildDomainDNSRecords(defaultTTL int, proxied bool, payload []domainDNSRecordPayload, now time.Time) ([]models.DomainDNSRecord, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if defaultTTL <= 0 {
		defaultTTL = 300
	}
	records := make([]models.DomainDNSRecord, 0, len(payload))
	for _, entry := range payload {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			return nil, models.ErrValidation("dns record name required")
		}
		recordType := models.DNSRecordType(strings.ToUpper(strings.TrimSpace(entry.Type)))
		rec := models.DomainDNSRecord{
			ID:        strings.TrimSpace(entry.ID),
			Name:      name,
			Type:      recordType,
			Content:   strings.TrimSpace(entry.Content),
			Proxied:   proxied,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if entry.Proxied != nil {
			rec.Proxied = *entry.Proxied
		}
		if entry.TTL != nil {
			rec.TTL = *entry.TTL
		} else {
			rec.TTL = defaultTTL
		}
		if entry.Priority != nil {
			val := *entry.Priority
			rec.Priority = &val
		}
		if recordType.RequiresPriority() && rec.Priority == nil {
			defaultPriority := 10
			rec.Priority = &defaultPriority
		}
		if entry.Comment != nil {
			rec.Comment = strings.TrimSpace(*entry.Comment)
		}
		if rec.ID == "" {
			rec.ID = uuid.NewString()
		}
		records = append(records, rec)
	}
	return records, nil
}

func normalizeRecordContentForDomain(rec *models.DomainRecord, record *models.DomainDNSRecord) {
	if rec == nil || record == nil {
		return
	}
	trimmed := strings.TrimSpace(record.Content)
	if trimmed != "@" {
		return
	}
	switch record.Type {
	case models.DNSRecordTypeA:
		origin := strings.TrimSpace(rec.OriginIP)
		record.Content = origin
	case models.DNSRecordTypeAAAA:
		record.Content = ""
	case models.DNSRecordTypeCNAME, models.DNSRecordTypeMX, models.DNSRecordTypeNS, models.DNSRecordTypePTR,
		models.DNSRecordTypeHTTPS, models.DNSRecordTypeSVCB, models.DNSRecordTypeURI, models.DNSRecordTypeSRV:
		record.Content = strings.TrimSuffix(rec.Domain, ".")
	}
}

func ensureApexARecord(rec *models.DomainRecord, now time.Time) bool {
	if rec == nil {
		return false
	}
	origin := strings.TrimSpace(rec.OriginIP)
	indices := make([]int, 0, len(rec.DNSRecords))
	for i := range rec.DNSRecords {
		record := rec.DNSRecords[i]
		name := strings.TrimSpace(record.Name)
		if name == "" || name == "@" {
			if record.Type == models.DNSRecordTypeA {
				indices = append(indices, i)
			}
		}
	}
	changed := false
	if origin == "" {
		if len(indices) > 0 {
			filtered := make([]models.DomainDNSRecord, 0, len(rec.DNSRecords)-len(indices))
			for i := range rec.DNSRecords {
				skip := false
				for _, idx := range indices {
					if i == idx {
						skip = true
						break
					}
				}
				if !skip {
					filtered = append(filtered, rec.DNSRecords[i])
				}
			}
			rec.DNSRecords = filtered
			changed = true
		}
		return changed
	}
	// Ensure exactly one apex A record remains, sync content/flags/ttl
	var target *models.DomainDNSRecord
	if len(indices) > 0 {
		target = &rec.DNSRecords[indices[0]]
		// Remove duplicates beyond the first
		if len(indices) > 1 {
			filtered := make([]models.DomainDNSRecord, 0, len(rec.DNSRecords)-(len(indices)-1))
			for i := range rec.DNSRecords {
				duplicate := false
				for _, idx := range indices[1:] {
					if i == idx {
						duplicate = true
						break
					}
				}
				if !duplicate {
					filtered = append(filtered, rec.DNSRecords[i])
				}
			}
			rec.DNSRecords = filtered
			// target pointer may have been invalidated, reassign
			for i := range rec.DNSRecords {
				record := rec.DNSRecords[i]
				name := strings.TrimSpace(record.Name)
				if record.Type == models.DNSRecordTypeA && (name == "" || name == "@") {
					target = &rec.DNSRecords[i]
					break
				}
			}
			changed = true
		}
	}
	if target == nil {
		ttl := rec.TTL
		if ttl <= 0 {
			ttl = 300
		}
		rec.DNSRecords = append(rec.DNSRecords, models.DomainDNSRecord{
			ID:        uuid.NewString(),
			Name:      "@",
			Type:      models.DNSRecordTypeA,
			Content:   origin,
			TTL:       ttl,
			Proxied:   rec.Proxied,
			CreatedAt: now,
			UpdatedAt: now,
		})
		return true
	}
	ttl := rec.TTL
	if ttl <= 0 {
		ttl = 300
	}
	updatedFlag := false
	if target.Content != origin {
		target.Content = origin
		updatedFlag = true
	}
	if target.Proxied != rec.Proxied {
		target.Proxied = rec.Proxied
		updatedFlag = true
	}
	if target.TTL != ttl {
		target.TTL = ttl
		updatedFlag = true
	}
	if updatedFlag {
		target.UpdatedAt = now
	}
	target.Normalize()
	return changed || updatedFlag
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var payload createDomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Edge != nil && user.Role != models.RoleAdmin {
		writeError(w, http.StatusForbidden, "edge configuration requires admin")
		return
	}
	origin := ""
	if payload.OriginIP != nil {
		origin = *payload.OriginIP
	}
	if payload.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	record, err := s.prepareDomainRecord(user, payload.Domain, payload.Owner, origin, payload.Proxied, payload.TTL, payload.TLS, payload.Edge, payload.WAF, payload.DNSRecords)
	if err != nil {
		if errors.Is(err, errForbiddenDomainOwner) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if ve, ok := err.(models.ErrValidation); ok {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var rolePtr *string
	roleValue := strings.TrimSpace(payload.Role)
	if roleValue != "" {
		rolePtr = &roleValue
	}
	var redirectPtr *[]domainRedirectRulePayload
	var redirectCopy []domainRedirectRulePayload
	if payload.RedirectRules != nil {
		redirectCopy = payload.RedirectRules
		redirectPtr = &redirectCopy
	}
	if err := applyDomainRoleUpdate(&record, rolePtr, payload.Alias, redirectPtr); err != nil {
		if ve, ok := err.(models.ErrValidation); ok {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.validateDomainLinkTargets(&record, nil); err != nil {
		if ve, ok := err.(models.ErrValidation); ok {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record.Proxied {
		if _, err := s.ensureDomainEdgeAssignment(&record); err != nil {
			if ve, ok := err.(models.ErrValidation); ok {
				writeError(w, http.StatusBadRequest, ve.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.Store.UpsertDomain(record); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if record.Role == models.DomainRoleAlias || record.Role == models.DomainRoleRedirect || len(record.RedirectRules) > 0 {
		if err := s.invalidateDomainFamilyCache(record, nil); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	if s.Whois != nil {
		domainName := record.Domain
		go func() {
			ctx := context.Background()
			updated, err := s.refreshDomainWhois(ctx, domainName, "auto")
			if err != nil {
				log.Printf("whois refresh %s (create) failed: %v", domainName, err)
				if updated != nil {
					s.triggerSyncBroadcast()
					s.Orchestrator.Trigger(ctx)
				}
				return
			}
			if updated != nil {
				s.triggerSyncBroadcast()
				s.Orchestrator.Trigger(ctx)
			}
		}()
	}
	writeJSON(w, http.StatusCreated, record.Sanitize())
}

func (s *Server) handleBulkCreateDomains(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var payload bulkDomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Edge != nil && user.Role != models.RoleAdmin {
		writeError(w, http.StatusForbidden, "edge configuration requires admin")
		return
	}
	if len(payload.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "domains required")
		return
	}
	origin := ""
	if payload.OriginIP != nil {
		origin = *payload.OriginIP
	}
	results := make([]bulkDomainResult, 0, len(payload.Domains))
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(payload.Domains))
	skipped := 0
	failed := 0
	for _, raw := range payload.Domains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			failed++
			results = append(results, bulkDomainResult{Domain: raw, Status: "failed", Error: "domain required"})
			continue
		}
		if _, ok := seen[domain]; ok {
			skipped++
			results = append(results, bulkDomainResult{Domain: domain, Status: "skipped", Error: "duplicate"})
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}
	if len(normalized) > maxBulkDomains {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many domains (max %d)", maxBulkDomains))
		return
	}
	roleValue := strings.TrimSpace(payload.Role)
	var rolePtr *string
	if roleValue != "" {
		rolePtr = &roleValue
	}
	var redirectPtr *[]domainRedirectRulePayload
	var redirectCopy []domainRedirectRulePayload
	if payload.RedirectRules != nil {
		redirectCopy = payload.RedirectRules
		redirectPtr = &redirectCopy
	}
	linkCache := make(map[string]models.DomainRecord)
	success := 0
	familyInvalidations := make([]models.DomainRecord, 0)
	for _, domain := range normalized {
		record, err := s.prepareDomainRecord(user, domain, payload.Owner, origin, payload.Proxied, payload.TTL, payload.TLS, payload.Edge, payload.WAF, payload.DNSRecords)
		if err != nil {
			failed++
			errMsg := err.Error()
			if errors.Is(err, errForbiddenDomainOwner) {
				errMsg = errForbiddenDomainOwner.Error()
			}
			if ve, ok := err.(models.ErrValidation); ok {
				errMsg = ve.Error()
			}
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
			continue
		}
		if err := applyDomainRoleUpdate(&record, rolePtr, payload.Alias, redirectPtr); err != nil {
			failed++
			errMsg := err.Error()
			if ve, ok := err.(models.ErrValidation); ok {
				errMsg = ve.Error()
			}
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
			continue
		}
		if _, err := s.validateDomainLinkTargets(&record, linkCache); err != nil {
			failed++
			errMsg := err.Error()
			if ve, ok := err.(models.ErrValidation); ok {
				errMsg = ve.Error()
			}
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
			continue
		}
		if record.Proxied {
			if _, err := s.ensureDomainEdgeAssignment(&record); err != nil {
				failed++
				errMsg := err.Error()
				if ve, ok := err.(models.ErrValidation); ok {
					errMsg = ve.Error()
				}
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
				continue
			}
		}
		if err := s.Store.UpsertDomain(record); err != nil {
			failed++
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: err.Error()})
			continue
		}
		if record.Role == models.DomainRoleAlias || record.Role == models.DomainRoleRedirect || len(record.RedirectRules) > 0 {
			familyInvalidations = append(familyInvalidations, record)
		}
		success++
		if s.Whois != nil {
			domainName := record.Domain
			go func() {
				ctx := context.Background()
				updated, err := s.refreshDomainWhois(ctx, domainName, "auto")
				if err != nil {
					log.Printf("whois refresh %s (bulk create) failed: %v", domainName, err)
					if updated != nil {
						s.triggerSyncBroadcast()
						s.Orchestrator.Trigger(ctx)
					}
					return
				}
				if updated != nil {
					s.triggerSyncBroadcast()
					s.Orchestrator.Trigger(ctx)
				}
			}()
		}
		sanitized := record.Sanitize()
		recCopy := sanitized
		results = append(results, bulkDomainResult{Domain: domain, Status: "created", Record: &recCopy})
	}
	for _, rec := range familyInvalidations {
		if err := s.invalidateDomainFamilyCache(rec, nil); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if success > 0 {
		s.triggerSyncBroadcast()
		go s.Orchestrator.Trigger(r.Context())
	}
	resp := bulkDomainResponse{Results: results, Success: success, Failed: failed, Skipped: skipped}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBulkUpdateDomains(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var payload bulkUpdateDomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if len(payload.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "domains required")
		return
	}
	results := make([]bulkDomainResult, 0, len(payload.Domains))
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(payload.Domains))
	skipped := 0
	failed := 0
	for _, raw := range payload.Domains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			failed++
			results = append(results, bulkDomainResult{Domain: raw, Status: "failed", Error: "domain required"})
			continue
		}
		if _, ok := seen[domain]; ok {
			skipped++
			results = append(results, bulkDomainResult{Domain: domain, Status: "skipped", Error: "duplicate"})
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}
	if len(normalized) > maxBulkDomains {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many domains (max %d)", maxBulkDomains))
		return
	}
	var transferOwner *models.User
	if payload.Owner != nil {
		if user.Role != models.RoleAdmin {
			writeError(w, http.StatusForbidden, "owner updates require admin")
			return
		}
		resolvedOwner, err := s.resolveOwnerDetails(*payload.Owner)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "owner not found")
				return
			}
			if ve, ok := err.(models.ErrValidation); ok {
				writeError(w, http.StatusBadRequest, ve.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		transferOwner = resolvedOwner
	}
	linkCache := make(map[string]models.DomainRecord)
	success := 0
	for _, domain := range normalized {
		existing, err := s.Store.GetDomain(domain)
		if err != nil {
			failed++
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: "domain not found"})
			continue
		}
		s.attachOwnerMetadata(existing)
		if !userOwnsDomain(user, *existing) {
			failed++
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: "forbidden"})
			continue
		}
		prevOrigin := strings.TrimSpace(existing.OriginIP)
		prevParents := s.resolveDomainParents(*existing)
		linksTouched := payload.Role != nil || payload.Alias != nil || payload.RedirectRules != nil
		cacheBumped := false
		if payload.OriginIP != nil {
			origin := strings.TrimSpace(*payload.OriginIP)
			existing.OriginIP = origin
		}
		if payload.Proxied != nil {
			prevProxy := existing.Proxied
			existing.Proxied = *payload.Proxied
			if !existing.Proxied {
				disableTLSForDNS(existing)
			} else if !prevProxy && payload.TLS == nil {
				existing.TLS.UseRecommended = true
				existing.TLS.Mode = models.EncryptionFlexible
				queueTLSAutomation(existing, time.Now().UTC())
			}
		}
		if payload.OriginIP != nil {
			newOrigin := strings.TrimSpace(*payload.OriginIP)
			if newOrigin != prevOrigin {
				existing.CacheVersion++
				cacheBumped = true
			}
		}
		if payload.TTL != nil && *payload.TTL > 0 {
			existing.TTL = *payload.TTL
		}
		if payload.TLS != nil {
			if payload.TLS.Mode != "" {
				existing.TLS.Mode = models.EncryptionMode(strings.ToLower(payload.TLS.Mode))
			}
			if payload.TLS.UseRecommended != nil {
				prevAuto := existing.TLS.UseRecommended
				existing.TLS.UseRecommended = *payload.TLS.UseRecommended
				existing.TLS.Challenges = nil
				existing.TLS.LockID = ""
				existing.TLS.LockNodeID = ""
				existing.TLS.LockExpiresAt = time.Time{}
				existing.TLS.RecommendedMode = ""
				existing.TLS.RecommendedAt = time.Time{}
				if existing.TLS.UseRecommended {
					if !prevAuto || existing.TLS.Certificate == nil || existing.TLS.Certificate.CertChainPEM == "" {
						queueTLSAutomation(existing, time.Now().UTC())
					}
				} else {
					if existing.TLS.Certificate != nil && existing.TLS.Certificate.CertChainPEM != "" {
						existing.TLS.Status = models.CertificateStatusActive
					} else {
						existing.TLS.Status = models.CertificateStatusNone
						existing.TLS.LastError = ""
					}
				}
			}
			existing.TLS.UpdatedAt = time.Now().UTC()
		}
		if transferOwner != nil {
			existing.Owner = transferOwner.ID
			existing.OwnerEmail = strings.ToLower(strings.TrimSpace(transferOwner.Email))
		}
		if payload.Edge != nil {
			if user.Role != models.RoleAdmin {
				failed++
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: "edge updates require admin"})
				continue
			}
			existing.Edge.Labels = append([]string{}, payload.Edge.Labels...)
			existing.Edge.Normalize()
		}
		if payload.WAF != nil {
			if err := applyDomainWAFPayload(existing, payload.WAF); err != nil {
				failed++
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: err.Error()})
				continue
			}
		}
		if payload.Role != nil || payload.Alias != nil || payload.RedirectRules != nil {
			if err := applyDomainRoleUpdate(existing, payload.Role, payload.Alias, payload.RedirectRules); err != nil {
				failed++
				errMsg := err.Error()
				if ve, ok := err.(models.ErrValidation); ok {
					errMsg = ve.Error()
				}
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
				continue
			}
			if _, err := s.validateDomainLinkTargets(existing, linkCache); err != nil {
				failed++
				errMsg := err.Error()
				if ve, ok := err.(models.ErrValidation); ok {
					errMsg = ve.Error()
				}
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
				continue
			}
		}
		if linksTouched && !cacheBumped {
			existing.CacheVersion++
			cacheBumped = true
		}
		if existing.Proxied {
			// Use mutex to prevent concurrent edge assignments
			s.edgeReconcileMu.Lock()
			_, edgeErr := s.ensureDomainEdgeAssignment(existing)
			s.edgeReconcileMu.Unlock()

			if edgeErr != nil {
				failed++
				errMsg := edgeErr.Error()
				if ve, ok := edgeErr.(models.ErrValidation); ok {
					errMsg = ve.Error()
				}
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: errMsg})
				continue
			}
		} else {
			existing.Edge.AssignedIP = ""
			existing.Edge.AssignedNodeID = ""
			existing.Edge.AssignedAt = time.Time{}
			existing.Edge.Normalize()
		}
		if err := ensureTLSProxyCompatibility(existing); err != nil {
			failed++
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: err.Error()})
			continue
		}
		if !existing.Proxied {
			disableTLSForDNS(existing)
		}
		if err := existing.Validate(); err != nil {
			failed++
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: err.Error()})
			continue
		}
		now := time.Now().UTC()
		existing.UpdatedAt = now
		existing.Version.Counter++
		existing.Version.NodeID = s.Config.NodeID
		existing.Version.Updated = now.Unix()
		if err := s.Store.UpsertDomain(*existing); err != nil {
			failed++
			results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: err.Error()})
			continue
		}
		if linksTouched {
			if err := s.invalidateDomainFamilyCache(*existing, prevParents); err != nil {
				failed++
				results = append(results, bulkDomainResult{Domain: domain, Status: "failed", Error: err.Error()})
				continue
			}
		}
		success++
		sanitized := existing.Sanitize()
		recCopy := sanitized
		results = append(results, bulkDomainResult{Domain: domain, Status: "updated", Record: &recCopy})
	}
	if success > 0 {
		s.triggerSyncBroadcast()
		go s.Orchestrator.Trigger(r.Context())
	}
	resp := bulkDomainResponse{Results: results, Success: success, Failed: failed, Skipped: skipped}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	prevParents := s.resolveDomainParents(*existing)
	var payload updateDomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	prevOrigin := strings.TrimSpace(existing.OriginIP)
	updated := *existing
	linksTouched := payload.Role != nil || payload.Alias != nil || payload.RedirectRules != nil
	cacheBumped := false
	apexTouched := false
	if payload.OriginIP != nil {
		origin := strings.TrimSpace(*payload.OriginIP)
		updated.OriginIP = origin
		for i := range updated.DNSRecords {
			rec := &updated.DNSRecords[i]
			if rec.Type == models.DNSRecordTypeA && rec.Proxied {
				trimmedContent := strings.TrimSpace(rec.Content)
				if trimmedContent == "" || trimmedContent == prevOrigin {
					rec.Content = origin
				}
			}
		}
		if origin != prevOrigin {
			updated.CacheVersion++
			cacheBumped = true
		}
		apexTouched = true
	}
	if payload.Proxied != nil {
		prevProxy := updated.Proxied
		updated.Proxied = *payload.Proxied
		if !updated.Proxied {
			for i := range updated.DNSRecords {
				updated.DNSRecords[i].Proxied = false
			}
			disableTLSForDNS(&updated)
		} else if !prevProxy && payload.TLS == nil {
			updated.TLS.UseRecommended = true
			updated.TLS.Mode = models.EncryptionFlexible
			queueTLSAutomation(&updated, time.Now().UTC())
		}
		apexTouched = true
	}
	if payload.TTL != nil && *payload.TTL > 0 {
		updated.TTL = *payload.TTL
	}
	if payload.Owner != nil {
		if user.Role != models.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		resolvedOwner, err := s.resolveOwnerDetails(*payload.Owner)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "owner not found")
				return
			}
			if ve, ok := err.(models.ErrValidation); ok {
				writeError(w, http.StatusBadRequest, ve.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		updated.Owner = resolvedOwner.ID
		updated.OwnerEmail = strings.ToLower(strings.TrimSpace(resolvedOwner.Email))
	}
	if payload.TLS != nil {
		if payload.TLS.Mode != "" {
			updated.TLS.Mode = models.EncryptionMode(strings.ToLower(payload.TLS.Mode))
		}
		if payload.TLS.UseRecommended != nil {
			prevAuto := updated.TLS.UseRecommended
			updated.TLS.UseRecommended = *payload.TLS.UseRecommended
			updated.TLS.Challenges = nil
			updated.TLS.LockID = ""
			updated.TLS.LockNodeID = ""
			updated.TLS.LockExpiresAt = time.Time{}
			updated.TLS.RecommendedMode = ""
			updated.TLS.RecommendedAt = time.Time{}
			if updated.TLS.UseRecommended {
				if !prevAuto || updated.TLS.Certificate == nil || updated.TLS.Certificate.CertChainPEM == "" {
					queueTLSAutomation(&updated, time.Now().UTC())
				}
			} else {
				if updated.TLS.Certificate != nil && updated.TLS.Certificate.CertChainPEM != "" {
					updated.TLS.Status = models.CertificateStatusActive
				} else {
					updated.TLS.Status = models.CertificateStatusNone
					updated.TLS.LastError = ""
				}
			}
		}
		updated.TLS.UpdatedAt = time.Now().UTC()
	}
	if payload.Edge != nil {
		if user.Role != models.RoleAdmin {
			writeError(w, http.StatusForbidden, "edge updates require admin")
			return
		}
		updated.Edge.Labels = append([]string{}, payload.Edge.Labels...)
		updated.Edge.Normalize()
	}
	if payload.WAF != nil {
		if err := applyDomainWAFPayload(&updated, payload.WAF); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if payload.Role != nil || payload.Alias != nil || payload.RedirectRules != nil {
		if err := applyDomainRoleUpdate(&updated, payload.Role, payload.Alias, payload.RedirectRules); err != nil {
			if ve, ok := err.(models.ErrValidation); ok {
				writeError(w, http.StatusBadRequest, ve.Error())
			} else {
				writeError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		if _, err := s.validateDomainLinkTargets(&updated, nil); err != nil {
			if ve, ok := err.(models.ErrValidation); ok {
				writeError(w, http.StatusBadRequest, ve.Error())
			} else {
				writeError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
	}
	if linksTouched && !cacheBumped {
		updated.CacheVersion++
		cacheBumped = true
	}
	if updated.Proxied {
		s.edgeReconcileMu.Lock()
		_, edgeErr := s.ensureDomainEdgeAssignment(&updated)
		s.edgeReconcileMu.Unlock()
		if edgeErr != nil {
			if ve, ok := edgeErr.(models.ErrValidation); ok {
				writeError(w, http.StatusBadRequest, ve.Error())
			} else {
				writeError(w, http.StatusInternalServerError, edgeErr.Error())
			}
			return
		}
	} else {
		updated.Edge.AssignedIP = ""
		updated.Edge.AssignedNodeID = ""
		updated.Edge.AssignedAt = time.Time{}
		updated.Edge.Normalize()
	}
	if err := ensureTLSProxyCompatibility(&updated); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !updated.Proxied {
		disableTLSForDNS(&updated)
	}
	now := time.Now().UTC()
	if ensureApexARecord(&updated, now) {
		apexTouched = true
	}
	if apexTouched && !cacheBumped {
		updated.CacheVersion++
		cacheBumped = true
	}
	if err := updated.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated.UpdatedAt = now
	updated.Version.Counter++
	updated.Version.NodeID = s.Config.NodeID
	updated.Version.Updated = now.Unix()
	if err := s.Store.UpsertDomain(updated); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if linksTouched {
		if err := s.invalidateDomainFamilyCache(updated, prevParents); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, updated.Sanitize())
}

func (s *Server) handleListDomainDNSRecords(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	records := make([]models.DomainDNSRecord, len(existing.DNSRecords))
	copy(records, existing.DNSRecords)
	writeJSON(w, http.StatusOK, records)
}

func (s *Server) handleCreateDomainDNSRecord(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domainName := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domainName)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var payload domainDNSRecordPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	now := time.Now().UTC()
	var created models.DomainDNSRecord
	_, err = s.Store.MutateDomain(domainName, func(rec *models.DomainRecord) error {
		records, err := buildDomainDNSRecords(rec.TTL, rec.Proxied, []domainDNSRecordPayload{payload}, now)
		if err != nil {
			return err
		}
		newRecord := records[0]
		normalizeRecordContentForDomain(rec, &newRecord)
		rec.DNSRecords = append(rec.DNSRecords, newRecord)
		trimmedName := strings.TrimSpace(newRecord.Name)
		if trimmedName == "" || trimmedName == "@" {
			if newRecord.Type == models.DNSRecordTypeA {
				trimmedContent := strings.TrimSpace(newRecord.Content)
				if trimmedContent != "" && trimmedContent != "@" {
					rec.OriginIP = trimmedContent
				}
			}
		}
		rec.CacheVersion++
		rec.EnsureCacheVersion()
		rec.UpdatedAt = now
		rec.Version.Counter++
		if rec.Version.Counter <= 0 {
			rec.Version.Counter = 1
		}
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		if err := rec.Validate(); err != nil {
			return err
		}
		for _, candidate := range rec.DNSRecords {
			if candidate.ID == newRecord.ID {
				created = candidate
				break
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		if ve, ok := err.(models.ErrValidation); ok {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleUpdateDomainDNSRecord(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domainName := strings.ToLower(chi.URLParam(r, "domain"))
	recordID := strings.TrimSpace(chi.URLParam(r, "id"))
	if recordID == "" {
		writeError(w, http.StatusBadRequest, "dns record id required")
		return
	}
	existing, err := s.Store.GetDomain(domainName)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var payload domainDNSRecordPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	payload.ID = recordID
	now := time.Now().UTC()
	var updatedRecord models.DomainDNSRecord
	_, err = s.Store.MutateDomain(domainName, func(rec *models.DomainRecord) error {
		index := -1
		var current models.DomainDNSRecord
		for i := range rec.DNSRecords {
			if rec.DNSRecords[i].ID == recordID {
				index = i
				current = rec.DNSRecords[i]
				break
			}
		}
		if index < 0 {
			return fs.ErrNotExist
		}
		records, err := buildDomainDNSRecords(rec.TTL, rec.Proxied, []domainDNSRecordPayload{payload}, now)
		if err != nil {
			return err
		}
		next := records[0]
		normalizeRecordContentForDomain(rec, &next)
		next.ID = current.ID
		if !current.CreatedAt.IsZero() {
			next.CreatedAt = current.CreatedAt
		}
		next.UpdatedAt = now
		rec.DNSRecords[index] = next
		trimmedName := strings.TrimSpace(next.Name)
		if trimmedName == "" || trimmedName == "@" {
			if next.Type == models.DNSRecordTypeA {
				trimmedContent := strings.TrimSpace(next.Content)
				if trimmedContent != "" && trimmedContent != "@" {
					rec.OriginIP = trimmedContent
				}
			}
		}
		rec.CacheVersion++
		rec.EnsureCacheVersion()
		rec.UpdatedAt = now
		rec.Version.Counter++
		if rec.Version.Counter <= 0 {
			rec.Version.Counter = 1
		}
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		if err := rec.Validate(); err != nil {
			return err
		}
		for _, candidate := range rec.DNSRecords {
			if candidate.ID == next.ID {
				updatedRecord = candidate
				break
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "dns record not found")
			return
		}
		if ve, ok := err.(models.ErrValidation); ok {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, updatedRecord)
}

func (s *Server) handleDeleteDomainDNSRecord(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domainName := strings.ToLower(chi.URLParam(r, "domain"))
	recordID := strings.TrimSpace(chi.URLParam(r, "id"))
	if recordID == "" {
		writeError(w, http.StatusBadRequest, "dns record id required")
		return
	}
	existing, err := s.Store.GetDomain(domainName)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	now := time.Now().UTC()
	_, err = s.Store.MutateDomain(domainName, func(rec *models.DomainRecord) error {
		index := -1
		for i := range rec.DNSRecords {
			if rec.DNSRecords[i].ID == recordID {
				index = i
				break
			}
		}
		if index < 0 {
			return fs.ErrNotExist
		}
		record := rec.DNSRecords[index]
		rec.DNSRecords = append(rec.DNSRecords[:index], rec.DNSRecords[index+1:]...)
		trimmedName := strings.TrimSpace(record.Name)
		trimmedContent := strings.TrimSpace(record.Content)
		if (trimmedName == "" || trimmedName == "@") && record.Type == models.DNSRecordTypeA {
			if trimmedContent != "" && trimmedContent != "@" {
				rec.OriginIP = ""
			}
		}
		rec.CacheVersion++
		rec.EnsureCacheVersion()
		rec.UpdatedAt = now
		rec.Version.Counter++
		if rec.Version.Counter <= 0 {
			rec.Version.Counter = 1
		}
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		if err := rec.Validate(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "dns record not found")
			return
		}
		if ve, ok := err.(models.ErrValidation); ok {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePurgeDomainCache(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	existing.CacheVersion++
	existing.EnsureCacheVersion()
	now := time.Now().UTC()
	existing.UpdatedAt = now
	existing.Version.Counter++
	if existing.Version.Counter <= 0 {
		existing.Version.Counter = 1
	}
	existing.Version.NodeID = s.Config.NodeID
	existing.Version.Updated = now.Unix()
	if err := s.Store.UpsertDomain(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, existing.Sanitize())
}

func (s *Server) handleRefreshDomainWhois(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	user := userFromContext(r.Context())
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	updated, lookupErr := s.refreshDomainWhois(r.Context(), existing.Domain, "auto")
	if updated == nil {
		if errors.Is(lookupErr, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		if lookupErr != nil {
			writeError(w, http.StatusInternalServerError, lookupErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to refresh whois")
		return
	}
	if lookupErr != nil {
		log.Printf("whois refresh %s failed: %v", existing.Domain, lookupErr)
	}
	s.attachOwnerMetadata(updated)
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, updated.Sanitize())
}

func (s *Server) handleOverrideDomainWhois(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	user := userFromContext(r.Context())
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var payload domainWhoisManualPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	value := strings.TrimSpace(payload.ExpiresAt)
	if value == "" {
		writeError(w, http.StatusBadRequest, "expires_at required")
		return
	}
	parsed, err := dateparse.ParseIn(value, time.UTC)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid expires_at: %v", err))
		return
	}
	now := time.Now().UTC()
	rawInput := strings.TrimSpace(payload.RawInput)
	if rawInput == "" {
		rawInput = value
	}
	updated, err := s.Store.MutateDomain(existing.Domain, func(rec *models.DomainRecord) error {
		rec.Whois.ExpiresAt = parsed.UTC()
		rec.Whois.CheckedAt = now
		rec.Whois.Source = "manual"
		rec.Whois.LastError = ""
		if rawInput != "" {
			rec.Whois.RawExpires = rawInput
		} else {
			rec.Whois.RawExpires = rec.Whois.ExpiresAt.Format(time.RFC3339)
		}
		rec.Version.Counter++
		if rec.Version.Counter <= 0 {
			rec.Version.Counter = 1
		}
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		rec.UpdatedAt = now
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.attachOwnerMetadata(updated)
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, updated.Sanitize())
}

func (s *Server) refreshDomainWhois(ctx context.Context, domain string, source string) (*models.DomainRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if source == "" {
		source = "auto"
	}
	now := time.Now().UTC()
	var (
		lookupResult whois.Result
		lookupErr    error
	)
	if s.Whois == nil {
		lookupErr = errors.New("whois service unavailable")
	} else {
		lookupResult, lookupErr = s.Whois.Lookup(ctx, domain)
	}
	updated, err := s.Store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		rec.Whois.CheckedAt = now
		rec.Whois.Source = source
		if lookupErr == nil && !lookupResult.ExpiresAt.IsZero() {
			rec.Whois.ExpiresAt = lookupResult.ExpiresAt.UTC()
			rec.Whois.LastError = ""
		} else {
			if lookupErr != nil {
				rec.Whois.LastError = lookupErr.Error()
			} else {
				rec.Whois.LastError = whois.ErrNoExpiration.Error()
			}
		}
		if lookupResult.RawExpiration != "" {
			rec.Whois.RawExpires = lookupResult.RawExpiration
		}
		rec.Version.Counter++
		if rec.Version.Counter <= 0 {
			rec.Version.Counter = 1
		}
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		rec.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	if lookupErr == nil && !lookupResult.ExpiresAt.IsZero() {
		return updated, nil
	}
	if lookupErr != nil {
		return updated, lookupErr
	}
	return updated, whois.ErrNoExpiration
}

func (s *Server) handleListExtensions(w http.ResponseWriter, r *http.Request) {
	if s.Extensions == nil {
		writeError(w, http.StatusNotImplemented, "extensions service unavailable")
		return
	}
	exts, err := s.Extensions.ListGlobal()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := make([]extensionDTO, 0, len(exts))
	for _, ext := range exts {
		dto := extensionToDTO(ext)
		if ext.Definition.Key == models.ExtensionSearchBotLogs {
			if metrics, err := s.searchBotMetrics(r.Context()); err != nil {
				log.Printf("extensions: searchbot metrics failed: %v", err)
			} else if metrics != nil {
				dto.Metrics = metrics
			}
		}
		response = append(response, dto)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleUpdateExtension(w http.ResponseWriter, r *http.Request) {
	if s.Extensions == nil {
		writeError(w, http.StatusNotImplemented, "extensions service unavailable")
		return
	}
	key := strings.ToLower(chi.URLParam(r, "key"))
	var payload updateExtensionPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Enabled == nil && payload.Config == nil {
		writeError(w, http.StatusBadRequest, "nothing to update")
		return
	}
	user := userFromContext(r.Context())
	ext, err := s.Extensions.UpdateGlobal(key, payload.Enabled, payload.Config, user.ID)
	if err != nil {
		if errors.Is(err, extensions.ErrNotFound) {
			writeError(w, http.StatusNotFound, "extension not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if key == models.ExtensionSearchBotLogs {
		s.RefreshSearchBotConfig()
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	dto := extensionToDTO(ext)
	if ext.Definition.Key == models.ExtensionSearchBotLogs {
		if metrics, err := s.searchBotMetrics(r.Context()); err != nil {
			log.Printf("extensions: searchbot metrics failed: %v", err)
		} else if metrics != nil {
			dto.Metrics = metrics
		}
	}
	writeJSON(w, http.StatusOK, dto)
}

func (s *Server) handleExtensionAction(w http.ResponseWriter, r *http.Request) {
	if s.Extensions == nil {
		writeError(w, http.StatusNotImplemented, "extensions service unavailable")
		return
	}
	key := strings.ToLower(chi.URLParam(r, "key"))
	action := strings.ToLower(chi.URLParam(r, "action"))
	ext, err := s.Extensions.GetGlobal(key)
	if err != nil {
		if errors.Is(err, extensions.ErrNotFound) {
			writeError(w, http.StatusNotFound, "extension not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for _, act := range ext.Definition.Actions {
		if strings.EqualFold(act.Key, action) {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "action not supported")
		return
	}
	switch key {
	case models.ExtensionEdgeCache:
		if action == "purge" {
			if err := s.Orchestrator.PurgeEdgeCache(r.Context()); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "purge_queued"})
			return
		}
	case models.ExtensionSearchBotLogs:
		if action == "clear_logs" {
			if err := s.clearSearchBotLogs(r.Context()); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "cleared"})
			return
		}
	}
	writeError(w, http.StatusNotImplemented, "action handler not implemented")
}

// RefreshSearchBotConfig synchronises the runtime search bot logger configuration.
func (s *Server) RefreshSearchBotConfig() {
	if s.SearchBot == nil || s.Extensions == nil {
		return
	}
	cfg, err := s.Extensions.SearchBotConfig()
	if err != nil {
		log.Printf("searchbot: unable to resolve runtime config: %v", err)
		return
	}
	sbCfg := searchbot.Config{
		Enabled:        cfg.Enabled,
		LogDir:         cfg.LogDir,
		LogFile:        cfg.LogFile,
		RangesDir:      cfg.RangesDir,
		GeoFile:        cfg.GeoFile,
		JSONFile:       cfg.JSONFile,
		RangesURL:      cfg.RangesURL,
		FileLimitBytes: cfg.FileLimitBytes,
		CacheTTL:       cfg.CacheTTL,
	}
	for _, bot := range cfg.Bots {
		sbCfg.Bots = append(sbCfg.Bots, searchbot.BotDefinition{
			Key:     bot.Key,
			Label:   bot.Label,
			Icon:    bot.Icon,
			Regex:   bot.Regex,
			Matches: append([]string(nil), bot.Matches...),
		})
	}
	if err := s.SearchBot.UpdateConfig(sbCfg); err != nil {
		log.Printf("searchbot: failed to apply runtime config: %v", err)
	}
	go func() {
		if err := s.SearchBot.RefreshGoogleRanges(context.Background()); err != nil {
			log.Printf("searchbot: refresh google ranges failed: %v", err)
		}
	}()
}

func extensionToDTO(ext extensions.Extension) extensionDTO {
	clone := cloneConfig(ext.State.Config)
	dto := extensionDTO{
		Key:         ext.Definition.Key,
		Name:        ext.Definition.Name,
		Description: ext.Definition.Description,
		Category:    ext.Definition.Category,
		Scope:       ext.Definition.Scope,
		Enabled:     ext.State.Enabled,
		Config:      clone,
		UpdatedBy:   ext.State.UpdatedBy,
	}
	if !ext.State.UpdatedAt.IsZero() {
		dto.UpdatedAt = ext.State.UpdatedAt.UTC().Format(time.RFC3339)
	}
	actions := make([]extensionActionDTO, 0, len(ext.Definition.Actions))
	for _, act := range ext.Definition.Actions {
		actions = append(actions, extensionActionDTO{
			Key:         act.Key,
			Label:       act.Label,
			Description: act.Description,
		})
	}
	if len(actions) > 0 {
		dto.Actions = actions
	}
	return dto
}

func (s *Server) handleDomainSearchBotStats(w http.ResponseWriter, r *http.Request) {
	if s.SearchBot == nil {
		writeError(w, http.StatusNotImplemented, "search bot logging unavailable")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(chi.URLParam(r, "domain")))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	record, err := s.Store.GetDomain(domain)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user := userFromContext(r.Context())
	if !userOwnsDomain(user, *record) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	force := isTruthy(r.URL.Query().Get("refresh"))
	stats, err := s.domainSearchBotStats(r.Context(), *record, force)
	if err != nil {
		if errors.Is(err, searchbot.ErrDisabled) {
			writeError(w, http.StatusNotFound, "search bot logging disabled")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleDomainSearchBotExport(w http.ResponseWriter, r *http.Request) {
	if s.SearchBot == nil {
		writeError(w, http.StatusNotImplemented, "search bot logging unavailable")
		return
	}
	rawDomain := strings.TrimSpace(strings.ToLower(chi.URLParam(r, "domain")))
	if rawDomain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	rawBot := strings.TrimSpace(strings.ToLower(chi.URLParam(r, "bot")))
	if rawBot == "" {
		writeError(w, http.StatusBadRequest, "bot required")
		return
	}
	record, err := s.Store.GetDomain(rawDomain)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user := userFromContext(r.Context())
	if !userOwnsDomain(user, *record) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	nodeID := strings.TrimSpace(record.Edge.AssignedNodeID)
	filename := fmt.Sprintf("%s-%s.log", record.Domain, rawBot)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if nodeID != "" && nodeID != s.Config.NodeID {
		node, err := s.findNodeByID(nodeID)
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("resolve node: %v", err))
			return
		}
		if err := s.proxyRemoteSearchBotExport(r.Context(), w, node, record.Domain, rawBot); err != nil {
			if errors.Is(err, searchbot.ErrDisabled) {
				writeError(w, http.StatusNotFound, "search bot logging disabled on target node")
				return
			}
			writeError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	if _, err := s.SearchBot.ExportLogs(record.Domain, rawBot, w); err != nil {
		if errors.Is(err, searchbot.ErrBotNotFound) {
			writeError(w, http.StatusNotFound, "bot not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (s *Server) handleAdminSearchBotUsage(w http.ResponseWriter, r *http.Request) {
	if s.SearchBot == nil {
		writeJSON(w, http.StatusOK, []searchbot.NodeUsage{})
		return
	}
	cfg := s.SearchBot.Config()
	if !cfg.Enabled {
		writeJSON(w, http.StatusOK, []searchbot.NodeUsage{})
		return
	}
	usages, err := s.collectSearchBotUsage(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, usages)
}

func (s *Server) handleInternalSearchBotUsage(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil || !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	if s.SearchBot == nil {
		writeError(w, http.StatusNotImplemented, "search bot logging unavailable")
		return
	}
	usage, err := s.SearchBot.LocalUsage()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage.NodeID = s.Config.NodeID
	usage.NodeName = s.Config.NodeName
	writeJSON(w, http.StatusOK, usage)
}

func (s *Server) handleInternalSearchBotStats(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil || !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	if s.SearchBot == nil {
		writeError(w, http.StatusNotImplemented, "search bot logging unavailable")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(chi.URLParam(r, "domain")))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	force := isTruthy(r.URL.Query().Get("refresh"))
	stats, err := s.SearchBot.DomainStats(domain, force)
	if err != nil {
		if errors.Is(err, searchbot.ErrDisabled) {
			writeError(w, http.StatusNotFound, "search bot logging disabled")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleInternalSearchBotExport(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil || !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	if s.SearchBot == nil {
		writeError(w, http.StatusNotImplemented, "search bot logging unavailable")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(chi.URLParam(r, "domain")))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain required")
		return
	}
	bot := strings.TrimSpace(strings.ToLower(chi.URLParam(r, "bot")))
	if bot == "" {
		writeError(w, http.StatusBadRequest, "bot required")
		return
	}
	filename := fmt.Sprintf("%s-%s.log", domain, bot)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := s.SearchBot.ExportLogs(domain, bot, w); err != nil {
		if errors.Is(err, searchbot.ErrBotNotFound) {
			writeError(w, http.StatusNotFound, "bot not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func (s *Server) handleInternalSearchBotClear(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil || !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	if s.SearchBot == nil {
		writeError(w, http.StatusNotImplemented, "search bot logging unavailable")
		return
	}
	if err := s.SearchBot.ClearLogs(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (s *Server) domainSearchBotStats(ctx context.Context, record models.DomainRecord, force bool) (searchbot.DomainStats, error) {
	if s.SearchBot == nil {
		return searchbot.DomainStats{}, searchbot.ErrDisabled
	}
	cfg := s.SearchBot.Config()
	if !cfg.Enabled {
		return searchbot.DomainStats{}, searchbot.ErrDisabled
	}
	domain := strings.TrimSpace(record.Domain)
	if domain == "" {
		return searchbot.DomainStats{}, errors.New("domain required")
	}
	nodeID := strings.TrimSpace(record.Edge.AssignedNodeID)
	if nodeID == "" || nodeID == s.Config.NodeID {
		return s.SearchBot.DomainStats(domain, force)
	}
	node, err := s.findNodeByID(nodeID)
	if err != nil {
		return searchbot.DomainStats{}, err
	}
	return s.fetchRemoteDomainStats(ctx, node, domain, force)
}

func (s *Server) searchBotMetrics(ctx context.Context) (map[string]interface{}, error) {
	if s.SearchBot == nil {
		return nil, nil
	}
	cfg := s.SearchBot.Config()
	metrics := map[string]interface{}{
		"enabled": cfg.Enabled,
	}
	if !cfg.Enabled {
		return metrics, nil
	}
	usage, err := s.collectSearchBotUsage(ctx)
	if err != nil {
		return nil, err
	}
	metrics["log_dir"] = cfg.LogDir
	metrics["file_limit_bytes"] = cfg.FileLimitBytes
	metrics["cache_ttl_seconds"] = int64(cfg.CacheTTL / time.Second)
	metrics["nodes"] = usage
	return metrics, nil
}

func (s *Server) collectSearchBotUsage(ctx context.Context) ([]searchbot.NodeUsage, error) {
	localUsage, err := s.SearchBot.LocalUsage()
	if err != nil {
		return nil, err
	}
	localUsage.NodeID = s.Config.NodeID
	localUsage.NodeName = s.Config.NodeName
	usages := []searchbot.NodeUsage{localUsage}
	nodes, err := s.Store.GetNodes()
	if err != nil {
		return usages, err
	}
	for _, node := range nodes {
		if node.ID == "" || node.ID == s.Config.NodeID || node.IsDeleted() {
			continue
		}
		endpoint := strings.TrimSpace(node.APIEndpoint)
		if endpoint == "" {
			continue
		}
		usage, err := s.fetchRemoteSearchBotUsage(ctx, node)
		if err != nil {
			log.Printf("searchbot: fetch usage from node %s failed: %v", node.ID, err)
			continue
		}
		if usage.NodeName == "" {
			usage.NodeName = node.Name
		}
		usages = append(usages, usage)
	}
	sort.SliceStable(usages, func(i, j int) bool {
		if usages[i].NodeName == usages[j].NodeName {
			return usages[i].NodeID < usages[j].NodeID
		}
		return usages[i].NodeName < usages[j].NodeName
	})
	return usages, nil
}

func (s *Server) clearSearchBotLogs(ctx context.Context) error {
	if s.SearchBot == nil {
		return errors.New("search bot logging unavailable")
	}
	if err := s.SearchBot.ClearLogs(); err != nil {
		return err
	}
	nodes, err := s.Store.GetNodes()
	if err != nil {
		return err
	}
	errs := make([]string, 0)
	for _, node := range nodes {
		if node.ID == "" || node.ID == s.Config.NodeID || node.IsDeleted() {
			continue
		}
		endpoint := strings.TrimSpace(node.APIEndpoint)
		if endpoint == "" {
			continue
		}
		if err := s.sendRemoteSearchBotClear(ctx, node); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", node.Name, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) fetchRemoteDomainStats(ctx context.Context, node models.Node, domain string, force bool) (searchbot.DomainStats, error) {
	if s.Sync == nil {
		return searchbot.DomainStats{}, errors.New("sync service unavailable")
	}
	endpoint := strings.TrimSuffix(strings.TrimSpace(node.APIEndpoint), "/")
	if endpoint == "" {
		return searchbot.DomainStats{}, fmt.Errorf("node %s lacks api endpoint", node.ID)
	}
	target := fmt.Sprintf("%s/api/v1/internal/searchbot/domains/%s/stats", endpoint, url.PathEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return searchbot.DomainStats{}, err
	}
	if force {
		q := req.URL.Query()
		q.Set("refresh", "1")
		req.URL.RawQuery = q.Encode()
	}
	req.Header.Set("Authorization", s.Sync.AuthHeader())
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return searchbot.DomainStats{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var stats searchbot.DomainStats
		if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
			return searchbot.DomainStats{}, err
		}
		return stats, nil
	case http.StatusNotFound:
		return searchbot.DomainStats{}, searchbot.ErrDisabled
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return searchbot.DomainStats{}, fmt.Errorf("remote status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

func (s *Server) fetchRemoteSearchBotUsage(ctx context.Context, node models.Node) (searchbot.NodeUsage, error) {
	if s.Sync == nil {
		return searchbot.NodeUsage{}, errors.New("sync service unavailable")
	}
	endpoint := strings.TrimSuffix(strings.TrimSpace(node.APIEndpoint), "/")
	if endpoint == "" {
		return searchbot.NodeUsage{}, fmt.Errorf("node %s lacks api endpoint", node.ID)
	}
	target := fmt.Sprintf("%s/api/v1/internal/searchbot/usage", endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return searchbot.NodeUsage{}, err
	}
	req.Header.Set("Authorization", s.Sync.AuthHeader())
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return searchbot.NodeUsage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return searchbot.NodeUsage{}, fmt.Errorf("remote status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var usage searchbot.NodeUsage
	if err := json.NewDecoder(resp.Body).Decode(&usage); err != nil {
		return searchbot.NodeUsage{}, err
	}
	if usage.NodeID == "" {
		usage.NodeID = node.ID
	}
	if usage.NodeName == "" {
		usage.NodeName = node.Name
	}
	return usage, nil
}

func (s *Server) proxyRemoteSearchBotExport(ctx context.Context, w http.ResponseWriter, node models.Node, domain, bot string) error {
	if s.Sync == nil {
		return errors.New("sync service unavailable")
	}
	endpoint := strings.TrimSuffix(strings.TrimSpace(node.APIEndpoint), "/")
	if endpoint == "" {
		return fmt.Errorf("node %s lacks api endpoint", node.ID)
	}
	target := fmt.Sprintf("%s/api/v1/internal/searchbot/domains/%s/logs/%s", endpoint, url.PathEscape(domain), url.PathEscape(bot))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", s.Sync.AuthHeader())
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return searchbot.ErrDisabled
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("remote status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func (s *Server) sendRemoteSearchBotClear(ctx context.Context, node models.Node) error {
	if s.Sync == nil {
		return errors.New("sync service unavailable")
	}
	endpoint := strings.TrimSuffix(strings.TrimSpace(node.APIEndpoint), "/")
	if endpoint == "" {
		return fmt.Errorf("node %s lacks api endpoint", node.ID)
	}
	target := fmt.Sprintf("%s/api/v1/internal/searchbot/logs/clear", endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", s.Sync.AuthHeader())
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("remote status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *Server) findNodeByID(id string) (models.Node, error) {
	nodes, err := s.Store.GetNodes()
	if err != nil {
		return models.Node{}, err
	}
	for _, node := range nodes {
		if node.ID == id {
			return node, nil
		}
	}
	return models.Node{}, store.ErrNotFound
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func cloneConfig(src map[string]interface{}) map[string]interface{} {
	if len(src) == 0 {
		return nil
	}
	dup := make(map[string]interface{}, len(src))
	for k, v := range src {
		dup[k] = v
	}
	return dup
}

func (s *Server) handleReassignDomainEdge(w http.ResponseWriter, r *http.Request) {
	// Use mutex to prevent concurrent edge reassignments
	s.edgeReconcileMu.Lock()
	defer s.edgeReconcileMu.Unlock()

	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !existing.Proxied {
		writeError(w, http.StatusBadRequest, "domain is not proxied")
		return
	}

	endpoints, err := s.Infra.EdgeEndpoints()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	health, err := s.Store.GetEdgeHealthMap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	eligible := infra.FilterEdgeEndpointsByLabels(endpoints, existing.Edge.Labels)
	if len(eligible) == 0 {
		writeError(w, http.StatusBadRequest, "no edge nodes match the requested labels")
		return
	}
	candidates := infra.PreferHealthyEndpoints(eligible, health)
	if len(candidates) == 0 {
		candidates = eligible
	}
	if len(candidates) < 2 {
		writeError(w, http.StatusBadRequest, "no alternate edge available")
		return
	}

	baseSalt := computeDomainSalt(existing.Domain)
	key := fmt.Sprintf("%s|%s", existing.Domain, baseSalt)
	ordered := infra.RendezvousOrder(key, candidates)
	currentIP := existing.Edge.AssignedIP
	currentIndex := -1
	for i, ep := range ordered {
		if ep.IP == currentIP {
			currentIndex = i
			break
		}
	}

	selectNext := func(start int) (infra.EdgeEndpoint, bool) {
		for i := 0; i < len(ordered); i++ {
			candidate := ordered[(start+i)%len(ordered)]
			if candidate.IP != currentIP {
				return candidate, true
			}
		}
		return infra.EdgeEndpoint{}, false
	}

	var target infra.EdgeEndpoint
	var ok bool
	if currentIndex == -1 {
		target, ok = selectNext(0)
	} else {
		target, ok = selectNext(currentIndex + 1)
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "no alternate edge available")
		return
	}

	now := time.Now().UTC()
	existing.Edge.AssignmentSalt = fmt.Sprintf("pin:%s:%s", baseSalt, target.IP)
	existing.Edge.AssignedIP = target.IP
	existing.Edge.AssignedNodeID = target.NodeID
	existing.Edge.AssignedAt = now
	existing.Edge.Normalize()

	existing.UpdatedAt = now
	existing.Version.Counter++
	existing.Version.NodeID = s.Config.NodeID
	existing.Version.Updated = now.Unix()
	if err := s.Store.UpsertDomain(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, existing.Sanitize())
}

func (s *Server) handleReassignAllDomainEdges(w http.ResponseWriter, r *http.Request) {
	// Prevent overlapping global reassign operations
	s.edgeReconcileMu.Lock()
	defer s.edgeReconcileMu.Unlock()

	domains, err := s.Store.GetDomains()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type summary struct {
		Reassigned int      `json:"reassigned"`
		Unchanged  int      `json:"unchanged"`
		Skipped    int      `json:"skipped"`
		Failed     int      `json:"failed"`
		Errors     []string `json:"errors,omitempty"`
	}
	result := summary{}

	for _, rec := range domains {
		if !rec.Proxied {
			result.Skipped++
			continue
		}

		prevIP := rec.Edge.AssignedIP
		prevNode := rec.Edge.AssignedNodeID

		baseSalt := computeDomainSalt(rec.Domain)
		if rec.Edge.AssignmentSalt != baseSalt {
			rec.Edge.AssignmentSalt = baseSalt
		}
		rec.Edge.AssignedIP = ""
		rec.Edge.AssignedNodeID = ""
		rec.Edge.AssignedAt = time.Time{}
		rec.Edge.Normalize()

		mutated, err := s.ensureDomainEdgeAssignment(&rec)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", rec.Domain, err))
			continue
		}

		changed := rec.Edge.AssignedIP != prevIP || rec.Edge.AssignedNodeID != prevNode
		if !changed && !mutated {
			result.Unchanged++
			continue
		}

		now := time.Now().UTC()
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		if err := s.Store.UpsertDomain(rec); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", rec.Domain, err))
			continue
		}
		result.Reassigned++
	}

	if result.Reassigned > 0 {
		s.triggerSyncBroadcast()
		go s.Orchestrator.Trigger(r.Context())
	}

	writeJSON(w, http.StatusOK, result)
}

func computeDomainSalt(domain string) string {
	domainKey := strings.ToLower(strings.TrimSpace(domain))
	hasher := sha256.Sum256([]byte(domainKey))
	return hex.EncodeToString(hasher[:8])
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	s.attachOwnerMetadata(existing)
	if !userOwnsDomain(user, *existing) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if existing.Role == models.DomainRolePrimary {
		dependents, err := s.findDomainDependents(existing.Domain)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(dependents) > 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("domain has linked alias/redirect: %s", strings.Join(dependents, ", ")))
			return
		}
	}
	prevParents := s.resolveDomainParents(*existing)
	if err := s.Store.MarkDomainDeleted(domain, s.Config.NodeID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.invalidateDomainFamilyCache(*existing, prevParents); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleInfraNS(w http.ResponseWriter, r *http.Request) {
	ns, err := s.Infra.ActiveNameServers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ns)
}

func (s *Server) handleInfraEdges(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.Infra.EdgeEndpoints()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, endpoints)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.GetUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range users {
		users[i] = users[i].Sanitize()
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Email == "" || payload.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}
	role := models.UserRole(payload.Role)
	if role != models.RoleAdmin && role != models.RoleUser {
		role = models.RoleUser
	}
	hash, err := auth.HashPassword(payload.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	user := models.User{
		ID:    uuid.NewString(),
		Email: strings.ToLower(payload.Email),
		Role:  role,
	}
	user.Password = hash
	if err := s.Store.UpsertUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	writeJSON(w, http.StatusCreated, user.Sanitize())
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.Store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	var payload struct {
		Password *string `json:"password"`
		Role     *string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Password != nil && *payload.Password != "" {
		hash, err := auth.HashPassword(*payload.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		existing.Password = hash
	}
	if payload.Role != nil {
		role := models.UserRole(*payload.Role)
		if role == models.RoleAdmin || role == models.RoleUser {
			existing.Role = role
		}
	}
	if err := s.Store.UpsertUser(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	writeJSON(w, http.StatusOK, existing.Sanitize())
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := s.Store.GetUserByID(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing.Role == models.RoleAdmin {
		users, err := s.Store.GetUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		adminCount := 0
		for _, u := range users {
			if u.Role == models.RoleAdmin && u.ID != id {
				adminCount++
			}
		}
		if adminCount == 0 {
			writeError(w, http.StatusBadRequest, "cannot delete the last admin user")
			return
		}
	}
	if err := s.Store.DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.triggerSyncBroadcast()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Store.GetNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	annotated := s.decorateNodesWithStatus(nodes)
	writeJSON(w, http.StatusOK, annotated)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var node models.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if node.ID == "" {
		// Generate new UUID for new nodes
		// Nodes should provide their persistent ID from /data/cluster/node_id
		node.ID = uuid.NewString()
	}
	node.Name = strings.TrimSpace(node.Name)
	node.NSLabel = s.Config.NSLabel     // Always use config value
	node.NSBase = s.Config.NSBaseDomain // Always use config value
	node.APIEndpoint = strings.TrimSpace(node.APIEndpoint)
	node.IPs = filterEmpty(node.IPs)
	node.NSIPs = filterEmpty(node.NSIPs)
	node.EdgeIPs = filterEmpty(node.EdgeIPs)
	node.Labels = filterEmpty(node.Labels)
	node.ComputeEdgeIPs()
	now := time.Now().UTC()
	node.Version.Counter++
	node.Version.NodeID = s.Config.NodeID
	node.Version.Updated = now.Unix()
	if err := s.Store.UpsertNode(node); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := s.ensureControlPlaneDomain(node); err != nil {
		log.Printf("control-plane: ensure domain for %s failed: %v", node.Name, err)
	}
	s.triggerSyncBroadcast()
	if node.ID == s.Config.NodeID {
		if err := s.Store.SaveLocalNodeSnapshot(node); err != nil {
			log.Printf("sync local node snapshot: %v", err)
		}
	}
	s.bootstrapEdgeHealth(node)
	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("sync peers after create node: %v", err)
	}
	go s.reconcileDomainAssignments(context.Background(), fmt.Sprintf("node-create:%s", node.ID))
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusCreated, s.decorateNodeStatus(node))
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existingNodes, err := s.Store.GetNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var existing *models.Node
	for _, n := range existingNodes {
		if n.ID == id {
			n2 := n
			existing = &n2
			break
		}
	}
	if existing == nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	var payload struct {
		Name        *string   `json:"name"`
		IPs         *[]string `json:"ips"`
		NSIPs       *[]string `json:"ns_ips"`
		EdgeIPs     *[]string `json:"edge_ips"`
		APIEndpoint *string   `json:"api_endpoint"`
		Labels      *[]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	oldName := existing.Name
	if payload.Name != nil {
		existing.Name = strings.TrimSpace(*payload.Name)

		// If name changed, NODE_ID will change too (it's deterministic based on name)
		if oldName != existing.Name {
			// Calculate new NODE_ID
			clusterSecretBytes, err := os.ReadFile(s.Config.ClusterSecretFile)
			if err == nil {
				clusterSecret := strings.TrimSpace(string(clusterSecretBytes))
				data := fmt.Sprintf("%s:%s", clusterSecret, strings.ToLower(existing.Name))
				hash := sha256.Sum256([]byte(data))
				hashStr := hex.EncodeToString(hash[:])

				newID := fmt.Sprintf("%s-%s-%s-%s-%s",
					hashStr[0:8],
					hashStr[8:12],
					hashStr[12:16],
					hashStr[16:20],
					hashStr[20:32],
				)

				// Mark old node as deleted
				now := time.Now().UTC()
				if err := s.Store.MarkNodeDeleted(existing.ID, s.Config.NodeID, now); err != nil {
					writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to remove old node: %v", err))
					return
				}

				// Update to new ID
				existing.ID = newID
			}
		}
	}
	if payload.IPs != nil {
		existing.IPs = filterEmpty(*payload.IPs)
	}
	if payload.NSIPs != nil {
		existing.NSIPs = filterEmpty(*payload.NSIPs)
	}
	if payload.EdgeIPs != nil {
		existing.EdgeIPs = filterEmpty(*payload.EdgeIPs)
	}
	// NS configuration always comes from config
	existing.NSLabel = s.Config.NSLabel
	existing.NSBase = s.Config.NSBaseDomain
	if payload.APIEndpoint != nil {
		existing.APIEndpoint = strings.TrimSpace(*payload.APIEndpoint)
	}
	if payload.Labels != nil {
		existing.Labels = filterEmpty(*payload.Labels)
	}
	existing.ComputeEdgeIPs()
	now := time.Now().UTC()
	renamed := oldName != existing.Name
	existing.Version.Counter++
	existing.Version.NodeID = s.Config.NodeID
	existing.Version.Updated = now.Unix()
	if err := s.Store.UpsertNode(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if renamed && strings.TrimSpace(oldName) != "" {
		if err := s.deleteControlPlaneDomain(oldName); err != nil {
			log.Printf("control-plane: delete domain for %s failed: %v", oldName, err)
		}
	}
	if _, err := s.ensureControlPlaneDomain(*existing); err != nil {
		log.Printf("control-plane: ensure domain for %s failed: %v", existing.Name, err)
	}
	s.triggerSyncBroadcast()
	// Save local node snapshot if this is our node
	if existing.ID == s.Config.NodeID {
		if err := s.Store.SaveLocalNodeSnapshot(*existing); err != nil {
			log.Printf("sync local node snapshot: %v", err)
		}
	}
	s.bootstrapEdgeHealth(*existing)
	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("sync peers after update node: %v", err)
	}
	go s.reconcileDomainAssignments(context.Background(), fmt.Sprintf("node-update:%s", existing.ID))
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, s.decorateNodeStatus(*existing))
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "node id required")
		return
	}
	nodes, err := s.Store.GetNodesIncludingDeleted()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var (
		target    *models.Node
		softMatch *models.Node
	)
	for _, node := range nodes {
		if node.ID != id {
			continue
		}
		n2 := node
		softMatch = &n2
		if node.IsDeleted() {
			break
		}
		target = &n2
		s.cleanupEdgeHealth(node)
		break
	}
	if target == nil {
		if softMatch == nil {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		// Node already deleted; ensure tombstone exists for consistency.
		target = softMatch
	}
	now := time.Now().UTC()
	if err := s.Store.MarkNodeDeleted(id, s.Config.NodeID, now); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if target != nil && strings.TrimSpace(target.Name) != "" {
		if err := s.deleteControlPlaneDomain(target.Name); err != nil {
			log.Printf("control-plane: delete domain for %s failed: %v", target.Name, err)
		}
	}
	s.triggerSyncBroadcast()
	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("sync peers after delete node: %v", err)
	}
	go s.reconcileDomainAssignments(context.Background(), fmt.Sprintf("node-delete:%s", id))
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleDomainsOverview(w http.ResponseWriter, r *http.Request) {
	domains, err := s.Store.GetDomains()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	users, err := s.Store.GetUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userMap := make(map[string]models.User, len(users))
	for _, user := range users {
		userMap[user.ID] = user
	}
	nsList, nsErr := s.Infra.ActiveNameServers()
	if nsErr != nil {
		log.Printf("domains overview: load nameservers failed: %v", nsErr)
		nsList = nil
	}
	defaultEntries := prepareDefaultNameServers(nsList)
	overview := make([]domainOverview, 0, len(domains))
	for _, domain := range domains {
		if domain.IsSystemManaged() {
			continue
		}
		entry := domainOverview{
			Domain:       domain.Domain,
			OwnerID:      domain.Owner,
			OwnerExists:  false,
			OriginIP:     domain.OriginIP,
			Proxied:      domain.Proxied,
			TTL:          domain.TTL,
			CacheVersion: domain.CacheVersion,
			UpdatedAt:    domain.UpdatedAt,
			Role:         domain.Role,
			TLSMode:      domain.TLS.Mode,
			TLSStatus:    domain.TLS.Status,
			TLSUseRec:    domain.TLS.UseRecommended,
			TLSRecMode:   domain.TLS.RecommendedMode,
			TLSError:     domain.TLS.LastError,
		}
		if domain.Alias != nil {
			aliasCopy := *domain.Alias
			entry.Alias = &aliasCopy
		}
		if len(domain.RedirectRules) > 0 {
			entry.RedirectRules = append([]models.DomainRedirectRule{}, domain.RedirectRules...)
		}
		if domain.OwnerEmail != "" {
			entry.OwnerEmail = strings.ToLower(domain.OwnerEmail)
		} else if strings.Contains(domain.Owner, "@") {
			entry.OwnerEmail = strings.ToLower(domain.Owner)
		}
		if domain.TLS.Certificate != nil && !domain.TLS.Certificate.NotAfter.IsZero() {
			expires := domain.TLS.Certificate.NotAfter.UTC()
			entry.TLSExpires = &expires
		}
		if !domain.TLS.RetryAfter.IsZero() {
			retry := domain.TLS.RetryAfter.UTC()
			entry.TLSRetryAt = &retry
		}
		if domain.Edge.AssignedIP != "" {
			entry.EdgeIP = domain.Edge.AssignedIP
		}
		if domain.Edge.AssignedNodeID != "" {
			entry.EdgeNodeID = domain.Edge.AssignedNodeID
		}
		if len(domain.Edge.Labels) > 0 {
			entry.EdgeLabels = append([]string{}, domain.Edge.Labels...)
		}
		if !domain.Edge.AssignedAt.IsZero() {
			assigned := domain.Edge.AssignedAt.UTC()
			entry.EdgeUpdated = &assigned
		}
		if user, ok := userMap[domain.Owner]; ok {
			entry.OwnerExists = true
			entry.OwnerEmail = strings.ToLower(user.Email)
		} else if entry.OwnerEmail != "" {
			for _, user := range users {
				if strings.EqualFold(user.Email, entry.OwnerEmail) {
					entry.OwnerExists = true
					break
				}
			}
		}
		if nsSet, _ := s.composeNameserverSet(domain.Domain, nsList, defaultEntries); len(nsSet.Default) > 0 || len(nsSet.Anycast) > 0 || len(nsSet.Vanity) > 0 {
			nsCopy := nsSet
			entry.Nameservers = &nsCopy
		}
		if !domain.Whois.IsZero() {
			copy := domain.Whois
			copy.Normalize()
			entry.Whois = &copy
		}
		entry.WAF = domain.WAF
		if len(domain.DNSRecords) > 0 {
			entry.DNSRecords = append(make([]models.DomainDNSRecord, 0, len(domain.DNSRecords)), domain.DNSRecords...)
		}
		overview = append(overview, entry)
	}
	sort.Slice(overview, func(i, j int) bool {
		if overview[i].OwnerEmail != overview[j].OwnerEmail {
			return overview[i].OwnerEmail < overview[j].OwnerEmail
		}
		if overview[i].OwnerID != overview[j].OwnerID {
			return overview[i].OwnerID < overview[j].OwnerID
		}
		return overview[i].Domain < overview[j].Domain
	})
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	if err := s.Orchestrator.FlushSync(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func (s *Server) handleSyncDigest(w http.ResponseWriter, r *http.Request) {
	if !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	digest, err := s.Sync.ComputeDigest()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, digest)
}

func (s *Server) handleSyncPull(w http.ResponseWriter, r *http.Request) {
	if !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	snapshot, err := s.Sync.BuildSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleSyncPush(w http.ResponseWriter, r *http.Request) {
	if !s.Sync.ValidatePeerRequest(r) {
		writeError(w, http.StatusUnauthorized, "invalid peer secret")
		return
	}
	var snapshot syncsvc.Snapshot
	if err := json.NewDecoder(r.Body).Decode(&snapshot); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := s.Sync.ApplySnapshot(snapshot); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

func computeRateLimits(perMinute, burst int) (int, int) {
	if perMinute <= 0 {
		return 0, 0
	}
	rps := perMinute / 60
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = rps * 2
	}
	if burst < rps {
		burst = rps
	}
	return rps, burst
}

func buildAttemptDescriptors(email string, hashedIP string) []loginAttemptDescriptor {
	descriptors := make([]loginAttemptDescriptor, 0, 2)
	seen := make(map[string]struct{}, 2)
	if email != "" {
		key := loginAttemptKey(loginScopeEmail, email)
		seen[key] = struct{}{}
		descriptors = append(descriptors, loginAttemptDescriptor{Scope: loginScopeEmail, Key: key})
	}
	if hashedIP != "" {
		key := loginAttemptKey(loginScopeIP, hashedIP)
		if _, ok := seen[key]; !ok {
			descriptors = append(descriptors, loginAttemptDescriptor{Scope: loginScopeIP, Key: key})
		}
	}
	return descriptors
}

func loginAttemptKey(scope, value string) string {
	return scope + ":" + value
}

func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			candidate := strings.TrimSpace(part)
			if candidate != "" {
				return candidate
			}
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil && host != "" {
		return host
	}
	return remote
}

func (s *Server) hashIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || len(s.Config.ClusterSecret) == 0 {
		return ""
	}
	normalized := strings.ToLower(ip)
	seed := append(append([]byte{}, s.Config.ClusterSecret...), ':')
	seed = append(seed, normalized...)
	sum := sha256.Sum256(seed)
	return hex.EncodeToString(sum[:])
}

func (s *Server) loginAttemptsLocked(attempts []loginAttemptDescriptor, now time.Time) (bool, time.Time, string) {
	if len(attempts) == 0 {
		return false, time.Time{}, ""
	}
	cutoff := time.Time{}
	if s.Config.LoginFailureReset > 0 {
		cutoff = now.Add(-s.Config.LoginFailureReset)
	}
	locked := false
	var lockUntil time.Time
	var scope string
	for _, attempt := range attempts {
		if attempt.Key == "" {
			continue
		}
		record, ok, err := s.Store.GetLoginAttempt(attempt.Key)
		if err != nil {
			log.Printf("auth: load login attempt for %s failed: %v", attempt.Key, err)
			continue
		}
		if !ok {
			continue
		}
		if !cutoff.IsZero() && !record.LastFailure.IsZero() && record.LastFailure.Before(cutoff) && record.LockedUntil.Before(now) {
			if err := s.Store.ResetLoginAttempts(attempt.Key); err != nil {
				log.Printf("auth: cleanup login attempt for %s failed: %v", attempt.Key, err)
			}
			continue
		}
		if record.LockedUntil.After(now) {
			locked = true
			if record.LockedUntil.After(lockUntil) {
				lockUntil = record.LockedUntil
				scope = record.Scope
			}
		}
	}
	return locked, lockUntil, scope
}

func (s *Server) recordLoginFailure(attempts []loginAttemptDescriptor, now time.Time) {
	if len(attempts) == 0 {
		return
	}
	if err := s.Store.ModifyLoginAttempts(func(records map[string]models.LoginAttempt) (bool, error) {
		changed := false
		seen := make(map[string]struct{}, len(attempts))
		cutoff := time.Time{}
		if s.Config.LoginFailureReset > 0 {
			cutoff = now.Add(-s.Config.LoginFailureReset)
		}
		for _, attempt := range attempts {
			if attempt.Key == "" {
				continue
			}
			if _, ok := seen[attempt.Key]; ok {
				continue
			}
			seen[attempt.Key] = struct{}{}
			record := records[attempt.Key]
			record.Key = attempt.Key
			if attempt.Scope != "" {
				record.Scope = attempt.Scope
			}
			if !cutoff.IsZero() && !record.LastFailure.IsZero() && record.LastFailure.Before(cutoff) && record.LockedUntil.Before(now) {
				record.Failures = 0
				record.LockedUntil = time.Time{}
			}
			record.Failures++
			record.LastFailure = now
			lockUntil := s.lockoutUntil(record.Failures, now)
			if lockUntil.After(record.LockedUntil) {
				record.LockedUntil = lockUntil
			}
			records[attempt.Key] = record
			changed = true
		}
		if !cutoff.IsZero() {
			nowLocal := now
			for key, record := range records {
				if record.LockedUntil.After(nowLocal) {
					continue
				}
				if record.Failures <= 0 && (record.LastFailure.IsZero() || record.LastFailure.Before(cutoff)) {
					delete(records, key)
					changed = true
				}
			}
		}
		return changed, nil
	}); err != nil {
		log.Printf("auth: update login attempts failed: %v", err)
	}
}

func (s *Server) resetLoginAttempts(attempts []loginAttemptDescriptor) {
	if len(attempts) == 0 {
		return
	}
	keys := make([]string, 0, len(attempts))
	seen := make(map[string]struct{}, len(attempts))
	for _, attempt := range attempts {
		if attempt.Key == "" {
			continue
		}
		if _, ok := seen[attempt.Key]; ok {
			continue
		}
		seen[attempt.Key] = struct{}{}
		keys = append(keys, attempt.Key)
	}
	if len(keys) == 0 {
		return
	}
	if err := s.Store.ResetLoginAttempts(keys...); err != nil {
		log.Printf("auth: reset login attempts failed: %v", err)
	}
}

func (s *Server) lockoutUntil(failures int, now time.Time) time.Time {
	if failures <= 0 {
		return time.Time{}
	}
	var lockUntil time.Time
	for _, tier := range s.Config.LoginLockTiers {
		if tier.Failures <= 0 || tier.LockDuration <= 0 {
			continue
		}
		if failures < tier.Failures {
			break
		}
		candidate := now.Add(tier.LockDuration)
		if candidate.After(lockUntil) {
			lockUntil = candidate
		}
	}
	return lockUntil
}

func limitBodySize(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if limit <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func skipRateLimitedPaths(r *http.Request) bool {
	path := r.URL.Path
	switch {
	case path == "/healthz", path == "/readyz":
		return true
	case strings.HasPrefix(path, "/.well-known/acme-challenge/"):
		return true
	case strings.HasPrefix(path, "/api/v1/sync/"):
		return true
	default:
		return false
	}
}

type userContextKey struct{}

type userContext struct {
	ID    string
	Email string
	Role  models.UserRole
}

func withUserContext(ctx context.Context, id string, email string, role models.UserRole) context.Context {
	return context.WithValue(ctx, userContextKey{}, userContext{ID: id, Email: email, Role: role})
}

func userFromContext(ctx context.Context) userContext {
	val := ctx.Value(userContextKey{})
	if val == nil {
		return userContext{}
	}
	if u, ok := val.(userContext); ok {
		return u
	}
	return userContext{}
}

// EnsurePeers recomputes the peer list based on current node metadata.
func (s *Server) EnsurePeers() error {
	return s.syncPeersFromNodes()
}

// SyncLocalNodeCapabilities reconciles the local node record with runtime feature flags.
func (s *Server) SyncLocalNodeCapabilities(ctx context.Context) bool {
	nodes, err := s.Store.GetNodesIncludingDeleted()
	if err != nil {
		log.Printf("infra: load nodes for capability sync failed: %v", err)
		return false
	}
	var local *models.Node
	for _, node := range nodes {
		if node.ID == s.Config.NodeID {
			n := node
			local = &n
			break
		}
	}
	if local == nil {
		return false
	}
	original := cloneNode(*local)
	desired := cloneNode(*local)
	changed := false

	if desired.Version.NodeID != s.Config.NodeID || desired.Version.Counter <= 0 {
		changed = true
	}

	desired.Roles = nil
	desired.ComputeEdgeIPs()

	if !changed {
		s.pruneUnusedEdgeHealth()
		s.TriggerDomainReconcile(fmt.Sprintf("node-capabilities:%s", desired.ID))
		return true
	}

	removed := diffStrings(original.EdgeIPs, desired.EdgeIPs)
	now := time.Now().UTC()
	desired.Version.Counter++
	if desired.Version.Counter <= 0 {
		desired.Version.Counter = 1
	}
	desired.Version.NodeID = s.Config.NodeID
	desired.Version.Updated = now.Unix()
	desired.UpdatedAt = now

	if err := s.Store.UpsertNode(desired); err != nil {
		log.Printf("infra: update local node capabilities failed: %v", err)
		return true
	}
	if _, err := s.ensureControlPlaneDomain(desired); err != nil {
		log.Printf("control-plane: ensure domain for %s failed: %v", desired.Name, err)
	}
	s.triggerSyncBroadcast()

	if err := s.Store.SaveLocalNodeSnapshot(desired); err != nil {
		log.Printf("infra: update local node snapshot failed: %v", err)
	}

	if len(removed) > 0 {
		s.cleanupEdgeHealth(models.Node{EdgeIPs: removed})
	}
	if len(desired.EdgeIPs) > 0 {
		s.bootstrapEdgeHealth(desired)
	}
	s.pruneUnusedEdgeHealth()

	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("infra: sync peers after capability change failed: %v", err)
	}
	s.TriggerDomainReconcileWithContext(ctx, fmt.Sprintf("node-capabilities:%s", desired.ID))
	go s.Orchestrator.Trigger(context.Background())
	return true
}

func (s *Server) pruneUnusedEdgeHealth() {
	endpoints, err := s.Infra.EdgeEndpoints()
	if err != nil {
		log.Printf("infra: edge endpoint enumeration failed: %v", err)
		return
	}
	active := make(map[string]struct{}, len(endpoints))
	for _, ep := range endpoints {
		ip := strings.TrimSpace(ep.IP)
		if ip == "" {
			continue
		}
		active[ip] = struct{}{}
	}
	statuses, err := s.Store.GetEdgeHealth()
	if err != nil {
		log.Printf("infra: fetch edge health for pruning failed: %v", err)
		return
	}
	for _, st := range statuses {
		if _, ok := active[st.IP]; ok {
			continue
		}
		if err := s.Store.DeleteEdgeHealth(st.IP); err != nil {
			log.Printf("infra: prune edge health %s failed: %v", st.IP, err)
		}
	}
}

func (s *Server) syncPeersFromNodes() error {
	nodes, err := s.Store.GetNodes()
	if err != nil {
		return err
	}
	unique := make(map[string]struct{}, len(nodes))
	peers := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node.ID == s.Config.NodeID {
			continue
		}
		endpoint := strings.TrimSpace(node.APIEndpoint)
		if endpoint == "" {
			continue
		}
		if _, ok := unique[endpoint]; ok {
			continue
		}
		unique[endpoint] = struct{}{}
		peers = append(peers, endpoint)
	}
	sort.Strings(peers)
	return s.Store.SavePeers(peers)
}

func filterEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func cloneNode(n models.Node) models.Node {
	clone := n
	clone.IPs = append([]string{}, n.IPs...)
	clone.NSIPs = append([]string{}, n.NSIPs...)
	clone.EdgeIPs = append([]string{}, n.EdgeIPs...)
	clone.Roles = append([]models.NodeRole{}, n.Roles...)
	clone.Labels = append([]string{}, n.Labels...)
	clone.ManagedNS = append([]string{}, n.ManagedNS...)
	return clone
}

func diffStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	out := make([]string, 0)
	for _, v := range a {
		if _, ok := set[v]; ok {
			continue
		}
		out = append(out, v)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) triggerSyncBroadcast() {
	if s == nil || s.Sync == nil {
		return
	}
	s.Sync.TriggerBroadcast()
}

func (s *Server) controlPlaneDomainForName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	label := strings.TrimSpace(s.Config.NSLabel)
	if label == "" {
		label = "dns"
	}
	base := strings.TrimSpace(s.Config.NSBaseDomain)
	if base == "" {
		base = "aki.cloud"
	}
	return fmt.Sprintf("%s.%s.%s", strings.ToLower(name), strings.ToLower(label), strings.ToLower(base))
}

func (s *Server) ensureControlPlaneDomain(node models.Node) (bool, error) {
	domain := s.controlPlaneDomainForName(node.Name)
	if domain == "" {
		return false, nil
	}
	targetIP := ""
	for _, ip := range append([]string{}, node.EdgeIPs...) {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			targetIP = ip
			break
		}
	}
	if targetIP == "" {
		for _, ip := range node.IPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				targetIP = ip
				break
			}
		}
	}
	if targetIP == "" {
		return false, nil
	}

	now := time.Now().UTC()
	pinnedSalt := fmt.Sprintf("pin:%s:%s", infra.ComputeDefaultSalt(domain), targetIP)
	changed := false

	_, err := s.Store.MutateDomain(domain, func(rec *models.DomainRecord) error {
		if rec.IsDeleted() {
			return fs.ErrNotExist
		}
		rec.EnsureTLSDefaults()
		rec.EnsureCacheVersion()
		if !rec.IsSystemManaged() || rec.Owner != models.SystemOwnerID {
			rec.Owner = models.SystemOwnerID
			rec.OwnerEmail = ""
			changed = true
		}
		if !rec.Proxied {
			rec.Proxied = true
			changed = true
		}
		if rec.Role != models.DomainRolePrimary {
			rec.Role = models.DomainRolePrimary
			changed = true
		}
		if rec.OriginIP != "" {
			rec.OriginIP = ""
			changed = true
		}
		rec.Alias = nil
		rec.RedirectRules = nil
		if rec.Edge.AssignmentSalt != pinnedSalt {
			rec.Edge.AssignmentSalt = pinnedSalt
			changed = true
		}
		if rec.Edge.AssignedIP != targetIP {
			rec.Edge.AssignedIP = targetIP
			changed = true
		}
		if rec.Edge.AssignedNodeID != node.ID {
			rec.Edge.AssignedNodeID = node.ID
			changed = true
		}
		if rec.Edge.AssignedAt.IsZero() {
			rec.Edge.AssignedAt = now
		}
		if rec.TLS.Mode != models.EncryptionFlexible {
			rec.TLS.Mode = models.EncryptionFlexible
			changed = true
		}
		if !rec.TLS.UseRecommended {
			rec.TLS.UseRecommended = true
			changed = true
		}
		if changed {
			rec.TLS.Status = models.CertificateStatusNone
			rec.TLS.RecommendedMode = ""
			rec.TLS.RecommendedAt = time.Time{}
			rec.UpdatedAt = now
			rec.Version.Counter++
			if rec.Version.Counter <= 0 {
				rec.Version.Counter = 1
			}
			rec.Version.NodeID = s.Config.NodeID
			rec.Version.Updated = now.Unix()
			rec.CacheVersion++
			if rec.CacheVersion <= 0 {
				rec.CacheVersion = 1
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			record := models.DomainRecord{
				Domain:       domain,
				Owner:        models.SystemOwnerID,
				OwnerEmail:   "",
				TTL:          60,
				Proxied:      true,
				CacheVersion: 1,
				UpdatedAt:    now,
				Version: models.ClockVersion{
					Counter: 1,
					NodeID:  s.Config.NodeID,
					Updated: now.Unix(),
				},
			}
			record.Edge.AssignmentSalt = pinnedSalt
			record.Edge.AssignedIP = targetIP
			record.Edge.AssignedNodeID = node.ID
			record.Edge.AssignedAt = now
			record.Role = models.DomainRolePrimary
			record.TLS.Mode = models.EncryptionFlexible
			record.TLS.UseRecommended = true
			record.TLS.Status = models.CertificateStatusNone
			record.EnsureTLSDefaults()
			record.EnsureCacheVersion()
			if err := s.Store.UpsertDomain(record); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, err
	}
	return changed, nil
}

func (s *Server) deleteControlPlaneDomain(nodeName string) error {
	domain := s.controlPlaneDomainForName(nodeName)
	if domain == "" {
		return nil
	}
	return s.Store.MarkDomainDeleted(domain, s.Config.NodeID, time.Now().UTC())
}

func (s *Server) EnsureControlPlaneDomains() {
	nodes, err := s.Store.GetNodes()
	if err != nil {
		log.Printf("control-plane: load nodes for domain ensure failed: %v", err)
		return
	}
	changed := false
	for _, node := range nodes {
		if node.IsDeleted() {
			continue
		}
		ok, err := s.ensureControlPlaneDomain(node)
		if err != nil {
			log.Printf("control-plane: ensure domain for %s failed: %v", node.Name, err)
			continue
		}
		if ok {
			changed = true
		}
	}
	if changed {
		s.triggerSyncBroadcast()
		go s.Orchestrator.Trigger(context.Background())
	}
}

func (s *Server) reconcileDomainAssignments(ctx context.Context, reason string) {
	s.edgeReconcileMu.Lock()
	defer s.edgeReconcileMu.Unlock()
	domains, err := s.Store.GetDomains()
	if err != nil {
		log.Printf("edge assignment reconcile (%s): %v", reason, err)
		return
	}
	updated := false
	for _, domain := range domains {
		if !domain.Proxied {
			continue
		}
		rec := domain
		mutated, err := s.ensureDomainEdgeAssignment(&rec)
		if err != nil {
			if _, ok := err.(models.ErrValidation); ok {
				log.Printf("edge assignment reconcile (%s): %s -> %v", reason, rec.Domain, err)
				continue
			}
			log.Printf("edge assignment reconcile (%s): %s -> %v", reason, rec.Domain, err)
			continue
		}
		if !mutated {
			continue
		}
		now := time.Now().UTC()
		rec.UpdatedAt = now
		rec.Version.Counter++
		rec.Version.NodeID = s.Config.NodeID
		rec.Version.Updated = now.Unix()
		if err := s.Store.UpsertDomain(rec); err != nil {
			log.Printf("edge assignment reconcile (%s): persist %s -> %v", reason, rec.Domain, err)
			continue
		}
		updated = true
	}
	if updated {
		s.triggerSyncBroadcast()
		go s.Orchestrator.Trigger(ctx)
	}
}

// TriggerDomainReconcile schedules a best-effort reconciliation of edge assignments using a background context.
func (s *Server) TriggerDomainReconcile(reason string) {
	s.TriggerDomainReconcileWithContext(context.Background(), reason)
}

// TriggerDomainReconcileWithContext schedules a best-effort reconciliation of edge assignments with the provided context.
func (s *Server) TriggerDomainReconcileWithContext(ctx context.Context, reason string) {
	if ctx == nil {
		ctx = context.Background()
	}
	go s.reconcileDomainAssignments(ctx, reason)
}

// StartDomainReconciler kicks off a periodic reconciliation loop until the context is cancelled.
func (s *Server) StartDomainReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reconcileDomainAssignments(context.Background(), "scheduled")
			}
		}
	}()
}

func (s *Server) decorateNodesWithStatus(nodes []models.Node) []models.Node {
	if len(nodes) == 0 {
		return nodes
	}
	health, err := s.Store.GetEdgeHealthMap()
	if err != nil {
		log.Printf("infra: fetch edge health failed: %v", err)
		return nodes
	}
	nsStatuses, err := s.Store.GetNameServerStatus()
	if err != nil {
		log.Printf("infra: fetch name server health failed: %v", err)
	}
	nsByNode := make(map[string][]models.NameServerHealth)
	for _, status := range nsStatuses {
		id := strings.TrimSpace(status.NodeID)
		if id == "" {
			continue
		}
		nsByNode[id] = append(nsByNode[id], status)
	}
	for i := range nodes {
		nodes[i] = s.decorateNodeStatusWithHealth(nodes[i], health, nsByNode)
	}
	return nodes
}

func (s *Server) decorateNodeStatus(node models.Node) models.Node {
	decorated := s.decorateNodesWithStatus([]models.Node{node})
	if len(decorated) == 0 {
		return node
	}
	return decorated[0]
}

func (s *Server) decorateNodeStatusWithHealth(node models.Node, health map[string]models.EdgeHealthStatus, ns map[string][]models.NameServerHealth) models.Node {
	node.ComputeEdgeIPs()
	status, msg, healthyCount, totalCount, last := evaluateNodeStatus(node, health, ns[node.ID])
	node.Status = status
	node.StatusMsg = msg
	node.HealthyEdges = healthyCount
	node.TotalEdges = totalCount
	node.LastHealthAt = last
	if !last.IsZero() {
		node.LastSeenAt = last
	}
	return node
}

type componentSeverity int

const (
	componentNone componentSeverity = iota
	componentHealthy
	componentPending
	componentDegraded
	componentOffline
)

func severityMax(a, b componentSeverity) componentSeverity {
	if a > b {
		return a
	}
	return b
}

func evaluateNodeStatus(node models.Node, health map[string]models.EdgeHealthStatus, nsStatuses []models.NameServerHealth) (models.NodeStatus, string, int, int, time.Time) {
	totalEdges := len(node.EdgeIPs)
	var (
		edgeHealthy int
		edgePending int
		edgeLast    time.Time
		edgeMsgs    []string
	)
	for _, ip := range node.EdgeIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		status, ok := health[ip]
		if !ok {
			edgePending++
			continue
		}
		if status.LastChecked.After(edgeLast) {
			edgeLast = status.LastChecked
		}
		if status.Healthy {
			edgeHealthy++
			continue
		}
		msg := strings.TrimSpace(status.Message)
		if msg == "" {
			msg = "unreachable"
		}
		edgeMsgs = append(edgeMsgs, fmt.Sprintf("%s %s", ip, msg))
	}
	edgeSeverity := componentNone
	switch {
	case totalEdges == 0:
		edgeSeverity = componentNone
	case edgeHealthy == totalEdges && edgePending == 0:
		edgeSeverity = componentHealthy
	case edgeHealthy == totalEdges && edgePending > 0:
		edgeSeverity = componentPending
	case edgeHealthy == 0 && edgePending == totalEdges:
		edgeSeverity = componentPending
	case edgeHealthy == 0 && edgePending == 0:
		edgeSeverity = componentOffline
	default:
		edgeSeverity = componentDegraded
	}

	nsTotal := len(node.NSIPs)
	nsByIP := make(map[string]models.NameServerHealth, len(nsStatuses))
	for _, ns := range nsStatuses {
		ip := strings.TrimSpace(ns.IPv4)
		if ip == "" {
			continue
		}
		nsByIP[ip] = ns
	}
	var (
		nsHealthy int
		nsPending int
		nsLast    time.Time
		nsMsgs    []string
	)
	for _, ip := range node.NSIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		stat, ok := nsByIP[ip]
		if !ok {
			nsPending++
			continue
		}
		if stat.CheckedAt.After(nsLast) {
			nsLast = stat.CheckedAt
		}
		if stat.Healthy {
			nsHealthy++
			continue
		}
		msg := strings.TrimSpace(stat.Message)
		if msg == "" {
			msg = "unreachable"
		}
		nsMsgs = append(nsMsgs, fmt.Sprintf("%s %s", ip, msg))
	}
	nsSeverity := componentNone
	if nsTotal > 0 {
		switch {
		case nsHealthy == nsTotal && nsPending == 0:
			nsSeverity = componentHealthy
		case nsHealthy == nsTotal && nsPending > 0:
			nsSeverity = componentPending
		case nsHealthy == 0 && nsPending == nsTotal:
			nsSeverity = componentPending
		case nsHealthy == 0 && nsPending == 0:
			nsSeverity = componentOffline
		default:
			nsSeverity = componentDegraded
		}
	}

	finalSeverity := severityMax(edgeSeverity, nsSeverity)
	var last time.Time
	if edgeLast.After(last) {
		last = edgeLast
	}
	if nsLast.After(last) {
		last = nsLast
	}

	var status models.NodeStatus
	switch finalSeverity {
	case componentNone:
		if totalEdges == 0 && nsTotal == 0 {
			status = models.NodeStatusIdle
		} else {
			status = models.NodeStatusHealthy
		}
	case componentHealthy:
		status = models.NodeStatusHealthy
	case componentPending:
		status = models.NodeStatusPending
	case componentDegraded:
		status = models.NodeStatusDegraded
	case componentOffline:
		status = models.NodeStatusOffline
	}

	var summary []string
	if totalEdges > 0 {
		part := fmt.Sprintf("edges %d/%d healthy", edgeHealthy, totalEdges)
		if edgePending > 0 {
			part = part + fmt.Sprintf(", %d pending", edgePending)
		}
		if len(edgeMsgs) > 0 {
			part = part + " (" + strings.Join(edgeMsgs, "; ") + ")"
		}
		summary = append(summary, part)
	}
	if nsTotal > 0 {
		part := fmt.Sprintf("nameservers %d/%d healthy", nsHealthy, nsTotal)
		if nsPending > 0 {
			part = part + fmt.Sprintf(", %d pending", nsPending)
		}
		if len(nsMsgs) > 0 {
			part = part + " (" + strings.Join(nsMsgs, "; ") + ")"
		}
		summary = append(summary, part)
	}
	if len(summary) == 0 {
		summary = append(summary, "no services configured")
	}

	return status, strings.Join(summary, " | "), edgeHealthy, totalEdges, last
}

func (s *Server) bootstrapEdgeHealth(node models.Node) {
	node.ComputeEdgeIPs()
	if len(node.EdgeIPs) == 0 {
		return
	}
	healthMap, err := s.Store.GetEdgeHealthMap()
	if err != nil {
		log.Printf("infra: bootstrap edge health map load failed: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, ip := range node.EdgeIPs {
		if _, exists := healthMap[ip]; exists {
			continue
		}
		status := models.EdgeHealthStatus{
			IP:           ip,
			Healthy:      false,
			LastChecked:  time.Time{},
			FailureCount: 0,
			Message:      "awaiting first health check",
			Version: models.ClockVersion{
				Counter: 1,
				NodeID:  s.Config.NodeID,
				Updated: now.Unix(),
			},
		}
		if err := s.Store.UpsertEdgeHealth(status); err != nil {
			log.Printf("infra: record pending health for %s failed: %v", ip, err)
			continue
		}
		healthMap[ip] = status
	}
}

func (s *Server) cleanupEdgeHealth(node models.Node) {
	node.ComputeEdgeIPs()
	for _, ip := range node.EdgeIPs {
		if err := s.Store.DeleteEdgeHealth(ip); err != nil {
			log.Printf("infra: cleanup health for %s failed: %v", ip, err)
		}
	}
}

func (s *Server) handleNodeJoinCommand(w http.ResponseWriter, r *http.Request) {
	clusterSecretBytes, err := os.ReadFile(s.Config.ClusterSecretFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to read cluster secret")
		return
	}
	clusterSecret := strings.TrimSpace(string(clusterSecretBytes))
	jwtSecret := strings.TrimSpace(string(s.Config.JWTSecret))
	if clusterSecret == "" || jwtSecret == "" {
		writeError(w, http.StatusInternalServerError, "cluster secrets unavailable")
		return
	}
	seedURL := s.seedURLFromRequest(r)
	command := fmt.Sprintf(
		"wget -qO install.sh %s && chmod +x install.sh && ./install.sh --mode join --seed %s --cluster-secret '%s' --jwt-secret '%s' --node-name \"<node-name>\" --ips \"<ip1,ip2>\" --ns-ips \"<ns-ip1,ns-ip2>\" --edge-ips \"<edge-ip1,edge-ip2>\" --labels \"<edge-labels>\"",
		installScriptURL,
		seedURL,
		escapeSingleQuotes(clusterSecret),
		escapeSingleQuotes(jwtSecret),
	)
	writeJSON(w, http.StatusOK, map[string]string{"command": command})
}

func (s *Server) seedURLFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			if val := strings.TrimSpace(parts[0]); val != "" {
				scheme = val
			}
		}
	}
	host := s.resolveSeedHost(r.Host)
	return fmt.Sprintf("%s://%s", scheme, host)
}

func escapeSingleQuotes(input string) string {
	if input == "" {
		return ""
	}
	return strings.ReplaceAll(input, "'", `'"'"'`)
}

func (s *Server) resolveSeedHost(requestHost string) string {
	trimmed := strings.TrimSpace(requestHost)
	if trimmed != "" && !isLocalhost(trimmed) {
		if strings.Contains(trimmed, ":") {
			return trimmed
		}
		if s.Config.Port == 80 || s.Config.Port == 443 {
			return trimmed
		}
		return fmt.Sprintf("%s:%d", trimmed, s.Config.Port)
	}

	// fall back to current node endpoint
	if nodeHost := s.localNodeAPIHost(); nodeHost != "" {
		return nodeHost
	}

	port := s.Config.Port
	if port == 0 {
		port = 8080
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func (s *Server) localNodeAPIHost() string {
	nodes, err := s.Store.GetNodes()
	if err != nil {
		return ""
	}
	if host := hostFromNodes(nodes, s.Config.NodeID, s.Config.Port); host != "" {
		return host
	}
	if len(nodes) > 0 {
		return hostFromNodes(nodes[:1], "", s.Config.Port)
	}
	return ""
}

func hostFromNodes(nodes []models.Node, targetID string, fallbackPort int) string {
	for _, node := range nodes {
		if targetID != "" && node.ID != targetID {
			continue
		}
		if host := hostFromEndpoint(node.APIEndpoint, fallbackPort); host != "" {
			return host
		}
		if len(node.IPs) > 0 {
			ip := node.IPs[0]
			if fallbackPort == 80 || fallbackPort == 443 {
				return ip
			}
			return fmt.Sprintf("%s:%d", ip, fallbackPort)
		}
	}
	return ""
}

func hostFromEndpoint(endpoint string, fallbackPort int) string {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		return ""
	}
	if !strings.Contains(ep, "://") {
		ep = "http://" + ep
	}
	u, err := url.Parse(ep)
	if err != nil {
		h := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
		if h == "" {
			return ""
		}
		if strings.Contains(h, ":") {
			return h
		}
		if fallbackPort == 80 || fallbackPort == 443 {
			return h
		}
		return fmt.Sprintf("%s:%d", h, fallbackPort)
	}
	host := u.Host
	if host == "" {
		host = u.Path
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		return host
	}
	if fallbackPort == 80 || fallbackPort == 443 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, fallbackPort)
}

func isLocalhost(host string) bool {
	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "127.") || lower == "localhost" {
		return true
	}
	if strings.Contains(lower, ":") {
		parts := strings.Split(lower, ":")
		return isLocalhost(parts[0])
	}
	return false
}

func (s *Server) resolveOwnerDetails(owner string) (*models.User, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, models.ErrValidation("owner must be provided")
	}
	if user, err := s.Store.GetUserByID(owner); err == nil {
		return user, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	lower := strings.ToLower(owner)
	if strings.Contains(lower, "@") {
		if user, err := s.Store.FindUserByEmail(lower); err == nil {
			return user, nil
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	return nil, store.ErrNotFound
}

func (s *Server) handleNameServerCheck(w http.ResponseWriter, r *http.Request) {
	var req nsCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	targets := make(map[string]struct{}, len(req.Targets))
	for _, target := range req.Targets {
		t := strings.TrimSpace(strings.ToLower(target))
		if t != "" {
			targets[t] = struct{}{}
		}
	}
	nsList, err := s.Infra.ActiveNameServers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results := make([]nsCheckResult, 0, len(nsList))
	for _, ns := range nsList {
		if len(targets) > 0 {
			if _, ok := targets[strings.ToLower(ns.FQDN)]; !ok {
				continue
			}
		}
		healthy, latency, message := s.probeNameServer(r.Context(), ns)
		checkedAt := time.Now().UTC()
		results = append(results, nsCheckResult{
			NodeID:    ns.NodeID,
			Name:      ns.Name,
			FQDN:      ns.FQDN,
			IPv4:      ns.IPv4,
			Healthy:   healthy,
			LatencyMS: latency.Milliseconds(),
			Message:   message,
			CheckedAt: checkedAt,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		if results[i].FQDN != results[j].FQDN {
			return results[i].FQDN < results[j].FQDN
		}
		return results[i].IPv4 < results[j].IPv4
	})
	if len(results) > 0 {
		snapshot := make([]models.NameServerHealth, 0, len(results))
		for _, res := range results {
			snapshot = append(snapshot, models.NameServerHealth{
				NodeID:    res.NodeID,
				FQDN:      res.FQDN,
				IPv4:      res.IPv4,
				Healthy:   res.Healthy,
				LatencyMS: res.LatencyMS,
				Message:   res.Message,
				CheckedAt: res.CheckedAt,
			})
		}
		if err := s.Store.SaveNameServerStatus(snapshot); err != nil {
			log.Printf("infra: persist nameserver status failed: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleNameServerStatus(w http.ResponseWriter, r *http.Request) {
	statuses, err := s.Store.GetNameServerStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].NodeID != statuses[j].NodeID {
			return statuses[i].NodeID < statuses[j].NodeID
		}
		if statuses[i].FQDN != statuses[j].FQDN {
			return statuses[i].FQDN < statuses[j].FQDN
		}
		return statuses[i].IPv4 < statuses[j].IPv4
	})
	writeJSON(w, http.StatusOK, statuses)
}

func (s *Server) probeNameServer(ctx context.Context, ns infra.NameServer) (bool, time.Duration, string) {
	base := strings.TrimSpace(ns.BaseZone)
	if base == "" {
		base = ns.FQDN
	}
	fqdn := dns.Fqdn(base)
	client := &dns.Client{
		Timeout: 3 * time.Second,
	}
	msg := dns.Msg{}
	msg.SetQuestion(fqdn, dns.TypeNS)
	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, &msg, net.JoinHostPort(ns.IPv4, "53"))
	latency := time.Since(start)
	if err != nil {
		return false, latency, err.Error()
	}
	if resp == nil {
		return false, latency, "nil response"
	}
	if resp.Rcode != dns.RcodeSuccess {
		if text, ok := dns.RcodeToString[resp.Rcode]; ok {
			return false, latency, text
		}
		return false, latency, fmt.Sprintf("rcode %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		return false, latency, "empty answer"
	}
	return true, latency, ""
}
