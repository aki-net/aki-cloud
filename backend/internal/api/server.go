package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aki-cloud/backend/internal/auth"
	"aki-cloud/backend/internal/config"
	"aki-cloud/backend/internal/infra"
	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/orchestrator"
	"aki-cloud/backend/internal/store"
	syncsvc "aki-cloud/backend/internal/sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"
)

// Server holds routing dependencies.
type Server struct {
	Config       *config.Config
	Store        *store.Store
	Auth         *auth.Service
	Orchestrator *orchestrator.Service
	Sync         *syncsvc.Service
	Infra        *infra.Controller
}

type domainOverview struct {
	Domain      string                   `json:"domain"`
	OwnerID     string                   `json:"owner_id"`
	OwnerEmail  string                   `json:"owner_email,omitempty"`
	OwnerExists bool                     `json:"owner_exists"`
	OriginIP    string                   `json:"origin_ip"`
	Proxied     bool                     `json:"proxied"`
	UpdatedAt   time.Time                `json:"updated_at"`
	TLSMode     models.EncryptionMode    `json:"tls_mode,omitempty"`
	TLSStatus   models.CertificateStatus `json:"tls_status,omitempty"`
	TLSUseRec   bool                     `json:"tls_use_recommended"`
	TLSRecMode  models.EncryptionMode    `json:"tls_recommended_mode,omitempty"`
	TLSExpires  *time.Time               `json:"tls_expires_at,omitempty"`
	TLSError    string                   `json:"tls_last_error,omitempty"`
}

type nsCheckRequest struct {
	Targets []string `json:"targets"`
}

type nsCheckResult struct {
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	FQDN      string `json:"fqdn"`
	IPv4      string `json:"ipv4"`
	Healthy   bool   `json:"healthy"`
	LatencyMS int64  `json:"latency_ms"`
	Message   string `json:"message,omitempty"`
}

type domainTLSPayload struct {
	Mode           string `json:"mode,omitempty"`
	UseRecommended *bool  `json:"use_recommended,omitempty"`
}

type createDomainPayload struct {
	Domain   string            `json:"domain"`
	Owner    string            `json:"owner,omitempty"`
	OriginIP string            `json:"origin_ip"`
	Proxied  *bool             `json:"proxied,omitempty"`
	TTL      *int              `json:"ttl,omitempty"`
	TLS      *domainTLSPayload `json:"tls,omitempty"`
}

type updateDomainPayload struct {
	OriginIP string            `json:"origin_ip,omitempty"`
	Proxied  *bool             `json:"proxied,omitempty"`
	TTL      *int              `json:"ttl,omitempty"`
	TLS      *domainTLSPayload `json:"tls,omitempty"`
}

// Routes constructs the HTTP router.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://*", "https://*"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)

	r.Post("/auth/login", s.handleLogin)

	// Sync endpoints use shared secret auth instead of JWT
	r.Route("/api/v1/sync", func(r chi.Router) {
		r.Get("/digest", s.handleSyncDigest)
		r.Post("/pull", s.handleSyncPull)
		r.Post("/push", s.handleSyncPush)
	})

	tokenAuth := s.Auth.TokenAuth()

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)

		r.Route("/api/v1", func(r chi.Router) {
			r.Get("/domains", s.authorizeUser(s.handleListDomains))
			r.Post("/domains", s.authorizeUser(s.handleCreateDomain))
			r.Put("/domains/{domain}", s.authorizeUser(s.handleUpdateDomain))
			r.Delete("/domains/{domain}", s.authorizeUser(s.handleDeleteDomain))

			r.Get("/infra/nameservers", s.requireRole(models.RoleUser, s.handleInfraNS))
			r.Get("/infra/edges", s.requireRole(models.RoleUser, s.handleInfraEdges))

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

				r.Get("/domains/overview", s.handleDomainsOverview)
				r.Post("/infra/nameservers/check", s.handleNameServerCheck)

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
	user, err := s.Store.FindUserByEmail(strings.ToLower(req.Email))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
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
		ctx = withUserContext(ctx, sub, models.UserRole(role))
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
		ctx = withUserContext(ctx, sub, models.RoleAdmin)
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
		ctx = withUserContext(ctx, sub, models.UserRole(got))
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
		records, err = s.Store.ListDomainsForOwner(user.ID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range records {
		records[i] = records[i].Sanitize()
	}
	writeJSON(w, http.StatusOK, records)
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var payload createDomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Domain == "" || payload.OriginIP == "" {
		writeError(w, http.StatusBadRequest, "domain and origin_ip required")
		return
	}
	record := models.DomainRecord{
		Domain:   strings.ToLower(payload.Domain),
		Owner:    payload.Owner,
		OriginIP: payload.OriginIP,
		TTL:      60,
		Proxied:  true,
	}
	if record.Owner == "" {
		record.Owner = user.ID
	}
	if user.Role != models.RoleAdmin && record.Owner != user.ID {
		writeError(w, http.StatusForbidden, "cannot create domain for another user")
		return
	}
	if payload.Proxied != nil {
		record.Proxied = *payload.Proxied
	}
	if payload.TTL != nil {
		record.TTL = *payload.TTL
	}

	record.TLS.Mode = models.EncryptionFlexible
	record.TLS.UseRecommended = true
	record.TLS.Status = models.CertificateStatusNone
	if payload.TLS != nil {
		if payload.TLS.Mode != "" {
			record.TLS.Mode = models.EncryptionMode(strings.ToLower(payload.TLS.Mode))
		}
		if payload.TLS.UseRecommended != nil {
			record.TLS.UseRecommended = *payload.TLS.UseRecommended
		}
	}
	if !record.TLS.UseRecommended && record.TLS.Mode == "" {
		record.TLS.Mode = models.EncryptionFlexible
	}
	now := time.Now().UTC()
	record.TLS.UpdatedAt = now
	if err := record.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	record.UpdatedAt = now
	record.Version.Counter++
	record.Version.NodeID = s.Config.NodeID
	record.Version.Updated = now.Unix()
	if err := s.Store.UpsertDomain(record); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusCreated, record.Sanitize())
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if user.Role != models.RoleAdmin && existing.Owner != user.ID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var payload updateDomainPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.OriginIP != "" {
		existing.OriginIP = payload.OriginIP
	}
	if payload.Proxied != nil {
		existing.Proxied = *payload.Proxied
	}
	if payload.TTL != nil && *payload.TTL > 0 {
		existing.TTL = *payload.TTL
	}
	if payload.TLS != nil {
		if payload.TLS.Mode != "" {
			existing.TLS.Mode = models.EncryptionMode(strings.ToLower(payload.TLS.Mode))
		}
		if payload.TLS.UseRecommended != nil {
			existing.TLS.UseRecommended = *payload.TLS.UseRecommended
		}
		existing.TLS.UpdatedAt = time.Now().UTC()
		if !existing.TLS.UseRecommended && existing.TLS.Mode == "" {
			existing.TLS.Mode = models.EncryptionFlexible
		}
	}
	if err := existing.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	existing.UpdatedAt = time.Now().UTC()
	existing.Version.Counter++
	existing.Version.NodeID = s.Config.NodeID
	existing.Version.Updated = existing.UpdatedAt.Unix()
	if err := s.Store.UpsertDomain(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, existing.Sanitize())
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	domain := strings.ToLower(chi.URLParam(r, "domain"))
	existing, err := s.Store.GetDomain(domain)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	if user.Role != models.RoleAdmin && existing.Owner != user.ID {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.Store.DeleteDomain(domain); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
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
	edges, err := s.Infra.EdgeIPs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, edges)
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
	writeJSON(w, http.StatusOK, existing.Sanitize())
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Store.DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Store.GetNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var node models.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if node.ID == "" {
		node.ID = uuid.NewString()
	}
	node.Name = strings.TrimSpace(node.Name)
	node.APIEndpoint = strings.TrimSpace(node.APIEndpoint)
	node.IPs = filterEmpty(node.IPs)
	node.NSIPs = filterEmpty(node.NSIPs)
	node.ComputeEdgeIPs()
	if err := s.Store.UpsertNode(node); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("sync peers after create node: %v", err)
	}
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusCreated, node)
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
		NSLabel     *string   `json:"ns_label"`
		NSBase      *string   `json:"ns_base_domain"`
		APIEndpoint *string   `json:"api_endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if payload.Name != nil {
		existing.Name = strings.TrimSpace(*payload.Name)
	}
	if payload.IPs != nil {
		existing.IPs = filterEmpty(*payload.IPs)
	}
	if payload.NSIPs != nil {
		existing.NSIPs = filterEmpty(*payload.NSIPs)
	}
	if payload.NSLabel != nil {
		existing.NSLabel = strings.TrimSpace(*payload.NSLabel)
	}
	if payload.NSBase != nil {
		existing.NSBase = strings.TrimSpace(*payload.NSBase)
	}
	if payload.APIEndpoint != nil {
		existing.APIEndpoint = strings.TrimSpace(*payload.APIEndpoint)
	}
	existing.ComputeEdgeIPs()
	if err := s.Store.UpsertNode(*existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("sync peers after update node: %v", err)
	}
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.Store.DeleteNode(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.syncPeersFromNodes(); err != nil {
		log.Printf("sync peers after delete node: %v", err)
	}
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
	overview := make([]domainOverview, 0, len(domains))
	for _, domain := range domains {
		entry := domainOverview{
			Domain:      domain.Domain,
			OwnerID:     domain.Owner,
			OwnerExists: false,
			OriginIP:    domain.OriginIP,
			Proxied:     domain.Proxied,
			UpdatedAt:   domain.UpdatedAt,
			TLSMode:     domain.TLS.Mode,
			TLSStatus:   domain.TLS.Status,
			TLSUseRec:   domain.TLS.UseRecommended,
			TLSRecMode:  domain.TLS.RecommendedMode,
			TLSError:    domain.TLS.LastError,
		}
		if domain.TLS.Certificate != nil && !domain.TLS.Certificate.NotAfter.IsZero() {
			expires := domain.TLS.Certificate.NotAfter.UTC()
			entry.TLSExpires = &expires
		}
		if user, ok := userMap[domain.Owner]; ok {
			entry.OwnerExists = true
			entry.OwnerEmail = user.Email
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

type userContextKey struct{}

type userContext struct {
	ID   string
	Role models.UserRole
}

func withUserContext(ctx context.Context, id string, role models.UserRole) context.Context {
	return context.WithValue(ctx, userContextKey{}, userContext{ID: id, Role: role})
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

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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
		results = append(results, nsCheckResult{
			NodeID:    ns.NodeID,
			Name:      ns.Name,
			FQDN:      ns.FQDN,
			IPv4:      ns.IPv4,
			Healthy:   healthy,
			LatencyMS: latency.Milliseconds(),
			Message:   message,
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
	writeJSON(w, http.StatusOK, results)
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
