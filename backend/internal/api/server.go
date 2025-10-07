package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
	writeJSON(w, http.StatusOK, records)
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	var req models.DomainRecord
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	req.Domain = strings.ToLower(req.Domain)
	if req.Owner == "" {
		req.Owner = user.ID
	}
	if user.Role != models.RoleAdmin && req.Owner != user.ID {
		writeError(w, http.StatusForbidden, "cannot create domain for another user")
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.UpdatedAt = time.Now().UTC()
	req.Version.Counter++
	req.Version.NodeID = s.Config.NodeID
	req.Version.Updated = req.UpdatedAt.Unix()
	if err := s.Store.UpsertDomain(req); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	go s.Orchestrator.Trigger(r.Context())
	writeJSON(w, http.StatusCreated, req)
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
	var payload models.DomainRecord
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	existing.OriginIP = payload.OriginIP
	existing.Proxied = payload.Proxied
	if payload.TTL > 0 {
		existing.TTL = payload.TTL
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
	writeJSON(w, http.StatusOK, existing)
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
