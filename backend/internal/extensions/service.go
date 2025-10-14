package extensions

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"aki-cloud/backend/internal/models"
	"aki-cloud/backend/internal/store"
)

// Definition describes a known extension and its capabilities.
type Definition struct {
	Key             string
	Name            string
	Description     string
	Category        string
	Scope           models.ExtensionScope
	Actions         []Action
	DefaultEnabled  bool
	DefaultConfig   map[string]interface{}
	RequiresRestart bool
}

// Action represents an operation exposed for an extension (e.g. cache purge).
type Action struct {
	Key         string
	Label       string
	Description string
}

// Extension couples definition and persisted state.
type Extension struct {
	Definition Definition
	State      models.ExtensionState
}

// ErrNotFound indicates the requested extension is not defined.
var ErrNotFound = errors.New("extension not found")

// Service provides helpers for working with extension configuration.
type Service struct {
	store       *store.Store
	definitions map[string]Definition
	nodeID      string
}

// New creates a new extensions service.
func New(st *store.Store, nodeID string) *Service {
	defs := map[string]Definition{
		models.ExtensionEdgeCache: {
			Key:         models.ExtensionEdgeCache,
			Name:        "Edge Cache",
			Description: "Caches HTTP responses on edge nodes to improve latency and reduce origin load.",
			Category:    "Performance",
			Scope:       models.ExtensionScopeGlobal,
			Actions: []Action{
				{
					Key:         "purge",
					Label:       "Clear Cache",
					Description: "Invalidate all cached objects across edge nodes.",
				},
			},
			DefaultEnabled: false,
			DefaultConfig: map[string]interface{}{
				"path":               "/data/openresty/cache",
				"zone_name":          "edge_cache",
				"levels":             "1:2",
				"keys_zone_size":     "128m",
				"max_size":           "10g",
				"inactive":           "60m",
				"min_uses":           2,
				"use_stale":          []interface{}{"error", "timeout", "updating", "http_500", "http_502", "http_503", "http_504"},
				"add_status_header":  true,
				"bypass_cookies":     []interface{}{"sessionid", "auth_token"},
				"base_ttl_seconds":   86400,
				"not_found_ttl":      600,
				"error_ttl":          60,
				"ttl_jitter_percent": 15,
			},
		},
		models.ExtensionRandomServerNames: {
			Key:            models.ExtensionRandomServerNames,
			Name:           "Random Server Headers",
			Description:    "Deterministically randomises Server headers per domain to make fingerprinting harder.",
			Category:       "Security",
			Scope:          models.ExtensionScopeGlobal,
			DefaultEnabled: false,
			DefaultConfig: map[string]interface{}{
				"pool": []interface{}{
					"nginx",
					"nginx/1.18.0",
					"nginx/1.19.6",
					"nginx/1.20.2",
					"nginx/1.22.1",
					"nginx/1.23.4",
					"nginx/1.24.0",
					"nginx/1.25.2",
					"openresty",
					"openresty/1.21.4.1",
					"Tengine",
					"Tengine/2.3.3",
					"cloudflare",
					"cloudflare-nginx",
					"CloudFront",
					"AkamaiGHost",
					"AmazonS3",
					"awselb/2.0",
					"Microsoft-IIS/7.5",
					"Microsoft-IIS/8.5",
					"Microsoft-IIS/10.0",
					"IIS",
					"Apache",
					"Apache/2.4.41 (Ubuntu)",
					"Apache/2.4.52 (Ubuntu)",
					"Apache/2.4.54 (Unix)",
					"Apache/2.4.57 (Unix) OpenSSL/3.0.8",
					"Apache-Coyote/1.1",
					"LiteSpeed",
					"LiteSpeed/6.0.12 Enterprise",
					"Caddy",
					"Caddy/2.7.4",
					"Envoy",
					"envoy/1.27.1",
					"Varnish",
					"Varnish/7.1",
					"AWS Lambda@Edge",
					"Fastly",
					"Fly.io",
					"Netlify",
					"Vercel",
					"Cloudflare Pages",
					"Google Frontend",
					"GSE",
					"gws",
					"ATS",
					"ATS/8.0.8",
					"Apache Traffic Server",
					"Edgecast",
					"Edgecast/2.0",
					"ECS (dcb/7F0B)",
					"ECS (sjc/4E2A)",
					"ECAcc (pdx/4096)",
					"ECD (dca/4F39)",
					"bunnycdn",
					"BunnyCDN",
					"Sucuri/Cloudproxy",
					"Reblaze",
					"Cloudflare-Workers",
					"ArvanCloud",
					"Namecheap CDN",
					"Rev-Cache",
					"StackPath/Rproxy",
					"Yunjiasu",
					"yunjiasu-nginx",
					"Alibaba Cloud",
					"TencentCDN",
					"QiniuCDN",
					"360wzb",
					"BaiduYunGuanjia",
					"openedge",
					"ProxyShield",
					"Verizon CDN",
					"QUIC.cloud",
					"sw-CDN",
					"CDN77",
					"Backtrace",
					"cachefly",
					"Zenbooster",
					"PangeaCDN",
					"StackPath",
					"Azion",
					"Highwinds",
					"edge-ios",
					"Anquanbao",
					"Incapsula",
					"Ingenius Cloud",
					"AeroCloud",
					"Cloudbric",
					"Azure Front Door",
					"Azure App Service",
					"Jetty(9.4.51.v20230217)",
					"Jetty(10.0.13)",
					"Undertow",
					"Undertow/2",
					"gunicorn/20.1.0",
					"uvicorn",
					"uvicorn/starlette",
					"TornadoServer/6.3.2",
					"Werkzeug/2.3.7 Python/3.11.4",
					"Django/4.1.7",
					"Flask",
					"Express",
					"Node.js",
					"Node/18",
					"Kestrel",
					"Kestrel/2.0",
					"ASP.NET",
					"ASP.NET Core",
					"Rocket",
					"Rocket/0.5.0",
					"hyper",
					"cloudflare-mirage",
					"Linkerd",
					"HAProxy",
					"HAProxy/2.7.5",
					"Traefik",
					"Traefik/2.10.1",
					"Cowboy",
					"Cowboy/2.9.0",
					"Puma 5.6.4",
					"Passenger/6.0.15",
					"mod_jk/1.2.48",
					"Resin/4.0.65",
					"Zoey CDN",
					"Tomcat",
					"Tomcat-Embed",
					"JBoss-EAP/7",
					"WildFly/26",
				},
			},
		},
		models.ExtensionPlaceholderPages: {
			Key:            models.ExtensionPlaceholderPages,
			Name:           "Aki Placeholder Pages",
			Description:    "Serve branded placeholder responses for domains without an origin IP.",
			Category:       "Operations",
			Scope:          models.ExtensionScopeGlobal,
			DefaultEnabled: false,
			DefaultConfig: map[string]interface{}{
				"title":        "Domain delegated to aki.cloud",
				"subtitle":     "Edge is live, origin not configured yet.",
				"message":      "Traffic reaches aki.cloud edge, but origin IP is not set. Configure an origin or keep this placeholder active for staging.",
				"support_url":  "https://aki.cloud/help/origin/missing",
				"support_text": "Learn how to point traffic",
				"footer":       "aki.cloud edge platform",
			},
		},
	}
	return &Service{
		store:       st,
		definitions: defs,
		nodeID:      nodeID,
	}
}

// ListGlobal returns known extensions with merged state.
func (s *Service) ListGlobal() ([]Extension, error) {
	doc, err := s.store.GetExtensionsState()
	if err != nil {
		return nil, err
	}
	out := make([]Extension, 0, len(s.definitions))
	for key, def := range s.definitions {
		stored, ok := doc.Config.Global[key]
		state := resolveState(def, stored, ok)
		out = append(out, Extension{
			Definition: def,
			State:      state,
		})
	}
	return out, nil
}

// GetGlobal returns the extension definition with current state.
func (s *Service) GetGlobal(key string) (Extension, error) {
	def, ok := s.definitions[key]
	if !ok {
		return Extension{}, ErrNotFound
	}
	doc, err := s.store.GetExtensionsState()
	if err != nil {
		return Extension{}, err
	}
	stored, exists := doc.Config.Global[key]
	state := resolveState(def, stored, exists)
	return Extension{
		Definition: def,
		State:      state,
	}, nil
}

// UpdateGlobal updates the global state for a given extension.
func (s *Service) UpdateGlobal(key string, enabled *bool, config map[string]interface{}, updatedBy string) (Extension, error) {
	def, ok := s.definitions[key]
	if !ok {
		return Extension{}, ErrNotFound
	}
	doc, err := s.store.UpdateExtensionsState(s.nodeID, func(docState *models.ExtensionsState) error {
		stored, exists := docState.Config.Global[key]
		updatedState := resolveState(def, stored, exists)
		if enabled != nil {
			updatedState.Enabled = *enabled
		}
		if config != nil {
			updatedState.Config = mergeConfig(def.DefaultConfig, config)
		}
		updatedState.UpdatedAt = time.Now().UTC()
		updatedState.UpdatedBy = updatedBy
		docState.Config.Global[key] = updatedState
		return nil
	})
	if err != nil {
		return Extension{}, err
	}
	stored, exists := doc.Config.Global[key]
	updated := resolveState(def, stored, exists)
	return Extension{
		Definition: def,
		State:      updated,
	}, nil
}

// EdgeCacheConfig returns runtime parameters for edge caching.
func (s *Service) EdgeCacheConfig() (EdgeCacheRuntimeConfig, error) {
	ext, err := s.GetGlobal(models.ExtensionEdgeCache)
	if err != nil {
		return EdgeCacheRuntimeConfig{}, err
	}
	cfg := ext.State.Config
	if cfg == nil {
		cfg = make(map[string]interface{})
	}
	return EdgeCacheRuntimeConfig{
		Enabled:         ext.State.Enabled,
		Path:            stringValue(cfg, "path", "/data/openresty/cache"),
		ZoneName:        stringValue(cfg, "zone_name", "edge_cache"),
		Levels:          stringValue(cfg, "levels", "1:2"),
		KeysZoneSize:    stringValue(cfg, "keys_zone_size", "128m"),
		MaxSize:         stringValue(cfg, "max_size", "10g"),
		Inactive:        stringValue(cfg, "inactive", "60m"),
		MinUses:         intValue(cfg, "min_uses", 2),
		AddStatusHeader: boolValue(cfg, "add_status_header", true),
		UseStale:        stringSlice(cfg, "use_stale", []string{"error", "timeout", "updating", "http_500", "http_502", "http_503", "http_504"}),
		BypassCookies:   stringSlice(cfg, "bypass_cookies", []string{"sessionid", "auth_token"}),
		BaseTTLSeconds:  intValue(cfg, "base_ttl_seconds", 86400),
		NotFoundTTL:     intValue(cfg, "not_found_ttl", 600),
		ErrorTTL:        intValue(cfg, "error_ttl", 60),
		TTLJitterPct:    intValue(cfg, "ttl_jitter_percent", 15),
	}, nil
}

// PlaceholderConfig returns runtime settings for placeholder pages.
func (s *Service) PlaceholderConfig() (PlaceholderRuntimeConfig, error) {
	ext, err := s.GetGlobal(models.ExtensionPlaceholderPages)
	if err != nil {
		return PlaceholderRuntimeConfig{}, err
	}
	cfg := ext.State.Config
	if cfg == nil {
		cfg = make(map[string]interface{})
	}
	return PlaceholderRuntimeConfig{
		Enabled:     ext.State.Enabled,
		Title:       stringValue(cfg, "title", "Domain delegated to aki.cloud"),
		Subtitle:    stringValue(cfg, "subtitle", "Edge is live, origin not configured yet."),
		Message:     stringValue(cfg, "message", "Traffic reaches aki.cloud edge, but origin IP is not set. Configure an origin or keep this placeholder active for staging."),
		SupportURL:  stringValue(cfg, "support_url", "https://aki.cloud/help/origin/missing"),
		SupportText: stringValue(cfg, "support_text", "Learn how to point traffic"),
		Footer:      stringValue(cfg, "footer", "aki.cloud edge platform"),
	}, nil
}

// ServerHeaderForDomain returns the synthetic Server header for the domain if the extension is enabled.
func (s *Service) ServerHeaderForDomain(domain string) (string, bool, error) {
	ext, err := s.GetGlobal(models.ExtensionRandomServerNames)
	if err != nil {
		return "", false, err
	}
	if !ext.State.Enabled {
		return "", false, nil
	}
	pool := stringSlice(ext.State.Config, "pool", defaultServerHeaderPool())
	if len(pool) == 0 {
		pool = defaultServerHeaderPool()
	}
	domainKey := strings.ToLower(strings.TrimSpace(domain))
	if domainKey == "" {
		return "", false, errors.New("domain required for server header")
	}
	sum := sha256.Sum256([]byte(domainKey))
	index := binary.BigEndian.Uint32(sum[:4]) % uint32(len(pool))
	selected := pool[index]
	return selected, true, nil
}

// EdgeCacheRuntimeConfig captures nginx-related cache parameters.
type EdgeCacheRuntimeConfig struct {
	Enabled         bool
	Path            string
	ZoneName        string
	Levels          string
	KeysZoneSize    string
	MaxSize         string
	Inactive        string
	MinUses         int
	AddStatusHeader bool
	UseStale        []string
	BypassCookies   []string
	BaseTTLSeconds  int
	NotFoundTTL     int
	ErrorTTL        int
	TTLJitterPct    int
}

// PlaceholderRuntimeConfig describes placeholder copy shown when no origin IP is set.
type PlaceholderRuntimeConfig struct {
	Enabled     bool
	Title       string
	Subtitle    string
	Message     string
	SupportURL  string
	SupportText string
	Footer      string
}

func resolveState(def Definition, stored models.ExtensionState, exists bool) models.ExtensionState {
	state := stored
	if state.Config == nil {
		state.Config = make(map[string]interface{})
	}
	if def.DefaultConfig != nil {
		state.Config = mergeConfig(def.DefaultConfig, state.Config)
	}
	if !exists {
		state.Enabled = def.DefaultEnabled
	}
	return state
}

func mergeConfig(defaults, overrides map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(defaults)+len(overrides))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

func stringValue(cfg map[string]interface{}, key string, fallback string) string {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key]; ok {
		switch val := v.(type) {
		case string:
			if strings.TrimSpace(val) != "" {
				return val
			}
		}
	}
	return fallback
}

func intValue(cfg map[string]interface{}, key string, fallback int) int {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key]; ok {
		switch val := v.(type) {
		case float64:
			if val >= 0 {
				return int(val)
			}
		case int:
			return val
		case int64:
			return int(val)
		}
	}
	return fallback
}

func boolValue(cfg map[string]interface{}, key string, fallback bool) bool {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key]; ok {
		switch val := v.(type) {
		case bool:
			return val
		case string:
			switch strings.ToLower(strings.TrimSpace(val)) {
			case "true", "1", "yes", "on":
				return true
			case "false", "0", "no", "off":
				return false
			}
		}
	}
	return fallback
}

func stringSlice(cfg map[string]interface{}, key string, fallback []string) []string {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key]; ok {
		switch vals := v.(type) {
		case []interface{}:
			out := make([]string, 0, len(vals))
			for _, item := range vals {
				switch iv := item.(type) {
				case string:
					if strings.TrimSpace(iv) != "" {
						out = append(out, iv)
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		case []string:
			if len(vals) > 0 {
				return vals
			}
		}
	}
	return fallback
}

func defaultServerHeaderPool() []string {
	return []string{
		"nginx",
		"nginx/1.18.0",
		"nginx/1.19.6",
		"nginx/1.20.2",
		"nginx/1.22.1",
		"nginx/1.23.4",
		"nginx/1.24.0",
		"nginx/1.25.2",
		"openresty",
		"openresty/1.21.4.1",
		"Tengine",
		"Tengine/2.3.3",
		"cloudflare",
		"cloudflare-nginx",
		"CloudFront",
		"AkamaiGHost",
		"AmazonS3",
		"awselb/2.0",
		"Microsoft-IIS/7.5",
		"Microsoft-IIS/8.5",
		"Microsoft-IIS/10.0",
		"IIS",
		"Apache",
		"Apache/2.4.41 (Ubuntu)",
		"Apache/2.4.52 (Ubuntu)",
		"Apache/2.4.54 (Unix)",
		"Apache/2.4.57 (Unix) OpenSSL/3.0.8",
		"Apache-Coyote/1.1",
		"LiteSpeed",
		"LiteSpeed/6.0.12 Enterprise",
		"Caddy",
		"Caddy/2.7.4",
		"Envoy",
		"envoy/1.27.1",
		"Varnish",
		"Varnish/7.1",
		"AWS Lambda@Edge",
		"Fastly",
		"Fly.io",
		"Netlify",
		"Vercel",
		"Cloudflare Pages",
		"Google Frontend",
		"GSE",
		"gws",
		"ATS",
		"ATS/8.0.8",
		"Apache Traffic Server",
		"Edgecast",
		"Edgecast/2.0",
		"ECS (dcb/7F0B)",
		"ECS (sjc/4E2A)",
		"ECAcc (pdx/4096)",
		"ECD (dca/4F39)",
		"bunnycdn",
		"BunnyCDN",
		"Sucuri/Cloudproxy",
		"Reblaze",
		"Cloudflare-Workers",
		"ArvanCloud",
		"Namecheap CDN",
		"Rev-Cache",
		"StackPath/Rproxy",
		"Yunjiasu",
		"yunjiasu-nginx",
		"Alibaba Cloud",
		"TencentCDN",
		"QiniuCDN",
		"360wzb",
		"BaiduYunGuanjia",
		"openedge",
		"ProxyShield",
		"Verizon CDN",
		"QUIC.cloud",
		"sw-CDN",
		"CDN77",
		"Backtrace",
		"cachefly",
		"Zenbooster",
		"PangeaCDN",
		"StackPath",
		"Azion",
		"Highwinds",
		"edge-ios",
		"Anquanbao",
		"Incapsula",
		"Ingenic Cloud",
		"AeroCloud",
		"Cloudbric",
		"Azure Front Door",
		"Azure App Service",
		"Jetty(9.4.51.v20230217)",
		"Jetty(10.0.13)",
		"Undertow",
		"Undertow/2",
		"gunicorn/20.1.0",
		"uvicorn",
		"uvicorn/starlette",
		"TornadoServer/6.3.2",
		"Werkzeug/2.3.7 Python/3.11.4",
		"Django/4.1.7",
		"Flask",
		"Express",
		"Node.js",
		"Node/18",
		"Kestrel",
		"Kestrel/2.0",
		"ASP.NET",
		"ASP.NET Core",
		"Rocket",
		"Rocket/0.5.0",
		"hyper",
		"cloudflare-mirage",
		"Linkerd",
		"HAProxy",
		"HAProxy/2.7.5",
		"Traefik",
		"Traefik/2.10.1",
		"Cowboy",
		"Cowboy/2.9.0",
		"Puma 5.6.4",
		"Passenger/6.0.15",
		"mod_jk/1.2.48",
		"Resin/4.0.65",
		"Zoey CDN",
		"Tomcat",
		"Tomcat-Embed",
		"JBoss-EAP/7",
		"WildFly/26",
	}
}
