package extensions

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"aki-cloud/backend/internal/infra"
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

// VanityNSRuntimeConfig captures runtime settings for vanity nameserver generation.
type VanityNSRuntimeConfig struct {
	Enabled    bool
	Label      string
	BaseDomain string
	Count      int
	HashLength int
}

// VanityNameServer represents a synthesized NS hostname with its glue IP.
type VanityNameServer struct {
	Name string
	IPv4 string
}

// VanityNameServerSet groups synthetic names by category.
type VanityNameServerSet struct {
	Anycast []VanityNameServer
	Domain  []VanityNameServer
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
		models.ExtensionVanityNameServers: {
			Key:            models.ExtensionVanityNameServers,
			Name:           "Vanity Name Servers",
			Description:    "Assigns per-domain vanity NS names within the platform domain to reduce fingerprinting.",
			Category:       "DNS",
			Scope:          models.ExtensionScopeGlobal,
			DefaultEnabled: false,
			DefaultConfig: map[string]interface{}{
				"label":       "dns",
				"base_domain": "aki.cloud",
				"count":       2,
				"hash_length": 8,
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
		models.ExtensionSearchBotLogs: {
			Key:            models.ExtensionSearchBotLogs,
			Name:           "Search Bot Analytics",
			Description:    "Capture crawler visits, surface counters, and export search bot access logs per domain.",
			Category:       "Analytics",
			Scope:          models.ExtensionScopeGlobal,
			DefaultEnabled: false,
			DefaultConfig: map[string]interface{}{
				"log_dir":           "/data/searchbot/logs",
				"file_limit_mb":     1024,
				"cache_ttl_minutes": 60,
				"bots": []interface{}{
					map[string]interface{}{
						"key":     "googlebot",
						"label":   "Googlebot",
						"icon":    "G",
						"matches": []interface{}{"googlebot"},
					},
					map[string]interface{}{
						"key":     "bingbot",
						"label":   "Bingbot",
						"icon":    "B",
						"matches": []interface{}{"bingbot"},
					},
					map[string]interface{}{
						"key":     "yandexbot",
						"label":   "YandexBot",
						"icon":    "Y",
						"matches": []interface{}{"yandex"},
					},
					map[string]interface{}{
						"key":     "baiduspider",
						"label":   "Baidu Spider",
						"icon":    "Bd",
						"matches": []interface{}{"baiduspider"},
					},
				},
			},
			Actions: []Action{
				{
					Key:         "clear_logs",
					Label:       "Clear Logs",
					Description: "Truncate search bot logs on all edge nodes.",
				},
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

// SearchBotConfig returns runtime parameters for search bot logging.
func (s *Service) SearchBotConfig() (SearchBotRuntimeConfig, error) {
	out := SearchBotRuntimeConfig{}
	ext, err := s.GetGlobal(models.ExtensionSearchBotLogs)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return out, nil
		}
		return out, err
	}
	cfg := ext.State.Config
	if cfg == nil {
		cfg = make(map[string]interface{})
	}
	logDir := strings.TrimSpace(stringValue(cfg, "log_dir", "/data/searchbot/logs"))
	if logDir == "" {
		logDir = "/data/searchbot/logs"
	}
	logDir = filepath.Clean(logDir)
	logFile := filepath.Join(logDir, "searchbots.log")
	baseDir := filepath.Dir(logDir)
	if baseDir == "." || baseDir == "/" {
		baseDir = "/data/searchbot"
	}
	rangesDir := filepath.Join(baseDir, "ranges")
	geoFile := filepath.Join(rangesDir, "google.geo")
	jsonFile := filepath.Join(rangesDir, "google.json")
	limitMB := intValue(cfg, "file_limit_mb", 1024)
	if limitMB <= 0 {
		limitMB = 1024
	}
	cacheMinutes := intValue(cfg, "cache_ttl_minutes", 60)
	if cacheMinutes <= 0 {
		cacheMinutes = 60
	}
	bots := parseSearchBotDefinitions(cfg["bots"])
	fileLimit := int64(limitMB) * 1024 * 1024
	if fileLimit < 10*1024*1024 {
		fileLimit = 10 * 1024 * 1024
	}
	for i := range bots {
		if bots[i].LogPath == "" {
			bots[i].LogPath = logFile
		}
	}
	out = SearchBotRuntimeConfig{
		Enabled:        ext.State.Enabled,
		LogDir:         logDir,
		LogFile:        logFile,
		RangesDir:      rangesDir,
		GeoFile:        geoFile,
		JSONFile:       jsonFile,
		RangesURL:      googlebotRangesURL,
		FileLimitBytes: fileLimit,
		CacheTTL:       time.Duration(cacheMinutes) * time.Minute,
		Bots:           bots,
	}
	return out, nil
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

// VanityNSConfig returns runtime settings for vanity nameserver generation.
func (s *Service) VanityNSConfig() (VanityNSRuntimeConfig, error) {
	cfg := VanityNSRuntimeConfig{}
	ext, err := s.GetGlobal(models.ExtensionVanityNameServers)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return cfg, nil
		}
		return cfg, err
	}
	raw := ext.State.Config
	if raw == nil {
		raw = make(map[string]interface{})
	}
	label := sanitizeDNSLabel(stringValue(raw, "label", "dns"))
	if label == "" {
		label = "dns"
	}
	baseDomain := sanitizeDomain(stringValue(raw, "base_domain", "aki.cloud"))
	if baseDomain == "" {
		baseDomain = "aki.cloud"
	}
	count := intValue(raw, "count", 2)
	if count <= 0 {
		count = 2
	}
	if count > 8 {
		count = 8
	}
	hashLength := intValue(raw, "hash_length", 8)
	if hashLength < 4 {
		hashLength = 4
	}
	if hashLength > 32 {
		hashLength = 32
	}
	cfg = VanityNSRuntimeConfig{
		Enabled:    ext.State.Enabled,
		Label:      label,
		BaseDomain: baseDomain,
		Count:      count,
		HashLength: hashLength,
	}
	return cfg, nil
}

// VanityNameServersForDomain returns synthetic vanity NS names for the provided domain.
func (s *Service) VanityNameServersForDomain(domain string, nsList []infra.NameServer) (VanityNameServerSet, error) {
	out := VanityNameServerSet{}
	cfg, err := s.VanityNSConfig()
	if err != nil {
		return out, err
	}
	if !cfg.Enabled {
		return out, nil
	}
	domainKey := strings.TrimSpace(strings.ToLower(domain))
	domainKey = strings.TrimSuffix(domainKey, ".")
	if domainKey == "" {
		return out, errors.New("domain required for vanity nameserver generation")
	}
	available := selectNameServersForDomain(domainKey, nsList, cfg.Count)
	if len(available) == 0 {
		return out, nil
	}
	for idx, ns := range available {
		label := hashedVanityLabel(domainKey, ns.FQDN, idx, cfg.HashLength)
		fqdn := joinLabels(label, cfg.Label, cfg.BaseDomain)
		out.Anycast = append(out.Anycast, VanityNameServer{
			Name: fqdn,
			IPv4: strings.TrimSpace(ns.IPv4),
		})
		domainLabel := fmt.Sprintf("ns%d", idx+1)
		out.Domain = append(out.Domain, VanityNameServer{
			Name: joinLabels(domainLabel, domainKey),
			IPv4: strings.TrimSpace(ns.IPv4),
		})
	}
	return out, nil
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

const googlebotRangesURL = "https://developers.google.com/static/search/apis/ipranges/googlebot.json"

// SearchBotDefinition describes a search crawler signature we want to capture.
type SearchBotDefinition struct {
	Key     string
	Label   string
	Icon    string
	Matches []string
	Regex   string
	LogPath string
}

// SearchBotRuntimeConfig captures runtime settings for crawler logging.
type SearchBotRuntimeConfig struct {
	Enabled        bool
	LogDir         string
	LogFile        string
	RangesDir      string
	GeoFile        string
	JSONFile       string
	RangesURL      string
	FileLimitBytes int64
	CacheTTL       time.Duration
	Bots           []SearchBotDefinition
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

func parseSearchBotDefinitions(value interface{}) []SearchBotDefinition {
	if value == nil {
		return defaultSearchBotDefinitions()
	}
	defs := make([]SearchBotDefinition, 0, 4)
	switch raw := value.(type) {
	case []interface{}:
		for _, item := range raw {
			if def, ok := parseSearchBotDefinition(item); ok {
				defs = append(defs, def)
			}
		}
	case []map[string]interface{}:
		for _, item := range raw {
			if def, ok := parseSearchBotDefinition(item); ok {
				defs = append(defs, def)
			}
		}
	default:
		return defaultSearchBotDefinitions()
	}
	if len(defs) == 0 {
		return defaultSearchBotDefinitions()
	}
	sort.SliceStable(defs, func(i, j int) bool {
		if defs[i].Key == defs[j].Key {
			return defs[i].Label < defs[j].Label
		}
		return defs[i].Key < defs[j].Key
	})
	return defs
}

func parseSearchBotDefinition(item interface{}) (SearchBotDefinition, bool) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return SearchBotDefinition{}, false
	}
	key := sanitizeSearchBotKey(anyToString(m["key"]))
	if key == "" {
		return SearchBotDefinition{}, false
	}
	label := strings.TrimSpace(anyToString(m["label"]))
	if label == "" {
		label = defaultLabelForKey(key)
	}
	icon := strings.TrimSpace(anyToString(m["icon"]))
	matches := normalizeStringSlice(m["matches"])
	if len(matches) == 0 {
		matches = []string{key}
	}
	regexes := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.TrimSpace(match)
		if match == "" {
			continue
		}
		regexes = append(regexes, regexp.QuoteMeta(match))
	}
	if len(regexes) == 0 {
		regexes = append(regexes, regexp.QuoteMeta(key))
	}
	return SearchBotDefinition{
		Key:     key,
		Label:   label,
		Icon:    icon,
		Matches: matches,
		Regex:   strings.Join(regexes, "|"),
	}, true
}

func defaultSearchBotDefinitions() []SearchBotDefinition {
	return []SearchBotDefinition{
		{
			Key:     "googlebot",
			Label:   "Googlebot",
			Icon:    "G",
			Matches: []string{"googlebot"},
			Regex:   regexp.QuoteMeta("googlebot"),
		},
		{
			Key:     "bingbot",
			Label:   "Bingbot",
			Icon:    "B",
			Matches: []string{"bingbot"},
			Regex:   regexp.QuoteMeta("bingbot"),
		},
		{
			Key:     "yandexbot",
			Label:   "YandexBot",
			Icon:    "Y",
			Matches: []string{"yandex"},
			Regex:   regexp.QuoteMeta("yandex"),
		},
		{
			Key:     "baiduspider",
			Label:   "Baidu Spider",
			Icon:    "Bd",
			Matches: []string{"baiduspider"},
			Regex:   regexp.QuoteMeta("baiduspider"),
		},
	}
}

func sanitizeSearchBotKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		}
	}
	return strings.Trim(builder.String(), "-_")
}

func anyToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case []byte:
		return string(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int, int32, int64:
		return fmt.Sprintf("%v", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func normalizeStringSlice(value interface{}) []string {
	switch v := value.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			out = append(out, item)
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			str := strings.TrimSpace(anyToString(item))
			if str == "" || strings.EqualFold(str, "<nil>") {
				continue
			}
			out = append(out, str)
		}
		return out
	default:
		str := strings.TrimSpace(anyToString(value))
		if str == "" || strings.EqualFold(str, "<nil>") {
			return nil
		}
		return []string{str}
	}
}

func defaultLabelForKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) == 1 {
		return strings.ToUpper(key)
	}
	return strings.ToUpper(key[:1]) + key[1:]
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

func (cfg VanityNSRuntimeConfig) ZoneFQDN() string {
	return joinLabels(cfg.Label, cfg.BaseDomain)
}

func sanitizeDNSLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(label))
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			builder.WriteRune(r)
		}
	}
	sanitized := strings.Trim(builder.String(), "-")
	if len(sanitized) > 63 {
		sanitized = sanitized[:63]
	}
	return sanitized
}

func sanitizeDomain(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	input = strings.Trim(input, ".")
	if input == "" {
		return ""
	}
	parts := strings.Split(input, ".")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		label := sanitizeDNSLabel(part)
		if label == "" {
			continue
		}
		clean = append(clean, label)
	}
	return strings.Join(clean, ".")
}

func joinLabels(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(strings.ToLower(part), ".")
		if part == "" {
			continue
		}
		clean = append(clean, part)
	}
	if len(clean) == 0 {
		return ""
	}
	return strings.Join(clean, ".")
}

func selectNameServersForDomain(domain string, nsList []infra.NameServer, count int) []infra.NameServer {
	if count <= 0 {
		return nil
	}
	type candidate struct {
		ns    infra.NameServer
		score uint64
	}
	candidates := make([]candidate, 0, len(nsList))
	for _, ns := range nsList {
		ip := strings.TrimSpace(ns.IPv4)
		if ip == "" {
			continue
		}
		key := fmt.Sprintf("%s|%s", domain, strings.ToLower(strings.TrimSpace(ns.FQDN)))
		sum := sha256.Sum256([]byte(key))
		score := binary.BigEndian.Uint64(sum[:8])
		candidates = append(candidates, candidate{ns: ns, score: score})
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return strings.Compare(strings.ToLower(candidates[i].ns.FQDN), strings.ToLower(candidates[j].ns.FQDN)) < 0
		}
		return candidates[i].score < candidates[j].score
	})
	if count > len(candidates) {
		count = len(candidates)
	}
	selected := make([]infra.NameServer, 0, count)
	for i := 0; i < count; i++ {
		selected = append(selected, candidates[i].ns)
	}
	return selected
}

func hashedVanityLabel(domain string, nsFQDN string, idx int, length int) string {
	if length <= 0 {
		length = 8
	}
	payload := fmt.Sprintf("%s|%s|%d|vanity", domain, strings.ToLower(strings.TrimSpace(nsFQDN)), idx)
	sum := sha256.Sum256([]byte(payload))
	hexed := hex.EncodeToString(sum[:])
	if length > len(hexed) {
		length = len(hexed)
	}
	return fmt.Sprintf("ns-%s", hexed[:length])
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
