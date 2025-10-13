package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config captures runtime configuration for the backend service.
type LoginLockoutTier struct {
	Failures     int
	LockDuration time.Duration
}

// Config captures runtime configuration for the backend service.
type Config struct {
	DataDir                string
	Port                   int
	ClusterSecretFile      string
	NodeID                 string
	NodeName               string
	EnableOpenResty        bool
	EnableCoreDNS          bool
	JWTSecret              []byte
	NSLabel                string
	NSBaseDomain           string
	SyncInterval           time.Duration
	ReloadDebounce         time.Duration
	HealthInterval         time.Duration
	HealthDialTimeout      time.Duration
	HealthFailureThreshold int
	HealthFailureDecay     time.Duration
	ACMEEnabled            bool
	ACMEDirectory          string
	ACMEEmail              string
	ACMERetryAfter         time.Duration
	ACMELockTTL            time.Duration
	ACMERenewBefore        time.Duration
	TLSRecommender         bool
	ACMEMaxPerCycle        int
	ACMEWindowLimit        int
	ACMEWindow             time.Duration
	ClusterSecret          []byte
	APIRatePerMinute       int
	APIRateBurst           int
	LoginRatePerMinute     int
	LoginRateBurst         int
	MaxRequestBodyBytes    int64
	MaxHeaderBytes         int
	IdleTimeout            time.Duration
	LoginLockTiers         []LoginLockoutTier
	LoginFailureReset      time.Duration
}

// Load reads configuration values from environment variables with sensible defaults.
func Load() (*Config, error) {
	dataDir := getEnvDefault("DATA_DIR", "./data")
	if dataDir == "" {
		return nil, fmt.Errorf("DATA_DIR must be provided")
	}

	port, err := getEnvInt("PORT", 8080)
	if err != nil {
		return nil, fmt.Errorf("invalid PORT: %w", err)
	}

	clusterSecretFile := getEnvDefault("CLUSTER_SECRET_FILE", fmt.Sprintf("%s/cluster/secret", dataDir))
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return nil, fmt.Errorf("NODE_NAME must be provided")
	}

	// Read cluster secret for NODE_ID generation
	clusterSecretBytes, err := os.ReadFile(clusterSecretFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read cluster secret file: %w", err)
	}
	clusterSecret := strings.TrimSpace(string(clusterSecretBytes))

	// Generate NODE_ID deterministically from cluster_secret + node_name
	data := fmt.Sprintf("%s:%s", clusterSecret, strings.ToLower(nodeName))
	hash := sha256.Sum256([]byte(data))
	hashStr := hex.EncodeToString(hash[:])

	// Format as UUID-like string
	nodeID := fmt.Sprintf("%s-%s-%s-%s-%s",
		hashStr[0:8],
		hashStr[8:12],
		hashStr[12:16],
		hashStr[16:20],
		hashStr[20:32],
	)

	jwtSecretFile := getEnvDefault("JWT_SECRET_FILE", fmt.Sprintf("%s/cluster/jwt_secret", dataDir))
	jwtSecret, err := os.ReadFile(jwtSecretFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read JWT secret file: %w", err)
	}

	syncIntervalSeconds, err := getEnvInt("SYNC_INTERVAL_SECONDS", 15)
	if err != nil {
		return nil, fmt.Errorf("invalid SYNC_INTERVAL_SECONDS: %w", err)
	}

	reloadDebounceMillis, err := getEnvInt("RELOAD_DEBOUNCE_MS", 1500)
	if err != nil {
		return nil, fmt.Errorf("invalid RELOAD_DEBOUNCE_MS: %w", err)
	}

	// OpenResty and CoreDNS run always
	openRestyEnabled := true
	coreDNSEnabled := true

	// NS configuration
	nsLabel := getEnvDefault("NS_LABEL", "dns")
	nsBaseDomain := getEnvDefault("NS_BASE_DOMAIN", "aki.cloud")

	healthIntervalSeconds, err := getEnvInt("HEALTH_CHECK_INTERVAL_SECONDS", 30)
	if err != nil {
		return nil, fmt.Errorf("invalid HEALTH_CHECK_INTERVAL_SECONDS: %w", err)
	}
	healthDialTimeoutMillis, err := getEnvInt("HEALTH_DIAL_TIMEOUT_MS", 2500)
	if err != nil {
		return nil, fmt.Errorf("invalid HEALTH_DIAL_TIMEOUT_MS: %w", err)
	}
	healthFailureThreshold, err := getEnvInt("HEALTH_FAILURE_THRESHOLD", 3)
	if err != nil {
		return nil, fmt.Errorf("invalid HEALTH_FAILURE_THRESHOLD: %w", err)
	}
	healthFailureDecaySeconds, err := getEnvInt("HEALTH_FAILURE_DECAY_SECONDS", 300)
	if err != nil {
		return nil, fmt.Errorf("invalid HEALTH_FAILURE_DECAY_SECONDS: %w", err)
	}

	acmeEnabled, err := getEnvBool("SSL_ACME_ENABLED", true)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_ENABLED: %w", err)
	}
	acmeDirectory := getEnvDefault("SSL_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory")
	acmeEmail := os.Getenv("SSL_ACME_EMAIL")
	acmeRetrySeconds, err := getEnvInt("SSL_ACME_RETRY_SECONDS", 900)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_RETRY_SECONDS: %w", err)
	}
	acmeLockSeconds, err := getEnvInt("SSL_ACME_LOCK_TTL_SECONDS", 600)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_LOCK_TTL_SECONDS: %w", err)
	}
	acmeRenewDays, err := getEnvInt("SSL_ACME_RENEW_BEFORE_DAYS", 30)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_RENEW_BEFORE_DAYS: %w", err)
	}
	tlsRecommender, err := getEnvBool("SSL_RECOMMENDER_ENABLED", true)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_RECOMMENDER_ENABLED: %w", err)
	}
	acmeMaxPerCycle, err := getEnvInt("SSL_ACME_MAX_PER_CYCLE", 25)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_MAX_PER_CYCLE: %w", err)
	}
	acmeWindowLimit, err := getEnvInt("SSL_ACME_WINDOW_LIMIT", 200)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_WINDOW_LIMIT: %w", err)
	}
	acmeWindowSeconds, err := getEnvInt("SSL_ACME_WINDOW_SECONDS", 3600)
	if err != nil {
		return nil, fmt.Errorf("invalid SSL_ACME_WINDOW_SECONDS: %w", err)
	}
	loginLockTierSpec := strings.TrimSpace(os.Getenv("LOGIN_LOCK_TIERS"))
	loginLockTiers, err := parseLockoutTiers(loginLockTierSpec)
	if err != nil {
		return nil, fmt.Errorf("invalid LOGIN_LOCK_TIERS: %w", err)
	}
	if len(loginLockTiers) == 0 {
		loginLockTiers = defaultLockoutTiers()
	}
	loginFailureResetSeconds, err := getEnvInt("LOGIN_FAILURE_RESET_SECONDS", 86400)
	if err != nil {
		return nil, fmt.Errorf("invalid LOGIN_FAILURE_RESET_SECONDS: %w", err)
	}
	apiRatePerMinute, err := getEnvInt("API_RATE_LIMIT_PER_MIN", 300)
	if err != nil {
		return nil, fmt.Errorf("invalid API_RATE_LIMIT_PER_MIN: %w", err)
	}
	apiRateBurst, err := getEnvInt("API_RATE_LIMIT_BURST", 450)
	if err != nil {
		return nil, fmt.Errorf("invalid API_RATE_LIMIT_BURST: %w", err)
	}
	loginRatePerMinute, err := getEnvInt("LOGIN_RATE_LIMIT_PER_MIN", 10)
	if err != nil {
		return nil, fmt.Errorf("invalid LOGIN_RATE_LIMIT_PER_MIN: %w", err)
	}
	loginRateBurst, err := getEnvInt("LOGIN_RATE_LIMIT_BURST", 20)
	if err != nil {
		return nil, fmt.Errorf("invalid LOGIN_RATE_LIMIT_BURST: %w", err)
	}
	maxRequestBodyBytes, err := getEnvInt64("API_MAX_BODY_BYTES", 1<<20)
	if err != nil {
		return nil, fmt.Errorf("invalid API_MAX_BODY_BYTES: %w", err)
	}
	maxHeaderBytes, err := getEnvInt("API_MAX_HEADER_BYTES", 16384)
	if err != nil {
		return nil, fmt.Errorf("invalid API_MAX_HEADER_BYTES: %w", err)
	}
	idleTimeoutSeconds, err := getEnvInt("API_IDLE_TIMEOUT_SECONDS", 60)
	if err != nil {
		return nil, fmt.Errorf("invalid API_IDLE_TIMEOUT_SECONDS: %w", err)
	}

	return &Config{
		DataDir:                dataDir,
		Port:                   port,
		ClusterSecretFile:      clusterSecretFile,
		NodeID:                 nodeID,
		NodeName:               nodeName,
		EnableOpenResty:        openRestyEnabled,
		EnableCoreDNS:          coreDNSEnabled,
		JWTSecret:              bytesTrim(jwtSecret),
		NSLabel:                nsLabel,
		NSBaseDomain:           nsBaseDomain,
		SyncInterval:           time.Duration(syncIntervalSeconds) * time.Second,
		ReloadDebounce:         time.Duration(reloadDebounceMillis) * time.Millisecond,
		HealthInterval:         time.Duration(healthIntervalSeconds) * time.Second,
		HealthDialTimeout:      time.Duration(healthDialTimeoutMillis) * time.Millisecond,
		HealthFailureThreshold: healthFailureThreshold,
		HealthFailureDecay:     time.Duration(healthFailureDecaySeconds) * time.Second,
		ACMEEnabled:            acmeEnabled,
		ACMEDirectory:          acmeDirectory,
		ACMEEmail:              acmeEmail,
		ACMERetryAfter:         time.Duration(acmeRetrySeconds) * time.Second,
		ACMELockTTL:            time.Duration(acmeLockSeconds) * time.Second,
		ACMERenewBefore:        time.Duration(acmeRenewDays) * 24 * time.Hour,
		TLSRecommender:         tlsRecommender,
		ACMEMaxPerCycle:        acmeMaxPerCycle,
		ACMEWindowLimit:        acmeWindowLimit,
		ACMEWindow:             time.Duration(acmeWindowSeconds) * time.Second,
		ClusterSecret:          bytesTrim([]byte(clusterSecret)),
		APIRatePerMinute:       apiRatePerMinute,
		APIRateBurst:           apiRateBurst,
		LoginRatePerMinute:     loginRatePerMinute,
		LoginRateBurst:         loginRateBurst,
		MaxRequestBodyBytes:    maxRequestBodyBytes,
		MaxHeaderBytes:         maxHeaderBytes,
		IdleTimeout:            time.Duration(idleTimeoutSeconds) * time.Second,
		LoginLockTiers:         loginLockTiers,
		LoginFailureReset:      time.Duration(loginFailureResetSeconds) * time.Second,
	}, nil
}

func getEnvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getEnvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	return strconv.Atoi(v)
}

func getEnvInt64(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return i, nil
}

func getEnvBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", v)
	}
}

func defaultLockoutTiers() []LoginLockoutTier {
	return []LoginLockoutTier{
		{Failures: 5, LockDuration: 30 * time.Second},
		{Failures: 10, LockDuration: 5 * time.Minute},
		{Failures: 20, LockDuration: 30 * time.Minute},
		{Failures: 50, LockDuration: 2 * time.Hour},
		{Failures: 100, LockDuration: 24 * time.Hour},
	}
}

func parseLockoutTiers(spec string) ([]LoginLockoutTier, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return defaultLockoutTiers(), nil
	}
	if strings.EqualFold(spec, "none") {
		return []LoginLockoutTier{}, nil
	}
	parts := strings.Split(spec, ",")
	tiers := make([]LoginLockoutTier, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		segments := strings.Split(part, ":")
		if len(segments) != 2 {
			return nil, fmt.Errorf("invalid tier definition %q", part)
		}
		failuresStr := strings.TrimSpace(segments[0])
		durationStr := strings.TrimSpace(segments[1])
		failures, err := strconv.Atoi(failuresStr)
		if err != nil {
			return nil, fmt.Errorf("invalid tier threshold %q: %w", failuresStr, err)
		}
		if failures <= 0 {
			continue
		}
		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			return nil, fmt.Errorf("invalid tier duration %q: %w", durationStr, err)
		}
		if duration <= 0 {
			continue
		}
		tiers = append(tiers, LoginLockoutTier{
			Failures:     failures,
			LockDuration: duration,
		})
	}
	sort.Slice(tiers, func(i, j int) bool {
		return tiers[i].Failures < tiers[j].Failures
	})
	return tiers, nil
}

func bytesTrim(v []byte) []byte {
	for len(v) > 0 {
		switch v[len(v)-1] {
		case '\n', '\r', '\t', ' ':
			v = v[:len(v)-1]
		default:
			return v
		}
	}
	return v
}
