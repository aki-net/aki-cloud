package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

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
	nodeID := os.Getenv("NODE_ID")
	nodeName := os.Getenv("NODE_NAME")
	if nodeID == "" {
		return nil, fmt.Errorf("NODE_ID must be provided")
	}
	if nodeName == "" {
		return nil, fmt.Errorf("NODE_NAME must be provided")
	}

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

	openRestyEnabled, err := getEnvBool("ENABLE_OPENRESTY", true)
	if err != nil {
		return nil, fmt.Errorf("invalid ENABLE_OPENRESTY: %w", err)
	}
	coreDNSEnabled, err := getEnvBool("ENABLE_COREDNS", true)
	if err != nil {
		return nil, fmt.Errorf("invalid ENABLE_COREDNS: %w", err)
	}

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

	return &Config{
		DataDir:                dataDir,
		Port:                   port,
		ClusterSecretFile:      clusterSecretFile,
		NodeID:                 nodeID,
		NodeName:               nodeName,
		EnableOpenResty:        openRestyEnabled,
		EnableCoreDNS:          coreDNSEnabled,
		JWTSecret:              bytesTrim(jwtSecret),
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
