package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

// Config holds the settings of the direct scan API (v2).
// See docs/direct-scan/DEMAND.md section 11.
type Config struct {
	Enabled   bool   `env:"SCANNER_V2_API_ENABLED" envDefault:"false"`
	AuthToken string `env:"SCANNER_V2_AUTH_TOKEN"`

	MongoURI string `env:"SCANNER_MONGO_URI"`
	MongoDB  string `env:"SCANNER_MONGO_DB"`

	RegistryURL      string `env:"SCANNER_REGISTRY_URL"`
	RegistryUsername string `env:"SCANNER_REGISTRY_USERNAME"`
	RegistryPassword string `env:"SCANNER_REGISTRY_PASSWORD"`

	// DBCheckInterval is read from SCANNER_DB_CHECK_INTERVAL by GetConfig,
	// because it accepts days ("1d") and falls back to 3h when unset or invalid.
	DBCheckInterval time.Duration

	// DBSources and JavaDBSources are read from SCANNER_DB_SOURCES and
	// SCANNER_JAVA_DB_SOURCES by GetConfig, see ParseDBSources.
	DBSources     []DBSource
	JavaDBSources []DBSource

	// Seed DBs baked into the image, used when no DB is installed yet. A missing directory means no seed.
	DBSeedDir     string `env:"SCANNER_DB_SEED_DIR" envDefault:"/home/scanner/seed/db"`
	JavaDBSeedDir string `env:"SCANNER_JAVA_DB_SEED_DIR" envDefault:"/home/scanner/seed/java-db"`

	PrecheckTimeoutDNS      time.Duration `env:"SCANNER_PRECHECK_TIMEOUT_DNS" envDefault:"5s"`
	PrecheckTimeoutConnect  time.Duration `env:"SCANNER_PRECHECK_TIMEOUT_CONNECT" envDefault:"5s"`
	PrecheckTimeoutTLS      time.Duration `env:"SCANNER_PRECHECK_TIMEOUT_TLS" envDefault:"5s"`
	PrecheckTimeoutHTTP     time.Duration `env:"SCANNER_PRECHECK_TIMEOUT_HTTP" envDefault:"10s"`
	PrecheckTimeoutManifest time.Duration `env:"SCANNER_PRECHECK_TIMEOUT_MANIFEST" envDefault:"10s"`
	PrecheckTimeoutTotal    time.Duration `env:"SCANNER_PRECHECK_TIMEOUT_TOTAL" envDefault:"30s"`

	DBDownloadStallTimeout time.Duration `env:"SCANNER_DB_DOWNLOAD_STALL_TIMEOUT" envDefault:"30s"`
	DBDownloadTimeout      time.Duration `env:"SCANNER_DB_DOWNLOAD_TIMEOUT" envDefault:"15m"`
	DBMaxAgeDefault        time.Duration `env:"SCANNER_DB_MAX_AGE_DEFAULT" envDefault:"6h"`

	QueueWorkers   int           `env:"SCANNER_QUEUE_WORKERS" envDefault:"1"`
	QueueMaxLength int           `env:"SCANNER_QUEUE_MAX_LENGTH" envDefault:"100"`
	ScanTimeout    time.Duration `env:"SCANNER_SCAN_TIMEOUT" envDefault:"10m"`
}

// FallbackDBCheckInterval is used when SCANNER_DB_CHECK_INTERVAL is unset or invalid.
const FallbackDBCheckInterval = 3 * time.Hour

func GetConfig() (Config, error) {
	var cfg Config
	err := env.Parse(&cfg)
	if err != nil {
		return cfg, err
	}

	value := os.Getenv("SCANNER_DB_CHECK_INTERVAL")
	interval, err := ParseDuration(value)
	if err != nil || interval <= 0 {
		slog.Warn("using fallback interval",
			slog.String("env", "SCANNER_DB_CHECK_INTERVAL"),
			slog.String("value", value),
			slog.String("fallback", FallbackDBCheckInterval.String()),
		)
		interval = FallbackDBCheckInterval
	}
	cfg.DBCheckInterval = interval

	cfg.DBSources, err = ParseDBSources(os.Getenv("SCANNER_DB_SOURCES"))
	if err != nil {
		return cfg, fmt.Errorf("parsing SCANNER_DB_SOURCES: %w", err)
	}
	cfg.JavaDBSources, err = ParseDBSources(os.Getenv("SCANNER_JAVA_DB_SOURCES"))
	if err != nil {
		return cfg, fmt.Errorf("parsing SCANNER_JAVA_DB_SOURCES: %w", err)
	}

	if cfg.Enabled {
		if cfg.MongoURI == "" {
			return cfg, errors.New("SCANNER_MONGO_URI is required when SCANNER_V2_API_ENABLED is true")
		}
		if cfg.MongoDB == "" {
			return cfg, errors.New("SCANNER_MONGO_DB is required when SCANNER_V2_API_ENABLED is true")
		}
		if len(cfg.DBSources) == 0 {
			return cfg, errors.New("SCANNER_DB_SOURCES is required when SCANNER_V2_API_ENABLED is true")
		}
	}

	return cfg, nil
}

// ParseDuration parses a Go duration such as "90m" or "3h", and also whole days such as "1d".
func ParseDuration(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}
