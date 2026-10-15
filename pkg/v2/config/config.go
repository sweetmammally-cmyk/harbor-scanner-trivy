package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
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

	// MongoURI may hold a password: never log it or put it in errors.
	MongoURI string `env:"SCANNER_MONGO_URI"`
	// InstanceID names this scanner instance in db_state and db_checks.
	// GetConfig sets it to the hostname when SCANNER_INSTANCE_ID is unset.
	InstanceID string `env:"SCANNER_INSTANCE_ID"`
	MongoDB    string `env:"SCANNER_MONGO_DB"`

	MongoConnectTimeout         time.Duration `env:"SCANNER_MONGO_CONNECT_TIMEOUT" envDefault:"5s"`
	MongoServerSelectionTimeout time.Duration `env:"SCANNER_MONGO_SERVER_SELECTION_TIMEOUT" envDefault:"5s"`
	MongoOperationTimeout       time.Duration `env:"SCANNER_MONGO_OPERATION_TIMEOUT" envDefault:"10s"`
	// DBChecksRetention and DBStateRetention are read from SCANNER_DB_CHECKS_RETENTION
	// and SCANNER_DB_STATE_RETENTION by GetConfig ("30d" style).
	DBChecksRetention time.Duration
	DBStateRetention  time.Duration

	RegistryURL      string `env:"SCANNER_REGISTRY_URL"`
	RegistryUsername string `env:"SCANNER_REGISTRY_USERNAME"`
	RegistryPassword string `env:"SCANNER_REGISTRY_PASSWORD"`
	// RegistryTimeout bounds each registry request (HEAD, GET, token).
	RegistryTimeout time.Duration `env:"SCANNER_REGISTRY_TIMEOUT" envDefault:"15s"`

	// DBCheckInterval is read from SCANNER_DB_CHECK_INTERVAL by GetConfig,
	// because it accepts days ("1d") and falls back to 3h when unset or invalid.
	DBCheckInterval time.Duration
	// DBRetryInterval replaces DBCheckInterval while the DB mode is degraded.
	DBRetryInterval time.Duration `env:"SCANNER_DB_RETRY_INTERVAL" envDefault:"15m"`

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
	JavaDBDownloadTimeout  time.Duration `env:"SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT" envDefault:"45m"`
	DBMaxAgeDefault        time.Duration `env:"SCANNER_DB_MAX_AGE_DEFAULT" envDefault:"6h"`
	// On-demand refresh before a scan (DEMAND section 7.4).
	OnDemandRefreshWait   time.Duration `env:"SCANNER_ONDEMAND_REFRESH_WAIT" envDefault:"60s"`
	OnDemandRefreshMinGap time.Duration `env:"SCANNER_ONDEMAND_REFRESH_MIN_GAP" envDefault:"60s"`
	// DBAgeWarn is read from SCANNER_DB_AGE_WARN by GetConfig, because it accepts days ("7d").
	DBAgeWarn time.Duration

	QueueWorkers int `env:"SCANNER_QUEUE_WORKERS" envDefault:"1"`
	// QueueLease is the lease of a running scan; the heartbeat runs every third of it.
	QueueLease time.Duration `env:"SCANNER_QUEUE_LEASE" envDefault:"60s"`
	// QueueMaxAttempts is how many lease losses a scan may have before it fails.
	QueueMaxAttempts int `env:"SCANNER_QUEUE_MAX_ATTEMPTS" envDefault:"3"`
	// QueuePollInterval is how often idle workers look for work (with jitter).
	QueuePollInterval time.Duration `env:"SCANNER_QUEUE_POLL_INTERVAL" envDefault:"2s"`
	// ShutdownGrace is how long running scans may finish after SIGTERM.
	ShutdownGrace  time.Duration `env:"SCANNER_SHUTDOWN_GRACE" envDefault:"30s"`
	QueueMaxLength int           `env:"SCANNER_QUEUE_MAX_LENGTH" envDefault:"100"`
	ScanTimeout    time.Duration `env:"SCANNER_SCAN_TIMEOUT" envDefault:"10m"`
	// ScanPlatform is the platform scanned in a multi-platform image (Trivy --platform).
	ScanPlatform string `env:"SCANNER_SCAN_PLATFORM" envDefault:"linux/amd64"`
	// ScanMaxOutput is the largest Trivy JSON output read, in bytes (256 MiB).
	ScanMaxOutput int64 `env:"SCANNER_SCAN_MAX_OUTPUT" envDefault:"268435456"`
	// ScanMaxFindings is the most findings stored per scan.
	ScanMaxFindings int `env:"SCANNER_SCAN_MAX_FINDINGS" envDefault:"10000"`
}

// scanPlatformPattern is os/arch or os/arch/variant, for example linux/arm64/v8.
var scanPlatformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)

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

	ageWarn := os.Getenv("SCANNER_DB_AGE_WARN")
	if ageWarn == "" {
		ageWarn = "7d"
	}
	cfg.DBAgeWarn, err = ParseDuration(ageWarn)
	if err != nil || cfg.DBAgeWarn <= 0 {
		return cfg, fmt.Errorf("SCANNER_DB_AGE_WARN: invalid duration %q", ageWarn)
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = os.Hostname()
		if err != nil {
			return cfg, fmt.Errorf("SCANNER_INSTANCE_ID is unset and the hostname is unknown: %w", err)
		}
		slog.Warn("SCANNER_INSTANCE_ID is not set, using the hostname; set it explicitly (for example in compose) "+
			"so the instance keeps its DB state when its container is recreated",
			slog.String("instance_id", cfg.InstanceID))
	}

	retention := os.Getenv("SCANNER_DB_CHECKS_RETENTION")
	if retention == "" {
		retention = "30d"
	}
	cfg.DBChecksRetention, err = ParseDuration(retention)
	if err != nil || cfg.DBChecksRetention < time.Second {
		return cfg, fmt.Errorf("SCANNER_DB_CHECKS_RETENTION: invalid duration %q", retention)
	}

	stateRetention := os.Getenv("SCANNER_DB_STATE_RETENTION")
	if stateRetention == "" {
		stateRetention = "7d"
	}
	cfg.DBStateRetention, err = ParseDuration(stateRetention)
	if err != nil {
		return cfg, fmt.Errorf("SCANNER_DB_STATE_RETENTION: invalid duration %q", stateRetention)
	}
	// A live instance writes its state at least once per check interval.
	if cfg.DBStateRetention < 2*cfg.DBCheckInterval {
		return cfg, fmt.Errorf("SCANNER_DB_STATE_RETENTION (%s) must be at least twice SCANNER_DB_CHECK_INTERVAL (%s)",
			cfg.DBStateRetention, cfg.DBCheckInterval)
	}

	if !scanPlatformPattern.MatchString(cfg.ScanPlatform) {
		return cfg, fmt.Errorf("SCANNER_SCAN_PLATFORM %q must look like os/arch or os/arch/variant", cfg.ScanPlatform)
	}

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
