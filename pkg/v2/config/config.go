package config

import (
	"errors"
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

	// DBCheckInterval and the source lists are parsed in later steps.
	DBCheckInterval string `env:"SCANNER_DB_CHECK_INTERVAL"`
	DBSources       string `env:"SCANNER_DB_SOURCES"`
	JavaDBSources   string `env:"SCANNER_JAVA_DB_SOURCES"`

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

func GetConfig() (Config, error) {
	var cfg Config
	err := env.Parse(&cfg)
	if err != nil {
		return cfg, err
	}

	if cfg.Enabled {
		if cfg.MongoURI == "" {
			return cfg, errors.New("SCANNER_MONGO_URI is required when SCANNER_V2_API_ENABLED is true")
		}
		if cfg.MongoDB == "" {
			return cfg, errors.New("SCANNER_MONGO_DB is required when SCANNER_V2_API_ENABLED is true")
		}
	}

	return cfg, nil
}
