package config

import (
	"bytes"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Envs map[string]string

// defaultConfig is the config with no env vars set.
var defaultConfig = Config{
	ScanMaxOutput:               256 << 20,
	ScanMaxFindings:             10000,
	RegistryTimeout:             15 * time.Second,
	DBStateRetention:            7 * 24 * time.Hour,
	InstanceID:                  hostname(),
	DBChecksRetention:           30 * 24 * time.Hour,
	MongoConnectTimeout:         5 * time.Second,
	MongoServerSelectionTimeout: 5 * time.Second,
	MongoOperationTimeout:       10 * time.Second,
	OnDemandRefreshWait:         60 * time.Second,
	OnDemandRefreshMinGap:       60 * time.Second,
	DBRetryInterval:             15 * time.Minute,
	DBAgeWarn:                   7 * 24 * time.Hour,
	DBSeedDir:                   "/home/scanner/seed/db",
	JavaDBSeedDir:               "/home/scanner/seed/java-db",
	DBCheckInterval:             3 * time.Hour,
	PrecheckTimeoutDNS:          5 * time.Second,
	PrecheckTimeoutConnect:      5 * time.Second,
	PrecheckTimeoutTLS:          5 * time.Second,
	PrecheckTimeoutHTTP:         10 * time.Second,
	PrecheckTimeoutManifest:     10 * time.Second,
	PrecheckTimeoutTotal:        30 * time.Second,
	DBDownloadStallTimeout:      30 * time.Second,
	DBDownloadTimeout:           15 * time.Minute,
	JavaDBDownloadTimeout:       45 * time.Minute,
	DBMaxAgeDefault:             6 * time.Hour,
	QueueWorkers:                1,
	QueueMaxLength:              100,
	ScanTimeout:                 10 * time.Minute,
}

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedError  string
		expectedConfig Config
	}{
		{
			name:           "Should disable v2 API and use defaults when nothing is set",
			expectedConfig: defaultConfig,
		},
		{
			name: "Should not require Mongo settings when v2 API is disabled",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "false",
			},
			expectedConfig: defaultConfig,
		},
		{
			name: "Should return error when the flag is not a boolean",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "yes please",
			},
			expectedError: `parse error on field "Enabled"`,
		},
		{
			name: "Should return error when v2 API is enabled without SCANNER_MONGO_URI",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "true",
				"SCANNER_MONGO_DB":       "scanner",
			},
			expectedError: "SCANNER_MONGO_URI is required when SCANNER_V2_API_ENABLED is true",
		},
		{
			name: "Should return error when v2 API is enabled without SCANNER_MONGO_DB",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "true",
				"SCANNER_MONGO_URI":      "mongodb://mongo:27017",
			},
			expectedError: "SCANNER_MONGO_DB is required when SCANNER_V2_API_ENABLED is true",
		},
		{
			name: "Should return error when v2 API is enabled without SCANNER_DB_SOURCES",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "true",
				"SCANNER_MONGO_URI":      "mongodb://mongo:27017",
				"SCANNER_MONGO_DB":       "scanner",
			},
			expectedError: "SCANNER_DB_SOURCES is required when SCANNER_V2_API_ENABLED is true",
		},
		{
			name: "Should return error when v2 API is enabled with blank SCANNER_DB_SOURCES",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "true",
				"SCANNER_MONGO_URI":      "mongodb://mongo:27017",
				"SCANNER_MONGO_DB":       "scanner",
				"SCANNER_DB_SOURCES":     "  ",
			},
			expectedError: "SCANNER_DB_SOURCES is required when SCANNER_V2_API_ENABLED is true",
		},
		{
			name: "Should return error when SCANNER_DB_AGE_WARN is invalid",
			envs: Envs{
				"SCANNER_DB_AGE_WARN": "a week",
			},
			expectedError: `SCANNER_DB_AGE_WARN: invalid duration "a week"`,
		},
		{
			name: "Should return error when SCANNER_DB_AGE_WARN is zero",
			envs: Envs{
				"SCANNER_DB_AGE_WARN": "0d",
			},
			expectedError: `SCANNER_DB_AGE_WARN: invalid duration "0d"`,
		},
		{
			name: "Should return error when SCANNER_DB_CHECKS_RETENTION is invalid",
			envs: Envs{
				"SCANNER_DB_CHECKS_RETENTION": "forever",
			},
			expectedError: `SCANNER_DB_CHECKS_RETENTION: invalid duration "forever"`,
		},
		{
			name: "Should return error when SCANNER_DB_CHECKS_RETENTION is under a second",
			envs: Envs{
				"SCANNER_DB_CHECKS_RETENTION": "500ms",
			},
			expectedError: `SCANNER_DB_CHECKS_RETENTION: invalid duration "500ms"`,
		},
		{
			name: "Should return error when SCANNER_DB_STATE_RETENTION is invalid",
			envs: Envs{
				"SCANNER_DB_STATE_RETENTION": "a week",
			},
			expectedError: `SCANNER_DB_STATE_RETENTION: invalid duration "a week"`,
		},
		{
			name: "Should return error when SCANNER_DB_STATE_RETENTION is shorter than twice the check interval",
			envs: Envs{
				"SCANNER_DB_CHECK_INTERVAL":  "1d",
				"SCANNER_DB_STATE_RETENTION": "36h",
			},
			expectedError: "SCANNER_DB_STATE_RETENTION (36h0m0s) must be at least twice SCANNER_DB_CHECK_INTERVAL (24h0m0s)",
		},
		{
			name: "Should return error when a duration is invalid",
			envs: Envs{
				"SCANNER_SCAN_TIMEOUT": "ten minutes",
			},
			expectedError: `parse error on field "ScanTimeout"`,
		},
		{
			name: "Should return error when SCANNER_DB_SOURCES is invalid",
			envs: Envs{
				"SCANNER_DB_SOURCES": "ghcr.io/aquasecurity/trivy-db:2|ftp://user:s3cret@proxy:21",
			},
			expectedError: "parsing SCANNER_DB_SOURCES: source 1: route must be direct, http://host:port or socks5://host:port",
		},
		{
			name: "Should return error when SCANNER_JAVA_DB_SOURCES is invalid",
			envs: Envs{
				"SCANNER_JAVA_DB_SOURCES": "ghcr.io/aquasecurity/trivy-java-db:1",
			},
			expectedError: "parsing SCANNER_JAVA_DB_SOURCES: source 1: expected repository|route or repository|route|options",
		},
		{
			name: "Should read all values from env",
			envs: Envs{
				"SCANNER_V2_API_ENABLED":                 "true",
				"SCANNER_V2_AUTH_TOKEN":                  "token",
				"SCANNER_MONGO_URI":                      "mongodb://mongo:27017",
				"SCANNER_INSTANCE_ID":                    "scanner-1",
				"SCANNER_MONGO_DB":                       "scanner",
				"SCANNER_MONGO_CONNECT_TIMEOUT":          "1s",
				"SCANNER_MONGO_SERVER_SELECTION_TIMEOUT": "2s",
				"SCANNER_MONGO_OPERATION_TIMEOUT":        "3s",
				"SCANNER_DB_CHECKS_RETENTION":            "7d",
				"SCANNER_DB_STATE_RETENTION":             "3d",
				"SCANNER_REGISTRY_URL":                   "https://harbor.local",
				"SCANNER_REGISTRY_USERNAME":              "robot$scanner",
				"SCANNER_REGISTRY_PASSWORD":              "s3cret",
				"SCANNER_REGISTRY_TIMEOUT":               "20s",
				"SCANNER_DB_CHECK_INTERVAL":              "1d",
				"SCANNER_DB_RETRY_INTERVAL":              "5m",
				"SCANNER_DB_SOURCES":                     "mirror.local/aquasec/trivy-db:2|direct|allow-http1,ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080",
				"SCANNER_JAVA_DB_SOURCES":                "mirror.local/aquasec/trivy-java-db:1|direct",
				"SCANNER_DB_SEED_DIR":                    "/seed/db",
				"SCANNER_JAVA_DB_SEED_DIR":               "/seed/java-db",
				"SCANNER_PRECHECK_TIMEOUT_DNS":           "1s",
				"SCANNER_PRECHECK_TIMEOUT_CONNECT":       "2s",
				"SCANNER_PRECHECK_TIMEOUT_TLS":           "3s",
				"SCANNER_PRECHECK_TIMEOUT_HTTP":          "4s",
				"SCANNER_PRECHECK_TIMEOUT_MANIFEST":      "5s",
				"SCANNER_PRECHECK_TIMEOUT_TOTAL":         "20s",
				"SCANNER_DB_DOWNLOAD_STALL_TIMEOUT":      "10s",
				"SCANNER_DB_DOWNLOAD_TIMEOUT":            "5m",
				"SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT":       "30m",
				"SCANNER_DB_MAX_AGE_DEFAULT":             "3h",
				"SCANNER_DB_AGE_WARN":                    "2d",
				"SCANNER_ONDEMAND_REFRESH_WAIT":          "30s",
				"SCANNER_ONDEMAND_REFRESH_MIN_GAP":       "2m",
				"SCANNER_QUEUE_WORKERS":                  "4",
				"SCANNER_QUEUE_MAX_LENGTH":               "50",
				"SCANNER_SCAN_TIMEOUT":                   "20m",
				"SCANNER_SCAN_MAX_OUTPUT":                "1048576",
				"SCANNER_SCAN_MAX_FINDINGS":              "500",
			},
			expectedConfig: Config{
				Enabled:                     true,
				AuthToken:                   "token",
				MongoURI:                    "mongodb://mongo:27017",
				InstanceID:                  "scanner-1",
				MongoDB:                     "scanner",
				MongoConnectTimeout:         1 * time.Second,
				MongoServerSelectionTimeout: 2 * time.Second,
				MongoOperationTimeout:       3 * time.Second,
				DBChecksRetention:           7 * 24 * time.Hour,
				DBStateRetention:            3 * 24 * time.Hour,
				RegistryURL:                 "https://harbor.local",
				RegistryUsername:            "robot$scanner",
				RegistryPassword:            "s3cret",
				RegistryTimeout:             20 * time.Second,
				DBCheckInterval:             24 * time.Hour,
				DBRetryInterval:             5 * time.Minute,
				DBSources: []DBSource{
					{Repository: "mirror.local/aquasec/trivy-db:2", AllowHTTP1: true},
					{Repository: "ghcr.io/aquasecurity/trivy-db:2", Proxy: &url.URL{Scheme: "socks5", Host: "proxy:1080"}},
				},
				JavaDBSources: []DBSource{
					{Repository: "mirror.local/aquasec/trivy-java-db:1"},
				},
				DBSeedDir:               "/seed/db",
				JavaDBSeedDir:           "/seed/java-db",
				PrecheckTimeoutDNS:      1 * time.Second,
				PrecheckTimeoutConnect:  2 * time.Second,
				PrecheckTimeoutTLS:      3 * time.Second,
				PrecheckTimeoutHTTP:     4 * time.Second,
				PrecheckTimeoutManifest: 5 * time.Second,
				PrecheckTimeoutTotal:    20 * time.Second,
				DBDownloadStallTimeout:  10 * time.Second,
				DBDownloadTimeout:       5 * time.Minute,
				JavaDBDownloadTimeout:   30 * time.Minute,
				DBMaxAgeDefault:         3 * time.Hour,
				DBAgeWarn:               48 * time.Hour,
				OnDemandRefreshWait:     30 * time.Second,
				OnDemandRefreshMinGap:   2 * time.Minute,
				QueueWorkers:            4,
				QueueMaxLength:          50,
				ScanTimeout:             20 * time.Minute,
				ScanMaxOutput:           1 << 20,
				ScanMaxFindings:         500,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envs {
				t.Setenv(k, v)
			}

			cfg, err := GetConfig()
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedConfig, cfg)
		})
	}
}

func TestGetConfig_DBCheckInterval(t *testing.T) {
	testCases := []struct {
		name             string
		value            string
		expectedInterval time.Duration
		expectedWarning  bool
	}{
		{name: "hours", value: "1h", expectedInterval: time.Hour},
		{name: "minutes", value: "90m", expectedInterval: 90 * time.Minute},
		{name: "days", value: "2d", expectedInterval: 48 * time.Hour},
		{name: "unset", value: "", expectedInterval: 3 * time.Hour, expectedWarning: true},
		{name: "invalid", value: "often", expectedInterval: 3 * time.Hour, expectedWarning: true},
		{name: "invalid days", value: "xd", expectedInterval: 3 * time.Hour, expectedWarning: true},
		{name: "zero", value: "0s", expectedInterval: 3 * time.Hour, expectedWarning: true},
		{name: "negative", value: "-1h", expectedInterval: 3 * time.Hour, expectedWarning: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			defaultLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(defaultLogger)

			t.Setenv("SCANNER_DB_CHECK_INTERVAL", tc.value)
			t.Setenv("SCANNER_INSTANCE_ID", "scanner-1") // only the interval may log here

			cfg, err := GetConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedInterval, cfg.DBCheckInterval)
			if tc.expectedWarning {
				assert.Contains(t, logs.String(), "level=WARN")
				assert.Contains(t, logs.String(), "using fallback interval")
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	testCases := []struct {
		value            string
		expectedDuration time.Duration
		expectedError    bool
	}{
		{value: "30s", expectedDuration: 30 * time.Second},
		{value: "3h", expectedDuration: 3 * time.Hour},
		{value: "1h30m", expectedDuration: 90 * time.Minute},
		{value: "1d", expectedDuration: 24 * time.Hour},
		{value: "7d", expectedDuration: 7 * 24 * time.Hour},
		{value: "", expectedError: true},
		{value: "d", expectedError: true},
		{value: "1.5d", expectedError: true},
		{value: "1d2h", expectedError: true},
		{value: "abc", expectedError: true},
	}

	for _, tc := range testCases {
		t.Run(tc.value, func(t *testing.T) {
			duration, err := ParseDuration(tc.value)
			if tc.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedDuration, duration)
		})
	}
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	return name
}

func TestGetConfig_InstanceIDDefaultsToHostname(t *testing.T) {
	t.Setenv("SCANNER_INSTANCE_ID", "")
	var logs bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(defaultLogger)

	cfg, err := GetConfig()

	require.NoError(t, err)
	assert.Equal(t, hostname(), cfg.InstanceID)
	assert.NotEmpty(t, cfg.InstanceID)
	assert.Contains(t, logs.String(), "level=WARN msg=\"SCANNER_INSTANCE_ID is not set, using the hostname")
	assert.Contains(t, logs.String(), "instance_id="+hostname())
}

func TestGetConfig_InstanceIDSetHasNoWarning(t *testing.T) {
	t.Setenv("SCANNER_INSTANCE_ID", "scanner-1")
	t.Setenv("SCANNER_DB_CHECK_INTERVAL", "1h")
	var logs bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(defaultLogger)

	cfg, err := GetConfig()

	require.NoError(t, err)
	assert.Equal(t, "scanner-1", cfg.InstanceID)
	assert.NotContains(t, logs.String(), "SCANNER_INSTANCE_ID")
}
