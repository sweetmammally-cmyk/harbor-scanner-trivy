package config

import (
	"github.com/caarlos0/env/v6"
)

// Config holds the settings of the direct scan API (v2).
type Config struct {
	Enabled bool `env:"SCANNER_V2_API_ENABLED" envDefault:"false"`
}

func GetConfig() (Config, error) {
	var cfg Config
	err := env.Parse(&cfg)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}
