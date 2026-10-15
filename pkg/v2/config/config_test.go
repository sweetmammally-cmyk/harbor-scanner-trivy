package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Envs map[string]string

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedError  bool
		expectedConfig Config
	}{
		{
			name:           "Should disable v2 API by default",
			expectedConfig: Config{Enabled: false},
		},
		{
			name: "Should enable v2 API when the flag is true",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "true",
			},
			expectedConfig: Config{Enabled: true},
		},
		{
			name: "Should return error when the flag is not a boolean",
			envs: Envs{
				"SCANNER_V2_API_ENABLED": "yes please",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envs {
				t.Setenv(k, v)
			}

			cfg, err := GetConfig()
			if tc.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedConfig, cfg)
		})
	}
}
