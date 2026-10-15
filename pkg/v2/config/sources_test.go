package config

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDBSources(t *testing.T) {
	testCases := []struct {
		name            string
		value           string
		expectedSources []string
		expectedError   string
	}{
		{
			name:            "empty",
			value:           "",
			expectedSources: nil,
		},
		{
			name:            "one direct source",
			value:           "mirror.local/aquasec/trivy-db:2|direct",
			expectedSources: []string{"mirror.local/aquasec/trivy-db:2|direct"},
		},
		{
			name:  "ordered pool with every route and spaces",
			value: " mirror.local/aquasec/trivy-db:2|direct , ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080,docker.io/aquasec/trivy-db:2|http://proxy:3128",
			expectedSources: []string{
				"mirror.local/aquasec/trivy-db:2|direct",
				"ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080",
				"docker.io/aquasec/trivy-db:2|http://proxy:3128",
			},
		},
		{
			name:          "missing route",
			value:         "mirror.local/aquasec/trivy-db:2",
			expectedError: "source 1: expected repository|route",
		},
		{
			name:          "too many parts",
			value:         "mirror.local/aquasec/trivy-db:2|direct|direct",
			expectedError: "source 1: expected repository|route",
		},
		{
			name:          "empty item",
			value:         "mirror.local/aquasec/trivy-db:2|direct,",
			expectedError: "source 2: expected repository|route",
		},
		{
			name:          "empty repository",
			value:         "|direct",
			expectedError: "source 1: repository must look like host/path:tag",
		},
		{
			name:          "repository with scheme",
			value:         "https://ghcr.io/aquasecurity/trivy-db:2|direct",
			expectedError: "source 1: repository must look like host/path:tag",
		},
		{
			name:          "unknown proxy scheme",
			value:         "ghcr.io/aquasecurity/trivy-db:2|https://proxy:3128",
			expectedError: "source 1: route must be direct, http://host:port or socks5://host:port",
		},
		{
			name:          "proxy without host",
			value:         "ghcr.io/aquasecurity/trivy-db:2|socks5://",
			expectedError: "source 1: route must be direct, http://host:port or socks5://host:port",
		},
		{
			name:          "unknown route word",
			value:         "ghcr.io/aquasecurity/trivy-db:2|proxy",
			expectedError: "source 1: route must be direct, http://host:port or socks5://host:port",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sources, err := ParseDBSources(tc.value)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
				return
			}
			require.NoError(t, err)

			var got []string
			for _, source := range sources {
				got = append(got, source.String())
			}
			assert.Equal(t, tc.expectedSources, got)
		})
	}
}

func TestParseDBSources_KeepsProxyURL(t *testing.T) {
	sources, err := ParseDBSources("ghcr.io/aquasecurity/trivy-db:2|socks5://user:s3cret@proxy:1080")
	require.NoError(t, err)
	require.Len(t, sources, 1)

	assert.Equal(t, "ghcr.io/aquasecurity/trivy-db:2", sources[0].Repository)
	assert.Equal(t, "socks5", sources[0].Proxy.Scheme)
	assert.Equal(t, "proxy:1080", sources[0].Proxy.Host)
	password, _ := sources[0].Proxy.User.Password()
	assert.Equal(t, "s3cret", password, "the dialer needs the real credentials")
}

func TestParseDBSources_Redaction(t *testing.T) {
	t.Run("String hides proxy user and password", func(t *testing.T) {
		sources, err := ParseDBSources("ghcr.io/aquasecurity/trivy-db:2|http://proxyuser:s3cret@proxy:3128")
		require.NoError(t, err)
		require.Len(t, sources, 1)

		printed := sources[0].String()
		assert.Equal(t, "ghcr.io/aquasecurity/trivy-db:2|http://xxxxx@proxy:3128", printed)
		assert.NotContains(t, printed, "s3cret")
		assert.NotContains(t, printed, "proxyuser")
		assert.Equal(t, "proxyuser", sources[0].Proxy.User.Username(), "String must not change the source")
	})

	t.Run("errors do not contain the route", func(t *testing.T) {
		_, err := ParseDBSources("ghcr.io/aquasecurity/trivy-db:2|https://proxyuser:s3cret@proxy:3128")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "s3cret")
		assert.NotContains(t, err.Error(), "proxyuser")

		_, err = ParseDBSources("ghcr.io/aquasecurity/trivy-db:2|http://proxyuser:s3cret@proxy:bad port")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "s3cret")
		assert.NotContains(t, err.Error(), "proxyuser")
	})
}

func TestDBSource_String(t *testing.T) {
	proxy, err := url.Parse("socks5://proxy:1080")
	require.NoError(t, err)

	assert.Equal(t, "repo:1|direct", DBSource{Repository: "repo:1"}.String())
	assert.Equal(t, "repo:1|socks5://proxy:1080", DBSource{Repository: "repo:1", Proxy: proxy}.String())
}
