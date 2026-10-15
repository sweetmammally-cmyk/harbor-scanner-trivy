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
			name:  "allow-http1 option on direct and proxy routes",
			value: "mirror.local/aquasec/trivy-db:2|direct|allow-http1,ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080| allow-http1 ",
			expectedSources: []string{
				"mirror.local/aquasec/trivy-db:2|direct|allow-http1",
				"ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080|allow-http1",
			},
		},
		{
			name:            "option list with a repeated option",
			value:           "mirror.local/aquasec/trivy-db:2|direct|allow-http1;allow-http1",
			expectedSources: []string{"mirror.local/aquasec/trivy-db:2|direct|allow-http1"},
		},
		{
			name:          "unknown option",
			value:         "mirror.local/aquasec/trivy-db:2|direct|http1",
			expectedError: `source 1: unknown option "http1", known options: allow-http1`,
		},
		{
			name:          "empty options field",
			value:         "mirror.local/aquasec/trivy-db:2|direct|",
			expectedError: `source 1: unknown option "", known options: allow-http1`,
		},
		{
			name:          "the same repository and route twice",
			value:         "mirror.local/trivy-db:2|direct,ghcr.io/aquasecurity/trivy-db:2|direct,mirror.local/trivy-db:2|direct|allow-http1",
			expectedError: "source 3: same repository and route as source 1",
		},
		{
			name:          "the same proxy route twice, without its credentials in the error",
			value:         "ghcr.io/aquasecurity/trivy-db:2|socks5://user:s3cret@proxy:1080,ghcr.io/aquasecurity/trivy-db:2|socks5://user:s3cret@proxy:1080",
			expectedError: "source 2: same repository and route as source 1",
		},
		{
			name:  "the same repository through different routes is a fallback, not a duplicate",
			value: "ghcr.io/aquasecurity/trivy-db:2|direct,ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080",
			expectedSources: []string{
				"ghcr.io/aquasecurity/trivy-db:2|direct",
				"ghcr.io/aquasecurity/trivy-db:2|socks5://proxy:1080",
			},
		},
		{
			name:          "missing route",
			value:         "mirror.local/aquasec/trivy-db:2",
			expectedError: "source 1: expected repository|route or repository|route|options",
		},
		{
			name:          "too many parts",
			value:         "mirror.local/aquasec/trivy-db:2|direct|allow-http1|direct",
			expectedError: "source 1: expected repository|route or repository|route|options",
		},
		{
			name:          "empty item",
			value:         "mirror.local/aquasec/trivy-db:2|direct,",
			expectedError: "source 2: expected repository|route or repository|route|options",
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

func TestParseDBSources_AllowHTTP1(t *testing.T) {
	sources, err := ParseDBSources("a.local/trivy-db:2|direct,b.local/trivy-db:2|direct|allow-http1")
	require.NoError(t, err)
	require.Len(t, sources, 2)

	assert.False(t, sources[0].AllowHTTP1, "HTTP/2 is required by default")
	assert.True(t, sources[1].AllowHTTP1)
}

func TestDBSource_String(t *testing.T) {
	proxy, err := url.Parse("socks5://proxy:1080")
	require.NoError(t, err)

	assert.Equal(t, "repo:1|direct", DBSource{Repository: "repo:1"}.String())
	assert.Equal(t, "repo:1|socks5://proxy:1080", DBSource{Repository: "repo:1", Proxy: proxy}.String())
}
