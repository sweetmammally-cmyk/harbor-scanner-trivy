package config

import (
	"fmt"
	"net/url"
	"strings"
)

const RouteDirect = "direct"

// DBSource is one entry of SCANNER_DB_SOURCES or SCANNER_JAVA_DB_SOURCES.
type DBSource struct {
	// Repository is the OCI repository of the DB, for example "ghcr.io/aquasecurity/trivy-db:2".
	Repository string
	// Proxy is nil for a direct route, otherwise an http:// or socks5:// proxy URL.
	// It may contain credentials: never log it, use String().
	Proxy *url.URL
}

// String returns "repository|route" with any proxy credentials hidden. Safe to log.
func (s DBSource) String() string {
	if s.Proxy == nil {
		return s.Repository + "|" + RouteDirect
	}
	proxy := *s.Proxy
	if proxy.User != nil {
		proxy.User = url.User("xxxxx")
	}
	return s.Repository + "|" + proxy.String()
}

// ParseDBSources parses an ordered list "repo|route,repo|route" where route is
// "direct", "http://host:port" or "socks5://host:port". An empty value returns no sources.
// Errors never contain the route value, because it may hold proxy credentials.
func ParseDBSources(value string) ([]DBSource, error) {
	var sources []DBSource
	if strings.TrimSpace(value) == "" {
		return sources, nil
	}

	for i, item := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(item), "|")
		if len(parts) != 2 {
			return nil, fmt.Errorf("source %d: expected repository|route", i+1)
		}

		repository := strings.TrimSpace(parts[0])
		route := strings.TrimSpace(parts[1])

		if repository == "" || strings.Contains(repository, "://") {
			return nil, fmt.Errorf("source %d: repository must look like host/path:tag", i+1)
		}

		if route == RouteDirect {
			sources = append(sources, DBSource{Repository: repository})
			continue
		}

		proxy, err := url.Parse(route)
		if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "socks5") || proxy.Host == "" {
			return nil, fmt.Errorf("source %d: route must be direct, http://host:port or socks5://host:port", i+1)
		}
		sources = append(sources, DBSource{Repository: repository, Proxy: proxy})
	}

	return sources, nil
}
