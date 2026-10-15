package config

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	RouteDirect = "direct"

	// OptionAllowHTTP1 lets a source pass the pre-check over HTTP/1.1. HTTP/2 is required otherwise.
	OptionAllowHTTP1 = "allow-http1"
)

// DBSource is one entry of SCANNER_DB_SOURCES or SCANNER_JAVA_DB_SOURCES.
type DBSource struct {
	// Repository is the OCI repository of the DB, for example "ghcr.io/aquasecurity/trivy-db:2".
	Repository string
	// Proxy is nil for a direct route, otherwise an http:// or socks5:// proxy URL.
	// It may contain credentials: never log it, use String().
	Proxy *url.URL
	// AllowHTTP1 is set by the allow-http1 option.
	AllowHTTP1 bool
}

// String returns "repository|route[|options]" with any proxy credentials hidden. Safe to log.
func (s DBSource) String() string {
	route := RouteDirect
	if s.Proxy != nil {
		proxy := *s.Proxy
		if proxy.User != nil {
			proxy.User = url.User("xxxxx")
		}
		route = proxy.String()
	}
	if s.AllowHTTP1 {
		return s.Repository + "|" + route + "|" + OptionAllowHTTP1
	}
	return s.Repository + "|" + route
}

// ParseDBSources parses an ordered list "repo|route[|options],..." where route is
// "direct", "http://host:port" or "socks5://host:port", and options is an optional
// ";"-separated list (only "allow-http1" today). An empty value returns no sources.
// Errors never contain the route value, because it may hold proxy credentials.
func ParseDBSources(value string) ([]DBSource, error) {
	var sources []DBSource
	if strings.TrimSpace(value) == "" {
		return sources, nil
	}

	for i, item := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(item), "|")
		if len(parts) != 2 && len(parts) != 3 {
			return nil, fmt.Errorf("source %d: expected repository|route or repository|route|options", i+1)
		}

		source := DBSource{Repository: strings.TrimSpace(parts[0])}
		route := strings.TrimSpace(parts[1])

		if source.Repository == "" || strings.Contains(source.Repository, "://") {
			return nil, fmt.Errorf("source %d: repository must look like host/path:tag", i+1)
		}

		if route != RouteDirect {
			proxy, err := url.Parse(route)
			if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "socks5") || proxy.Host == "" {
				return nil, fmt.Errorf("source %d: route must be direct, http://host:port or socks5://host:port", i+1)
			}
			source.Proxy = proxy
		}

		if len(parts) == 3 {
			for _, option := range strings.Split(parts[2], ";") {
				option = strings.TrimSpace(option)
				if option != OptionAllowHTTP1 {
					return nil, fmt.Errorf("source %d: unknown option %q, known options: %s", i+1, option, OptionAllowHTTP1)
				}
				source.AllowHTTP1 = true
			}
		}

		sources = append(sources, source)
	}

	return sources, nil
}
