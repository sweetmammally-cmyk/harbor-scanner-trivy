package dbmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// manifestAccept lists the manifest media types we ask the registry for.
const manifestAccept = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// rootCAs is the CA pool for registry TLS. nil means the system pool. Tests replace it.
var rootCAs *x509.CertPool

// repositoryRef is a parsed DB repository such as "ghcr.io/aquasecurity/trivy-db:2".
type repositoryRef struct {
	// Host is the registry host, with a port when one was given.
	Host string
	// Addr is Host with the port added (443 by default), as used for dialing.
	Addr string
	Path string
	Tag  string
}

func parseRepository(repository string) (repositoryRef, error) {
	host, rest, found := strings.Cut(repository, "/")
	if !found || host == "" || rest == "" {
		return repositoryRef{}, fmt.Errorf("repository %q: expected host/path:tag", repository)
	}

	// The tag is after the last ":" of the path. A ":" in the host is a port.
	lastColon := strings.LastIndex(rest, ":")
	if lastColon <= 0 || lastColon == len(rest)-1 {
		return repositoryRef{}, fmt.Errorf("repository %q: missing tag", repository)
	}
	path := rest[:lastColon]
	tag := rest[lastColon+1:]
	if strings.Contains(tag, "/") {
		return repositoryRef{}, fmt.Errorf("repository %q: missing tag", repository)
	}

	// Docker Hub serves its registry API on a different host.
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}

	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "443")
	}

	return repositoryRef{Host: host, Addr: addr, Path: path, Tag: tag}, nil
}

// newTLSConfig is the TLS config for registry connections. It offers HTTP/2 and
// HTTP/1.1 with ALPN; the pre-check decides whether HTTP/1.1 is accepted.
func newTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// dialTLS dials addr through the source's route and does the TLS handshake.
func dialTLS(ctx context.Context, source config.DBSource, addr string) (*tls.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	conn, err := Dial(ctx, source, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, newTLSConfig(host))
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}
	return tlsConn, nil
}

// getManifest requests the manifest of ref. When the registry answers 401 with a
// Bearer challenge, it gets an anonymous pull token and asks again.
// The caller must close the response body. The token is never logged or returned.
func getManifest(ctx context.Context, client *http.Client, ref repositoryRef) (*http.Response, error) {
	manifestURL := "https://" + ref.Host + "/v2/" + ref.Path + "/manifests/" + ref.Tag

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestAccept)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(challenge, "Bearer ") {
		return resp, nil
	}
	_ = resp.Body.Close()

	token, err := getToken(ctx, client, challenge)
	if err != nil {
		return nil, err
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestAccept)
	req.Header.Set("Authorization", "Bearer "+token)
	return client.Do(req)
}

// getToken gets an anonymous token for a challenge such as
// `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:aquasecurity/trivy-db:pull"`.
func getToken(ctx context.Context, client *http.Client, challenge string) (string, error) {
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			params[key] = strings.Trim(value, `"`)
		}
	}

	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" {
		return "", fmt.Errorf("token: invalid realm in registry challenge")
	}
	query := realm.Query()
	if params["service"] != "" {
		query.Set("service", params["service"])
	}
	if params["scope"] != "" {
		query.Set("scope", params["scope"])
	}
	realm.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token: %s returned status %d", realm.Host, resp.StatusCode)
	}

	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("token: decoding response from %s: %w", realm.Host, err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", fmt.Errorf("token: empty token from %s", realm.Host)
}
