package dbmgr

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

// registryClient talks to one DB repository with the registry API (OCI distribution).
// It uses raw net/http so every request goes through the source's route.
type registryClient struct {
	client *http.Client
	ref    repositoryRef
	// token is the anonymous pull token, set after the first Bearer challenge.
	// It is sent only to the registry host and never logged or returned.
	token string
}

// newRegistryClient returns a client whose connections go through the source's route.
func newRegistryClient(source config.DBSource) (*registryClient, error) {
	ref, err := parseRepository(source.Repository)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(ctx, source, addr)
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: dropAuthOnRedirect}
	return &registryClient{client: client, ref: ref}, nil
}

// dropAuthOnRedirect removes the registry token when a redirect leaves the registry
// host:port (for example to a blob CDN). net/http alone keeps the header when only
// the port changes. It keeps the default limit of 10 redirects.
func dropAuthOnRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		req.Header.Del("Authorization")
	}
	return nil
}

// ociManifest is the part of an OCI image manifest we need.
type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Layers    []ociDescriptor `json:"layers"`
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// get requests a registry URL. When the registry answers 401 with a Bearer
// challenge, it gets an anonymous pull token, keeps it, and asks again.
// The caller must close the response body.
func (c *registryClient) get(ctx context.Context, url string, accept string) (*http.Response, error) {
	resp, err := c.send(ctx, url, accept)
	if err != nil {
		return nil, err
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(challenge, "Bearer ") {
		return resp, nil
	}
	_ = resp.Body.Close()

	c.token, err = getToken(ctx, c.client, challenge)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, url, accept)
}

func (c *registryClient) send(ctx context.Context, url string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c.token != "" {
		// dropAuthOnRedirect removes it when a redirect goes to another host (a blob CDN).
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.client.Do(req)
}

func (c *registryClient) manifestURL() string {
	return "https://" + c.ref.Host + "/v2/" + c.ref.Path + "/manifests/" + c.ref.Tag
}

// getManifest returns the manifest of the repository tag and its digest
// (sha256 of the manifest bytes, checked against Docker-Content-Digest when sent).
func (c *registryClient) getManifest(ctx context.Context) (ociManifest, string, error) {
	resp, err := c.get(ctx, c.manifestURL(), manifestAccept)
	if err != nil {
		return ociManifest{}, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ociManifest{}, "", fmt.Errorf("GET manifest %s:%s returned status %d", c.ref.Path, c.ref.Tag, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ociManifest{}, "", fmt.Errorf("reading manifest %s:%s: %w", c.ref.Path, c.ref.Tag, err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	if header := resp.Header.Get("Docker-Content-Digest"); header != "" && header != digest {
		return ociManifest{}, "", fmt.Errorf("manifest %s:%s: digest %s does not match Docker-Content-Digest %s", c.ref.Path, c.ref.Tag, digest, header)
	}

	var manifest ociManifest
	if err = json.Unmarshal(body, &manifest); err != nil {
		return ociManifest{}, "", fmt.Errorf("decoding manifest %s:%s: %w", c.ref.Path, c.ref.Tag, err)
	}
	if len(manifest.Layers) == 0 {
		return ociManifest{}, "", fmt.Errorf("manifest %s:%s has no layers", c.ref.Path, c.ref.Tag)
	}
	return manifest, digest, nil
}

// getBlob opens the blob with the given digest. Registries often redirect blobs to
// a CDN; the redirect is followed through the same route. The caller must close the body.
func (c *registryClient) getBlob(ctx context.Context, digest string) (io.ReadCloser, error) {
	resp, err := c.get(ctx, "https://"+c.ref.Host+"/v2/"+c.ref.Path+"/blobs/"+digest, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET blob %s returned status %d", digest, resp.StatusCode)
	}
	return resp.Body, nil
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
