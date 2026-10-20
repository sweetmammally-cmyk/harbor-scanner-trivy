// Package registry resolves image tags to digests in Harbor with the scanner's
// robot account (DEMAND section 6.1).
package registry

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/oci"
)

// manifestAccept asks for an image index or manifest list first, then a single
// manifest, in both OCI and Docker formats.
const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// The OCI distribution rules for repository path components and tags. They allow
// no "..", no "%" (encoded characters) and no other separators.
var (
	pathComponent = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// The errors of Resolve. The API maps them (DEMAND section 6.1): ErrInvalidName
// to 400, ErrImageNotFound to 404 image_not_found, ErrAuthFailed to 502
// registry_auth_failed, ErrUnavailable to 503 registry_unavailable with a retry hint.
var (
	ErrInvalidName   = errors.New("invalid image name")
	ErrImageNotFound = errors.New("image_not_found")
	ErrAuthFailed    = errors.New("registry_auth_failed")
	ErrUnavailable   = errors.New("registry_unavailable")
)

// retryBackoff is the pause before the single retry.
const retryBackoff = 200 * time.Millisecond

// Image is the image a scan request names.
type Image struct {
	Repository string
	Name       string
	Tag        string
}

// Resolved is a tag resolved to its manifest.
type Resolved struct {
	Digest string
	// MediaType is the manifest's media type, for example an OCI image index.
	MediaType string
	// Reference is what the scan runner scans: host/repository/name@digest,
	// never the tag, so the scanned image is exactly the resolved one.
	Reference string
}

// Client talks to the Harbor registry with the robot account.
type Client struct {
	base    *url.URL
	oci     *oci.Client
	timeout time.Duration
}

// NewClient returns a client for SCANNER_REGISTRY_URL with the robot account
// credentials. A plain http:// URL is allowed with a WARN.
func NewClient(cfg config.Config) (*Client, error) {
	base, err := url.Parse(cfg.RegistryURL)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, errors.New("SCANNER_REGISTRY_URL must be http(s)://host[:port]")
	}
	if base.Scheme == "http" {
		slog.Warn("SCANNER_REGISTRY_URL uses plain http: registry traffic and the robot credentials are not encrypted",
			slog.String("registry", base.Host))
	}

	httpClient := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	credentials := oci.Credentials{Username: cfg.RegistryUsername, Password: cfg.RegistryPassword}
	return &Client{
		base:    &url.URL{Scheme: base.Scheme, Host: base.Host},
		oci:     oci.NewClient(httpClient, credentials),
		timeout: cfg.RegistryTimeout,
	}, nil
}

// ValidateImage checks repository, name and tag against the OCI distribution rules.
func ValidateImage(image Image) error {
	path := image.Repository + "/" + image.Name
	if len(path) > 255 {
		return fmt.Errorf("%w: repository/name is longer than 255 characters", ErrInvalidName)
	}
	for _, part := range strings.Split(path, "/") {
		if !pathComponent.MatchString(part) {
			return fmt.Errorf("%w: %q is not a valid repository or name component "+
				"(lowercase letters, digits, and single '.', '_', '__' or '-' separators)", ErrInvalidName, part)
		}
	}
	if !tagPattern.MatchString(image.Tag) {
		return fmt.Errorf("%w: %q is not a valid tag", ErrInvalidName, image.Tag)
	}
	return nil
}

// Resolve returns the digest and media type of the image's tag. It asks with
// HEAD; when the registry sends no Docker-Content-Digest, it fetches the
// manifest and hashes the exact bytes.
func (c *Client) Resolve(ctx context.Context, image Image) (Resolved, error) {
	if err := ValidateImage(image); err != nil {
		return Resolved{}, err
	}
	repository := image.Repository + "/" + image.Name
	manifestURL := c.base.String() + "/v2/" + repository + "/manifests/" + image.Tag

	what := repository + ":" + image.Tag
	status, header, _, err := c.fetch(ctx, http.MethodHead, manifestURL)
	if err = checkResponse(status, err, "HEAD manifest "+what); err != nil {
		return Resolved{}, err
	}
	digest := header.Get("Docker-Content-Digest")
	mediaType := header.Get("Content-Type")

	if digest == "" {
		var body []byte
		status, header, body, err = c.fetch(ctx, http.MethodGet, manifestURL)
		if err = checkResponse(status, err, "GET manifest "+what); err != nil {
			return Resolved{}, err
		}
		digest = fmt.Sprintf("sha256:%x", sha256.Sum256(body))
		mediaType = header.Get("Content-Type")
	}

	if parsed, _, err := mime.ParseMediaType(mediaType); err == nil {
		mediaType = parsed
	}
	return Resolved{
		Digest:    digest,
		MediaType: mediaType,
		Reference: c.base.Host + "/" + repository + "@" + digest,
	}, nil
}

// checkResponse turns a registry answer into nil (200) or one of the Resolve errors.
func checkResponse(status int, err error, what string) error {
	switch {
	case errors.Is(err, oci.ErrTokenDenied):
		return fmt.Errorf("%w: %s: %w", ErrAuthFailed, what, err)
	case err != nil:
		return fmt.Errorf("%w: %s: %w", ErrUnavailable, what, err)
	case status == http.StatusOK:
		return nil
	case status == http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrImageNotFound, what)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: %s returned status %d", ErrAuthFailed, what, status)
	case status >= 500:
		return fmt.Errorf("%w: %s returned status %d", ErrUnavailable, what, status)
	}
	return fmt.Errorf("%s returned unexpected status %d", what, status)
}

// fetch sends a registry request. A network error, a timeout or a 5xx is
// retried once after a short pause; 401, 403 and 404 are not.
func (c *Client) fetch(ctx context.Context, method, requestURL string) (int, http.Header, []byte, error) {
	status, header, body, err := c.fetchOnce(ctx, method, requestURL)
	retry := (err != nil && !errors.Is(err, oci.ErrTokenDenied)) || status >= 500
	if !retry || ctx.Err() != nil {
		return status, header, body, err
	}
	select {
	case <-ctx.Done():
		return status, header, body, err
	case <-time.After(retryBackoff):
	}
	return c.fetchOnce(ctx, method, requestURL)
}

// fetchOnce sends one registry request with the per-request timeout and returns
// its status, headers and body (manifests are small: at most 4 MiB is read).
func (c *Client) fetchOnce(ctx context.Context, method, requestURL string) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.oci.Do(ctx, method, requestURL, manifestAccept)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}
