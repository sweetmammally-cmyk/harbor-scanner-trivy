// Package oci sends registry API (OCI distribution) requests and answers the
// registry's authentication challenges. The DB download (dbmgr) and the Harbor
// registry client (registry) both use it.
package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// MaxChallenges is how many authentication challenges one request answers before
// it gives up and returns the registry's 401, so a registry that keeps asking
// cannot make a request loop forever.
const MaxChallenges = 3

// defaultTokenLifetime is used when the token response has no expires_in
// (the distribution token spec says 60 seconds).
const defaultTokenLifetime = 60 * time.Second

// ErrTokenDenied is returned when the token endpoint refuses the credentials.
var ErrTokenDenied = errors.New("the registry token endpoint refused the credentials")

// Credentials are sent to the token endpoint and answer Basic challenges.
// Empty means anonymous. They are never logged or put in errors.
type Credentials struct {
	Username string
	Password string
}

// Client sends registry requests through httpClient (its transport decides the
// route and TLS) and answers 401 challenges: Bearer with a token from the
// challenge's realm, Basic with the credentials. Tokens are cached per realm,
// service and scope until they expire, and fetched once at a time per scope.
type Client struct {
	http  *http.Client
	creds Credentials
	// now is the clock for token expiry. Tests replace it.
	now func() time.Time

	mu       sync.Mutex
	tokens   map[string]cachedToken
	fetching map[string]*tokenFetch
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

// tokenFetch is a token request in progress; other callers wait for done.
type tokenFetch struct {
	done  chan struct{}
	token string
	err   error
}

// NewClient returns a client using httpClient. If httpClient has no
// CheckRedirect, DropAuthOnRedirect is set, so tokens never follow a redirect to
// another host.
func NewClient(httpClient *http.Client, creds Credentials) *Client {
	if httpClient.CheckRedirect == nil {
		httpClient.CheckRedirect = DropAuthOnRedirect
	}
	return &Client{
		http:     httpClient,
		creds:    creds,
		now:      time.Now,
		tokens:   map[string]cachedToken{},
		fetching: map[string]*tokenFetch{},
	}
}

// Do sends a request and answers up to MaxChallenges authentication challenges.
// A response that is not 401, or the last 401, is returned to the caller, who
// must close its body.
func (c *Client) Do(ctx context.Context, method, requestURL, accept string) (*http.Response, error) {
	authorization := ""
	for attempt := 0; ; attempt++ {
		resp, err := c.send(ctx, method, requestURL, accept, authorization)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt == MaxChallenges {
			return resp, nil
		}

		challenge := resp.Header.Get("WWW-Authenticate")
		switch {
		case strings.HasPrefix(challenge, "Bearer "):
			// After the first attempt the registry refused the token we sent: get a new one.
			token, err := c.token(ctx, challenge, requestURL, attempt > 0)
			if err != nil {
				_ = resp.Body.Close()
				return nil, err
			}
			authorization = "Bearer " + token
		case strings.HasPrefix(challenge, "Basic ") && c.creds.Username != "":
			authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.creds.Username+":"+c.creds.Password))
		default:
			return resp, nil
		}
		_ = resp.Body.Close()
	}
}

func (c *Client) send(ctx context.Context, method, requestURL, accept, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return c.http.Do(req)
}

// token returns a token for a Bearer challenge such as
// `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:aquasecurity/trivy-db:pull"`,
// from the cache unless refresh is set. Only one fetch per challenge runs at a time.
func (c *Client) token(ctx context.Context, challenge, requestURL string, refresh bool) (string, error) {
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			params[key] = strings.Trim(value, `"`)
		}
	}
	key := params["realm"] + "|" + params["service"] + "|" + params["scope"]

	c.mu.Lock()
	if refresh {
		delete(c.tokens, key)
	}
	if cached, found := c.tokens[key]; found && c.now().Before(cached.expiresAt) {
		c.mu.Unlock()
		return cached.value, nil
	}
	fetch, inProgress := c.fetching[key]
	if !inProgress {
		fetch = &tokenFetch{done: make(chan struct{})}
		c.fetching[key] = fetch
	}
	c.mu.Unlock()

	if inProgress {
		select {
		case <-fetch.done:
			return fetch.token, fetch.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	token, lifetime, err := c.fetchToken(ctx, params, requestURL)
	c.mu.Lock()
	if err == nil {
		c.tokens[key] = cachedToken{value: token, expiresAt: c.now().Add(lifetime)}
	}
	delete(c.fetching, key)
	c.mu.Unlock()
	fetch.token, fetch.err = token, err
	close(fetch.done)
	return token, err
}

// fetchToken asks the realm for a token and returns it with how long to keep it.
// Errors name the realm host only: never the token or the credentials.
func (c *Client) fetchToken(ctx context.Context, params map[string]string, requestURL string) (string, time.Duration, error) {
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" {
		return "", 0, errors.New("token: invalid realm in registry challenge")
	}
	// Credentials may only travel unencrypted when the registry itself is plain http.
	request, _ := url.Parse(requestURL)
	if realm.Scheme != "https" && !(realm.Scheme == "http" && request != nil && request.Scheme == "http") {
		return "", 0, errors.New("token: invalid realm in registry challenge")
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
		return "", 0, err
	}
	if c.creds.Username != "" {
		req.SetBasicAuth(c.creds.Username, c.creds.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", 0, fmt.Errorf("%w (%s returned status %d)", ErrTokenDenied, realm.Host, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token: %s returned status %d", realm.Host, resp.StatusCode)
	}

	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", 0, fmt.Errorf("token: decoding response from %s: %w", realm.Host, err)
	}
	token := body.Token
	if token == "" {
		token = body.AccessToken
	}
	if token == "" {
		return "", 0, fmt.Errorf("token: empty token from %s", realm.Host)
	}

	lifetime := defaultTokenLifetime
	if body.ExpiresIn > 0 {
		lifetime = time.Duration(body.ExpiresIn) * time.Second
	}
	// Renew a little early, so a token does not expire on the way to the registry.
	if lifetime > 10*time.Second {
		lifetime -= 5 * time.Second
	}
	return token, lifetime, nil
}

// DropAuthOnRedirect removes the Authorization header when a redirect leaves the
// first request's host:port (for example to a blob CDN). net/http alone keeps
// the header when only the port changes. It keeps the default limit of 10 redirects.
func DropAuthOnRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		req.Header.Del("Authorization")
	}
	return nil
}
