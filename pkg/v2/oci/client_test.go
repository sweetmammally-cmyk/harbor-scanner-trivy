package oci

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const manifestPath = "/v2/project/app/manifests/v1"

// fakeRegistry protects manifestPath with Bearer tokens from its /token realm.
type fakeRegistry struct {
	server *httptest.Server

	// Settings, changed before requests are made.
	wantBasic   string        // when set, the token request must carry this Authorization
	expiresIn   int           // expires_in of issued tokens; 0 leaves it out
	tokenDelay  time.Duration // slows the token endpoint, to overlap callers
	neverAccept bool          // refuse every token: an endless chain of challenges

	mu            sync.Mutex
	issued        map[string]bool
	tokenRequests int
	requests      atomic.Int32
	scopes        []string
}

func startFakeRegistry(t *testing.T, tls bool) *fakeRegistry {
	f := &fakeRegistry{issued: map[string]bool{}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.serveToken(w, r)
			return
		}
		f.requests.Add(1)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		valid := f.issued[token] && !f.neverAccept
		f.mu.Unlock()
		if !valid {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+f.server.URL+`/token",service="harbor-registry",scope="repository:project/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("manifest"))
	})
	if tls {
		f.server = httptest.NewTLSServer(handler)
	} else {
		f.server = httptest.NewServer(handler)
	}
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeRegistry) serveToken(w http.ResponseWriter, r *http.Request) {
	time.Sleep(f.tokenDelay)
	if f.wantBasic != "" && r.Header.Get("Authorization") != f.wantBasic {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.tokenRequests++
	token := fmt.Sprintf("token-%d", f.tokenRequests)
	f.issued[token] = true
	f.scopes = append(f.scopes, r.URL.Query().Get("scope"))
	f.mu.Unlock()
	if f.expiresIn > 0 {
		_, _ = fmt.Fprintf(w, `{"token":%q,"expires_in":%d}`, token, f.expiresIn)
		return
	}
	_, _ = fmt.Fprintf(w, `{"token":%q}`, token)
}

// revoke makes the registry refuse every token issued so far.
func (f *fakeRegistry) revoke() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = map[string]bool{}
}

func (f *fakeRegistry) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenRequests
}

func get(t *testing.T, c *Client, f *fakeRegistry) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Do(ctx, http.MethodGet, f.server.URL+manifestPath, "application/json")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestClient_TokenFlow(t *testing.T) {
	t.Run("anonymous token, cached for later requests", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		c := NewClient(f.server.Client(), Credentials{})

		for i := 0; i < 3; i++ {
			assert.Equal(t, http.StatusOK, get(t, c, f).StatusCode)
		}

		assert.Equal(t, 1, f.tokenCount(), "one token for three requests")
		assert.Equal(t, []string{"repository:project/app:pull"}, f.scopes)
	})

	t.Run("credentials go to the token endpoint as basic auth", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		f.wantBasic = "Basic " + base64.StdEncoding.EncodeToString([]byte("robot$scanner:s3cret"))
		c := NewClient(f.server.Client(), Credentials{Username: "robot$scanner", Password: "s3cret"})

		assert.Equal(t, http.StatusOK, get(t, c, f).StatusCode)
	})

	t.Run("refused credentials are ErrTokenDenied, without the secrets", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		f.wantBasic = "Basic " + base64.StdEncoding.EncodeToString([]byte("robot$scanner:s3cret"))
		c := NewClient(f.server.Client(), Credentials{Username: "robot$scanner", Password: "wr0ng"})

		_, err := c.Do(context.Background(), http.MethodGet, f.server.URL+manifestPath, "")

		require.ErrorIs(t, err, ErrTokenDenied)
		assert.NotContains(t, err.Error(), "wr0ng")
		assert.NotContains(t, err.Error(), "robot$scanner")
	})

	t.Run("an expired token is fetched again", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		f.expiresIn = 30
		c := NewClient(f.server.Client(), Credentials{})
		now := time.Now()
		c.now = func() time.Time { return now }

		get(t, c, f)
		now = now.Add(20 * time.Second)
		get(t, c, f)
		assert.Equal(t, 1, f.tokenCount(), "still valid after 20s")

		now = now.Add(10 * time.Second) // 30s: past expires_in minus the 5s early renewal
		get(t, c, f)
		assert.Equal(t, 2, f.tokenCount())
	})

	t.Run("a cached token the registry refuses is replaced", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		c := NewClient(f.server.Client(), Credentials{})
		get(t, c, f)
		f.revoke()

		assert.Equal(t, http.StatusOK, get(t, c, f).StatusCode)
		assert.Equal(t, 2, f.tokenCount())
	})

	t.Run("concurrent requests share one token fetch", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		f.tokenDelay = 100 * time.Millisecond
		c := NewClient(f.server.Client(), Credentials{})

		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := c.Do(context.Background(), http.MethodGet, f.server.URL+manifestPath, "")
				if assert.NoError(t, err) {
					assert.Equal(t, http.StatusOK, resp.StatusCode)
					_ = resp.Body.Close()
				}
			}()
		}
		wg.Wait()

		assert.Equal(t, 1, f.tokenCount())
	})

	t.Run("an endless chain of challenges stops with the registry's 401", func(t *testing.T) {
		f := startFakeRegistry(t, true)
		f.neverAccept = true
		c := NewClient(f.server.Client(), Credentials{})

		resp := get(t, c, f)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, int32(MaxChallenges+1), f.requests.Load(), "bounded number of attempts")
		assert.LessOrEqual(t, f.tokenCount(), MaxChallenges)
	})
}

func TestClient_Realm(t *testing.T) {
	t.Run("plain http registry may use a plain http realm", func(t *testing.T) {
		f := startFakeRegistry(t, false)
		c := NewClient(f.server.Client(), Credentials{Username: "robot", Password: "s3cret"})

		assert.Equal(t, http.StatusOK, get(t, c, f).StatusCode)
	})

	t.Run("an https registry must not send credentials to a plain http realm", func(t *testing.T) {
		c := NewClient(http.DefaultClient, Credentials{Username: "robot", Password: "s3cret"})

		_, err := c.token(context.Background(), `Bearer realm="http://insecure.local/token"`, "https://registry.local/v2/", false)

		assert.EqualError(t, err, "token: invalid realm in registry challenge")
	})

	t.Run("invalid realms", func(t *testing.T) {
		c := NewClient(http.DefaultClient, Credentials{})
		for _, challenge := range []string{`Bearer service="x"`, `Bearer realm="::bad"`, `Bearer realm="ftp://x/token"`} {
			_, err := c.token(context.Background(), challenge, "https://registry.local/v2/", false)
			assert.EqualError(t, err, "token: invalid realm in registry challenge", challenge)
		}
	})
}

func TestClient_BasicChallenge(t *testing.T) {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("robot:s3cret"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	withCredentials := NewClient(server.Client(), Credentials{Username: "robot", Password: "s3cret"})
	resp, err := withCredentials.Do(context.Background(), http.MethodHead, server.URL+"/v2/", "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	anonymous := NewClient(server.Client(), Credentials{})
	resp, err = anonymous.Do(context.Background(), http.MethodHead, server.URL+"/v2/", "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no credentials: the 401 is returned at once")
}

func TestDropAuthOnRedirect(t *testing.T) {
	newRequest := func(url string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer t0ken")
		return req
	}
	first := newRequest("https://registry.local:443/v2/x/blobs/sha256:1")

	sameHost := newRequest("https://registry.local:443/other")
	require.NoError(t, DropAuthOnRedirect(sameHost, []*http.Request{first}))
	assert.Equal(t, "Bearer t0ken", sameHost.Header.Get("Authorization"))

	otherPort := newRequest("https://registry.local:8443/blob")
	require.NoError(t, DropAuthOnRedirect(otherPort, []*http.Request{first}))
	assert.Empty(t, otherPort.Header.Get("Authorization"))

	otherHost := newRequest("https://cdn.local/blob")
	require.NoError(t, DropAuthOnRedirect(otherHost, []*http.Request{first}))
	assert.Empty(t, otherHost.Header.Get("Authorization"))

	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = first
	}
	assert.Error(t, DropAuthOnRedirect(newRequest("https://registry.local/again"), via))
}

func TestNewClient_SetsRedirectRule(t *testing.T) {
	httpClient := &http.Client{}
	NewClient(httpClient, Credentials{})
	require.NotNil(t, httpClient.CheckRedirect)

	own := func(req *http.Request, via []*http.Request) error { return errors.New("own rule") }
	custom := &http.Client{CheckRedirect: own}
	NewClient(custom, Credentials{})
	assert.EqualError(t, custom.CheckRedirect(nil, nil), "own rule", "a caller's rule is kept")
}
