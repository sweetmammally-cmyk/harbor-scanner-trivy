package dbmgr

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

func TestDial_Direct(t *testing.T) {
	target := startEchoServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, config.DBSource{Repository: "r"}, target)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	assertEcho(t, conn)
}

func TestDial_HTTPProxy(t *testing.T) {
	target := startEchoServer(t)

	t.Run("without credentials", func(t *testing.T) {
		proxy := startHTTPProxy(t, "")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := Dial(ctx, source(t, "http://"+proxy.addr), target)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		assertEcho(t, conn)
		assert.Equal(t, []string{target}, proxy.targets())
	})

	t.Run("with credentials", func(t *testing.T) {
		proxy := startHTTPProxy(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:s3cret")))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := Dial(ctx, source(t, "http://user:s3cret@"+proxy.addr), target)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		assertEcho(t, conn)
	})

	t.Run("wrong credentials", func(t *testing.T) {
		proxy := startHTTPProxy(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:s3cret")))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := Dial(ctx, source(t, "http://user:wr0ng@"+proxy.addr), target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CONNECT returned 407")
		assertNoSecrets(t, err, "wr0ng")
	})
}

func TestDial_SOCKS5(t *testing.T) {
	target := startEchoServer(t)

	t.Run("without credentials", func(t *testing.T) {
		proxy := startSOCKS5Proxy(t, "", "")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := Dial(ctx, source(t, "socks5://"+proxy.addr), target)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		assertEcho(t, conn)
		assert.Equal(t, []string{target}, proxy.targets())
	})

	t.Run("with credentials", func(t *testing.T) {
		proxy := startSOCKS5Proxy(t, "user", "s3cret")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := Dial(ctx, source(t, "socks5://user:s3cret@"+proxy.addr), target)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		assertEcho(t, conn)
	})

	t.Run("wrong credentials", func(t *testing.T) {
		proxy := startSOCKS5Proxy(t, "user", "s3cret")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := Dial(ctx, source(t, "socks5://user:wr0ng@"+proxy.addr), target)
		require.Error(t, err)
		assertNoSecrets(t, err, "wr0ng")
	})
}

// TestDial_Blackhole checks that a proxy which accepts the TCP connection
// but never answers cannot make Dial hang past its context deadline.
func TestDial_Blackhole(t *testing.T) {
	blackhole := startBlackhole(t)

	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			start := time.Now()
			_, err := Dial(ctx, source(t, scheme+"://user:s3cret@"+blackhole), "registry.local:443")
			require.Error(t, err)
			assert.Less(t, time.Since(start), 2*time.Second, "Dial must stop at the context deadline")
			assertNoSecrets(t, err, "s3cret")
		})
	}
}

func TestDial_ProxyUnreachable(t *testing.T) {
	// A port that was open and is now closed.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := listener.Addr().String()
	require.NoError(t, listener.Close())

	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := Dial(ctx, source(t, scheme+"://user:s3cret@"+closedAddr), "registry.local:443")
			require.Error(t, err)
			assert.Contains(t, err.Error(), closedAddr, "the error names the proxy address")
			assertNoSecrets(t, err, "s3cret")
		})
	}
}

func source(t *testing.T, proxyURL string) config.DBSource {
	t.Helper()
	proxy, err := url.Parse(proxyURL)
	require.NoError(t, err)
	return config.DBSource{Repository: "registry.local/trivy-db:2", Proxy: proxy}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
}

func assertNoSecrets(t *testing.T, err error, password string) {
	t.Helper()
	assert.NotContains(t, err.Error(), password)
	assert.NotContains(t, err.Error(), "user:")
	assert.NotContains(t, err.Error(), "Basic ")
}

// listen starts a TCP listener and serves every connection with handle.
func listen(t *testing.T, handle func(conn net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func startEchoServer(t *testing.T) string {
	return listen(t, func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
}

func startBlackhole(t *testing.T) string {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	return listen(t, func(conn net.Conn) {
		<-done
	})
}

type testProxy struct {
	addr string

	mu   sync.Mutex
	seen []string
}

func (p *testProxy) addTarget(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, target)
}

func (p *testProxy) targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

// pipe connects the client to target and copies data both ways.
func pipe(client net.Conn, target string) {
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()
	go func() { _, _ = io.Copy(upstream, client) }()
	_, _ = io.Copy(client, upstream)
}

// startHTTPProxy starts a CONNECT proxy. When wantAuth is set, the
// Proxy-Authorization header must be equal to it.
func startHTTPProxy(t *testing.T, wantAuth string) *testProxy {
	proxy := &testProxy{}
	proxy.addr = listen(t, func(conn net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		if wantAuth != "" && req.Header.Get("Proxy-Authorization") != wantAuth {
			_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
		proxy.addTarget(req.Host)
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		pipe(conn, req.Host)
	})
	return proxy
}

// startSOCKS5Proxy starts a minimal SOCKS5 server (RFC 1928 CONNECT, RFC 1929 auth).
// When user is set, username/password authentication is required.
func startSOCKS5Proxy(t *testing.T, user, password string) *testProxy {
	proxy := &testProxy{}
	proxy.addr = listen(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)

		// Greeting: version, number of methods, methods.
		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			return
		}
		if _, err := io.ReadFull(reader, make([]byte, header[1])); err != nil {
			return
		}

		if user == "" {
			_, _ = conn.Write([]byte{5, 0})
		} else {
			_, _ = conn.Write([]byte{5, 2})
			// Auth: version, user length, user, password length, password.
			buf := make([]byte, 2)
			if _, err := io.ReadFull(reader, buf); err != nil {
				return
			}
			gotUser := make([]byte, buf[1])
			if _, err := io.ReadFull(reader, gotUser); err != nil {
				return
			}
			length, err := reader.ReadByte()
			if err != nil {
				return
			}
			gotPassword := make([]byte, length)
			if _, err := io.ReadFull(reader, gotPassword); err != nil {
				return
			}
			if string(gotUser) != user || string(gotPassword) != password {
				_, _ = conn.Write([]byte{1, 1})
				return
			}
			_, _ = conn.Write([]byte{1, 0})
		}

		// Request: version, command, reserved, address type, address, port.
		request := make([]byte, 4)
		if _, err := io.ReadFull(reader, request); err != nil {
			return
		}
		var host string
		switch request[3] {
		case 1:
			ip := make([]byte, 4)
			if _, err := io.ReadFull(reader, ip); err != nil {
				return
			}
			host = net.IP(ip).String()
		case 3:
			length, err := reader.ReadByte()
			if err != nil {
				return
			}
			name := make([]byte, length)
			if _, err := io.ReadFull(reader, name); err != nil {
				return
			}
			host = string(name)
		default:
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(reader, port); err != nil {
			return
		}
		target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))

		proxy.addTarget(target)
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		pipe(conn, target)
	})
	return proxy
}
