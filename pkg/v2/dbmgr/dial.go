package dbmgr

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// Dial opens a TCP connection to addr ("host:port") through the route of the source:
// directly, through an HTTP proxy with CONNECT, or through a SOCKS5 proxy.
// The connection is plain TCP; TLS is done by the caller.
// ctx bounds the whole dial, including the proxy handshake.
// Errors never contain proxy credentials.
func Dial(ctx context.Context, source config.DBSource, addr string) (net.Conn, error) {
	if source.Proxy == nil {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", addr)
	}

	switch source.Proxy.Scheme {
	case "http":
		return dialHTTPProxy(ctx, source, addr)
	case "socks5":
		var auth *proxy.Auth
		if source.Proxy.User != nil {
			password, _ := source.Proxy.User.Password()
			auth = &proxy.Auth{User: source.Proxy.User.Username(), Password: password}
		}
		dialer, err := proxy.SOCKS5("tcp", source.Proxy.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy %s: %w", source.Proxy.Host, err)
		}
		conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy %s: %w", source.Proxy.Host, err)
		}
		return conn, nil
	}
	return nil, fmt.Errorf("unsupported proxy scheme %q", source.Proxy.Scheme)
}

// dialHTTPProxy connects to the HTTP proxy and opens a tunnel to addr with CONNECT.
func dialHTTPProxy(ctx context.Context, source config.DBSource, addr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", source.Proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("http proxy %s: %w", source.Proxy.Host, err)
	}

	// The CONNECT exchange has no context support of its own:
	// cancel it by expiring the connection deadline when ctx ends.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})

	connectLine := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if source.Proxy.User != nil {
		password, _ := source.Proxy.User.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(source.Proxy.User.Username() + ":" + password))
		connectLine += "Proxy-Authorization: Basic " + credentials + "\r\n"
	}
	connectLine += "\r\n"

	if _, err = conn.Write([]byte(connectLine)); err != nil {
		stop()
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy %s: sending CONNECT: %w", source.Proxy.Host, err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		stop()
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy %s: reading CONNECT response: %w", source.Proxy.Host, err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		stop()
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy %s: CONNECT returned %s", source.Proxy.Host, resp.Status)
	}
	if reader.Buffered() > 0 {
		stop()
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy %s: unexpected data after CONNECT response", source.Proxy.Host)
	}

	// stop returns false when ctx already ended and the deadline was expired.
	if !stop() {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy %s: %w", source.Proxy.Host, ctx.Err())
	}
	return conn, nil
}
