package dbmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// StageResult is the outcome of one pre-check stage (DEMAND section 7.3).
type StageResult struct {
	Stage    string        `json:"stage"`
	OK       bool          `json:"ok"`
	Skipped  bool          `json:"skipped,omitempty"`
	Duration time.Duration `json:"duration"`
	// FirstByte is the time from the stage start to the first response byte
	// (http and manifest stages only).
	FirstByte time.Duration `json:"first_byte,omitempty"`
	// Detail holds what the stage found (for example the TLS version) or why it failed.
	// It must never contain credentials.
	Detail string `json:"detail,omitempty"`
}

// CheckResult is the outcome of the pre-check of one source.
type CheckResult struct {
	// Source is DBSource.String(), so proxy credentials are hidden.
	Source    string        `json:"source"`
	OK        bool          `json:"ok"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Stages    []StageResult `json:"stages"`
}

// runStage runs one stage with its own timeout, inside ctx which carries the
// overall pre-check deadline. It appends the stage result and returns whether
// the stage passed. fn must stop when its context ends; every network call in
// a stage takes that context.
func runStage(ctx context.Context, result *CheckResult, stage string, timeout time.Duration,
	fn func(ctx context.Context) (string, error)) bool {
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	detail, err := fn(stageCtx)
	stageResult := StageResult{
		Stage:    stage,
		OK:       err == nil,
		Duration: time.Since(start),
		Detail:   detail,
	}

	if err != nil {
		switch {
		case ctx.Err() != nil:
			stageResult.Detail = fmt.Sprintf("overall pre-check deadline exceeded: %v", err)
		case stageCtx.Err() != nil:
			stageResult.Detail = fmt.Sprintf("stage timeout %s exceeded: %v", timeout, err)
		default:
			stageResult.Detail = err.Error()
		}
	}

	result.Stages = append(result.Stages, stageResult)
	return stageResult.OK
}

// Precheck checks one DB source before any upstream check or download
// (DEMAND section 7.3). Stages run in order and stop at the first failure:
// dns, connect, tls, http (GET /v2/) and manifest. Each stage has its own
// timeout and the whole check is bounded by cfg.PrecheckTimeoutTotal.
func Precheck(ctx context.Context, source config.DBSource, cfg config.Config) (result CheckResult) {
	result = CheckResult{Source: source.String(), StartedAt: time.Now()}
	// result is a named return value, so this also sets the duration on every early return.
	defer func() {
		result.Duration = time.Since(result.StartedAt)
	}()

	ctx, cancel := context.WithTimeout(ctx, cfg.PrecheckTimeoutTotal)
	defer cancel()

	ref, err := parseRepository(source.Repository)
	if err != nil {
		result.Stages = append(result.Stages, StageResult{Stage: "config", Detail: err.Error()})
		return result
	}

	// For a direct route we resolve the registry host and connect to the first address.
	// For a proxy route the proxy resolves the name, so the dns stage is skipped.
	dialAddr := ref.Addr
	if source.Proxy != nil {
		result.Stages = append(result.Stages, StageResult{
			Stage:   "dns",
			OK:      true,
			Skipped: true,
			Detail:  "proxy route: the proxy resolves " + ref.Host,
		})
	} else {
		ok := runStage(ctx, &result, "dns", cfg.PrecheckTimeoutDNS, func(ctx context.Context) (string, error) {
			host, port, err := net.SplitHostPort(ref.Addr)
			if err != nil {
				return "", err
			}
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return "", err
			}
			dialAddr = net.JoinHostPort(addrs[0], port)
			return host + " -> " + strings.Join(addrs, ", "), nil
		})
		if !ok {
			return result
		}
	}

	var conn net.Conn
	ok := runStage(ctx, &result, "connect", cfg.PrecheckTimeoutConnect, func(ctx context.Context) (string, error) {
		conn, err = Dial(ctx, source, dialAddr)
		if err != nil {
			return "", err
		}
		if source.Proxy != nil {
			return "connected to " + ref.Addr + " via " + source.Proxy.Scheme + " proxy " + source.Proxy.Host, nil
		}
		return "connected to " + dialAddr, nil
	})
	if !ok {
		return result
	}

	var tlsConn *tls.Conn
	ok = runStage(ctx, &result, "tls", cfg.PrecheckTimeoutTLS, func(ctx context.Context) (string, error) {
		host, _, err := net.SplitHostPort(ref.Addr)
		if err != nil {
			return "", err
		}
		tlsConn = tls.Client(conn, newTLSConfig(host))
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return "", err
		}
		state := tlsConn.ConnectionState()
		alpn := state.NegotiatedProtocol
		if alpn == "" {
			alpn = "none"
		}
		return fmt.Sprintf("version=%s cipher=%s alpn=%s",
			tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), alpn), nil
	})
	if !ok {
		_ = conn.Close()
		return result
	}

	// The http and manifest stages reuse the connection checked above, so they
	// measure the same path. Other hosts (a token realm) get a new connection
	// through the same route.
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if tlsConn != nil && addr == ref.Addr {
				checked := tlsConn
				tlsConn = nil
				return checked, nil
			}
			return dialTLS(ctx, source, addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	protocol := tlsConn.ConnectionState().NegotiatedProtocol
	var firstByte time.Duration
	ok = runStage(ctx, &result, "http", cfg.PrecheckTimeoutHTTP, func(ctx context.Context) (string, error) {
		ctx = withFirstByteTrace(ctx, &firstByte)
		if protocol != "h2" && !source.AllowHTTP1 {
			_ = tlsConn.Close()
			return "", fmt.Errorf("server did not negotiate HTTP/2 (alpn=%q); add the %s option to this source to accept HTTP/1.1",
				protocol, config.OptionAllowHTTP1)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ref.Host+"/v2/", nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		// 401 is normal here: the registry asks for a token, which proves it is a registry.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
			return "", fmt.Errorf("GET /v2/ returned status %d (protocol=%s)", resp.StatusCode, resp.Proto)
		}
		return fmt.Sprintf("protocol=%s status=%d", resp.Proto, resp.StatusCode), nil
	})
	result.Stages[len(result.Stages)-1].FirstByte = firstByte
	if !ok {
		return result
	}

	firstByte = 0
	ok = runStage(ctx, &result, "manifest", cfg.PrecheckTimeoutManifest, func(ctx context.Context) (string, error) {
		ctx = withFirstByteTrace(ctx, &firstByte)
		resp, err := getManifest(ctx, client, ref)
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("GET manifest %s:%s returned status %d (protocol=%s)", ref.Path, ref.Tag, resp.StatusCode, resp.Proto)
		}
		return fmt.Sprintf("protocol=%s status=%d digest=%s", resp.Proto, resp.StatusCode,
			resp.Header.Get("Docker-Content-Digest")), nil
	})
	result.Stages[len(result.Stages)-1].FirstByte = firstByte
	if !ok {
		return result
	}

	result.OK = true
	return result
}

// withFirstByteTrace returns ctx with an httptrace hook that stores in firstByte
// the time from now to the first response byte of the first request made with ctx.
func withFirstByteTrace(ctx context.Context, firstByte *time.Duration) context.Context {
	start := time.Now()
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			if *firstByte == 0 {
				*firstByte = time.Since(start)
			}
		},
	})
}
