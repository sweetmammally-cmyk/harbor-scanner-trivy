package dbmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

var errHTTP2NotNegotiated = errors.New("server did not negotiate HTTP/2")

// StageResult is the outcome of one pre-check stage (DEMAND section 7.3).
type StageResult struct {
	Stage   string `json:"stage" bson:"stage"`
	OK      bool   `json:"ok" bson:"ok"`
	Skipped bool   `json:"skipped,omitempty" bson:"skipped,omitempty"`
	// Class names the kind of failure, for example tls_reset (see classifyFailure). Empty when OK.
	Class    string        `json:"class,omitempty" bson:"class,omitempty"`
	Duration time.Duration `json:"duration" bson:"duration"`
	// FirstByte is the time from the stage start to the first response byte
	// (http and manifest stages only).
	FirstByte time.Duration `json:"first_byte,omitempty" bson:"first_byte,omitempty"`
	// Detail holds what the stage found (for example the TLS version) or why it failed.
	// It must never contain credentials.
	Detail string `json:"detail,omitempty" bson:"detail,omitempty"`
}

// CheckResult is the outcome of the pre-check of one source.
type CheckResult struct {
	// Source is DBSource.String(), so proxy credentials are hidden.
	Source string `json:"source" bson:"source"`
	OK     bool   `json:"ok" bson:"ok"`
	// FailureClass is the class of the failed stage. Empty when OK.
	FailureClass string        `json:"failure_class,omitempty" bson:"failure_class,omitempty"`
	StartedAt    time.Time     `json:"started_at" bson:"started_at"`
	Duration     time.Duration `json:"duration" bson:"duration"`
	Stages       []StageResult `json:"stages" bson:"stages"`
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
		// The dialers copy the context deadline onto the socket, so the socket can
		// time out a moment before the context reports it. Socket deadlines only come
		// from our contexts, so a deadline error is also a timeout.
		timedOut := stageCtx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded)
		overallDeadline, _ := ctx.Deadline()
		overall := ctx.Err() != nil || (timedOut && !overallDeadline.IsZero() && !time.Now().Before(overallDeadline))

		stageResult.Class = classifyFailure(stage, err, timedOut)
		switch {
		case overall:
			stageResult.Detail = fmt.Sprintf("overall pre-check deadline exceeded: %v", err)
		case timedOut:
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
// It logs the effective source and every stage result; credentials never reach the logs.
func Precheck(ctx context.Context, source config.DBSource, cfg config.Config) (result CheckResult) {
	result = CheckResult{Source: source.String(), StartedAt: time.Now()}

	route := config.RouteDirect
	if source.Proxy != nil {
		route = source.Proxy.Scheme + " proxy " + source.Proxy.Host
	}
	logger := slog.With(slog.String("source", result.Source))
	logger.Info("DB source pre-check started",
		slog.String("route", route),
		slog.String("tls_min_version", "TLS 1.2"),
		slog.String("alpn_offered", "h2,http/1.1"),
		slog.Bool("allow_http1", source.AllowHTTP1),
	)

	// result is a named return value, so this also runs with the final result on every early return.
	defer func() {
		result.Duration = time.Since(result.StartedAt)
		if !result.OK && len(result.Stages) > 0 {
			result.FailureClass = result.Stages[len(result.Stages)-1].Class
		}
		for _, stage := range result.Stages {
			level := slog.LevelInfo
			if !stage.OK {
				level = slog.LevelWarn
			}
			logger.Log(context.Background(), level, "DB source pre-check stage",
				slog.String("stage", stage.Stage),
				slog.Bool("ok", stage.OK),
				slog.Bool("skipped", stage.Skipped),
				slog.String("class", stage.Class),
				slog.Int64("duration_ms", stage.Duration.Milliseconds()),
				slog.Int64("first_byte_ms", stage.FirstByte.Milliseconds()),
				slog.String("detail", stage.Detail),
			)
		}
		if result.OK {
			logger.Info("DB source pre-check passed", slog.Int64("duration_ms", result.Duration.Milliseconds()))
		} else {
			logger.Warn("DB source pre-check failed",
				slog.String("failure_class", result.FailureClass),
				slog.Int64("duration_ms", result.Duration.Milliseconds()),
			)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, cfg.PrecheckTimeoutTotal)
	defer cancel()

	ref, err := parseRepository(source.Repository)
	if err != nil {
		result.Stages = append(result.Stages, StageResult{Stage: "config", Class: "config_error", Detail: err.Error()})
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
			// Record which certificate the path presented: a middlebox shows up here.
			var certErr *tls.CertificateVerificationError
			if errors.As(err, &certErr) && len(certErr.UnverifiedCertificates) > 0 {
				cert := certErr.UnverifiedCertificates[0]
				return "", fmt.Errorf("%w (peer certificate subject=%q issuer=%q expires=%s)", err,
					cert.Subject.String(), cert.Issuer.String(), cert.NotAfter.UTC().Format(time.RFC3339))
			}
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
	client := &http.Client{Transport: transport, CheckRedirect: dropAuthOnRedirect}

	protocol := tlsConn.ConnectionState().NegotiatedProtocol
	var firstByte time.Duration
	ok = runStage(ctx, &result, "http", cfg.PrecheckTimeoutHTTP, func(ctx context.Context) (string, error) {
		ctx = withFirstByteTrace(ctx, &firstByte)
		if protocol != "h2" && !source.AllowHTTP1 {
			_ = tlsConn.Close()
			return "", fmt.Errorf("%w (alpn=%q); add the %s option to this source to accept HTTP/1.1",
				errHTTP2NotNegotiated, protocol, config.OptionAllowHTTP1)
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
		registry := &registryClient{client: client, ref: ref}
		resp, err := registry.get(ctx, registry.manifestURL(), manifestAccept)
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

// classifyFailure names the kind of failure of a stage (DEMAND section 7.3),
// so a failing network path can be told apart from a failing registry.
// timedOut is true when the stage timeout or the overall deadline ended the stage.
func classifyFailure(stage string, err error, timedOut bool) string {
	switch stage {
	case "dns":
		return "dns_failure"
	case "connect":
		if timedOut {
			return "tcp_timeout"
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "tcp_refused"
		}
		return "tcp_error"
	case "tls":
		var certErr *tls.CertificateVerificationError
		var opErr *net.OpError
		switch {
		case timedOut:
			// Nothing came back after the ClientHello.
			return "tls_timeout"
		case errors.As(err, &certErr):
			return "tls_cert_invalid"
		case errors.As(err, &opErr) && opErr.Op == "remote error":
			// crypto/tls reports a received alert as an OpError with Op "remote error".
			return "tls_alert"
		case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			// The connection was reset or closed during the handshake.
			return "tls_reset"
		}
		return "tls_error"
	case "http":
		if timedOut {
			return "http_timeout"
		}
		if errors.Is(err, errHTTP2NotNegotiated) {
			return "http2_not_negotiated"
		}
		return "http_error"
	case "manifest":
		if timedOut {
			return "manifest_timeout"
		}
		return "manifest_error"
	}
	return stage + "_error"
}
