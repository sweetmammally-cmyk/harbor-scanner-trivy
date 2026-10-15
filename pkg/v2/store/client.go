package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/v2/config"
)

// PingInterval is how often Monitor pings MongoDB to update the readiness flag.
const PingInterval = 5 * time.Second

// Client is the MongoDB connection of the v2 service (DEMAND sections 4 and 11).
// MongoDB is a hard dependency, but an unreachable MongoDB never stops the
// service: Up reports false, readiness is false and the API answers 503, while
// the driver keeps reconnecting on its own.
type Client struct {
	client    *mongo.Client
	db        *mongo.Database
	opTimeout time.Duration
	// uri is kept only to remove it from error messages.
	uri string

	up atomic.Bool
	// ping checks MongoDB. Tests replace it.
	ping func(ctx context.Context) error
	// checked is false until the first ping, so the first failure is logged.
	checked bool
}

// NewClient creates the MongoDB client. It does no network I/O: the driver
// connects in the background, so an unreachable MongoDB is not an error here.
// Errors (for example a malformed SCANNER_MONGO_URI) never contain the URI.
func NewClient(cfg config.Config) (*Client, error) {
	opts := options.Client().
		ApplyURI(cfg.MongoURI).
		SetConnectTimeout(cfg.MongoConnectTimeout).
		SetServerSelectionTimeout(cfg.MongoServerSelectionTimeout)
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, redactURI(fmt.Errorf("creating MongoDB client: %w", err), cfg.MongoURI)
	}

	c := &Client{
		client:    client,
		db:        client.Database(cfg.MongoDB),
		opTimeout: cfg.MongoOperationTimeout,
		uri:       cfg.MongoURI,
	}
	c.ping = func(ctx context.Context) error {
		return client.Ping(ctx, nil)
	}
	return c, nil
}

// Database is the service's database (SCANNER_MONGO_DB).
func (c *Client) Database() *mongo.Database {
	return c.db
}

// OperationContext returns ctx with the per-operation deadline
// (SCANNER_MONGO_OPERATION_TIMEOUT). Every MongoDB call must use one.
func (c *Client) OperationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.opTimeout)
}

// Up reports the result of the last background ping. Readiness and the
// mongo_up gauge read it; they never call MongoDB themselves.
func (c *Client) Up() bool {
	return c.up.Load()
}

// Monitor pings MongoDB at once and then every interval until ctx ends, and
// keeps Up up to date. It logs only changes (and the first failure).
func (c *Client) Monitor(ctx context.Context, interval time.Duration) {
	for {
		c.checkOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (c *Client) checkOnce(ctx context.Context) {
	pingCtx, cancel := c.OperationContext(ctx)
	err := c.ping(pingCtx)
	cancel()

	wasUp := c.up.Swap(err == nil)
	switch {
	case err != nil && (wasUp || !c.checked):
		slog.Error("MongoDB is unreachable, the service is not ready",
			slog.String("error", redactURI(err, c.uri).Error()))
	case err == nil && !wasUp:
		slog.Info("MongoDB is reachable")
	}
	c.checked = true
}

// Disconnect closes the client's connections.
func (c *Client) Disconnect(ctx context.Context) error {
	ctx, cancel := c.OperationContext(ctx)
	defer cancel()
	return c.client.Disconnect(ctx)
}

// redactURI returns err with the connection string, its user info and its
// password removed from the message. The result does not wrap err, so nothing
// of the original message can leak through it.
func redactURI(err error, uri string) error {
	message := err.Error()
	var secrets []string
	if uri != "" {
		secrets = append(secrets, uri)
	}

	// mongodb://user:password@host1,host2/db?options: the user info is before the
	// last "@" of the part between "://" and the first "/" or "?".
	if _, rest, found := strings.Cut(uri, "://"); found {
		authority := rest
		if end := strings.IndexAny(rest, "/?"); end >= 0 {
			authority = rest[:end]
		}
		if at := strings.LastIndex(authority, "@"); at > 0 {
			userInfo := authority[:at]
			secrets = append(secrets, userInfo)
			if _, password, found := strings.Cut(userInfo, ":"); found && password != "" {
				secrets = append(secrets, password)
				if decoded, err := url.PathUnescape(password); err == nil && decoded != "" {
					secrets = append(secrets, decoded)
				}
			}
		}
	}

	for _, secret := range secrets {
		message = strings.ReplaceAll(message, secret, "xxxxx")
	}
	return errors.New(message)
}
