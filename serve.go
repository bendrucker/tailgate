package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/resource"
	"github.com/bendrucker/tailgate/internal/router"
	"github.com/bendrucker/tailgate/internal/tsnetserver"
)

const (
	// drainTimeout bounds the transport drain. An MCP session's SSE stream
	// stays open until its client goes away, so a drain without a deadline is a
	// hang.
	drainTimeout = 30 * time.Second
	// closeTimeout bounds the wait for connections whose handlers have already
	// returned. It runs on its own clock so a transport that spends the entire
	// drain budget still leaves the server a window to close cleanly rather
	// than severing every connection it was about to finish with.
	closeTimeout = 5 * time.Second
)

// serve runs tailgate until ctx is canceled or the listener fails.
//
// The order is forced by what each step learns from the one before it: the
// canonical resource URLs need the FQDN the join reports, the verifier needs a
// client that dials the tailnet, and the router needs both. Nothing serves
// until every one of them succeeds, so a startup failure is downtime rather
// than an unauthenticated window.
func serve(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	node, err := tsnetserver.New(tsnetserver.Config{
		Hostname: cfg.Node.Hostname,
		StateDir: cfg.Node.StateDir,
		Port:     cfg.Node.Port,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	defer node.Close()

	fqdn, err := node.Up(ctx)
	if err != nil {
		return err
	}
	logger.Info("joined tailnet", "fqdn", fqdn)

	urls, err := resource.NewURLs(fqdn, cfg.Node.Port)
	if err != nil {
		return err
	}

	// Introspection goes over the tailnet, where tsidp authenticates tailgate
	// by node identity and no client secret is stored anywhere.
	verifier, err := auth.NewVerifier(ctx, node.HTTPClient(), cfg.OIDC.Issuer)
	if err != nil {
		return fmt.Errorf("discover issuer %s: %w", cfg.OIDC.Issuer, err)
	}

	rt, err := handler(cfg, urls, verifier, logger, audit.New(logger))
	if err != nil {
		return err
	}
	defer rt.Close()

	listener, err := node.ListenFunnel()
	if err != nil {
		return err
	}

	server := router.Server(rt)
	serving := make(chan error, 1)
	go func() { serving <- server.Serve(listener) }()

	for _, upstream := range cfg.Upstreams {
		logger.Info("serving upstream", "name", upstream.Name, "resource", urls.ResourceURL(upstream.Name))
	}

	select {
	case err := <-serving:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return drain(logger, node, server, rt)
	}
}

// stopper closes the public listener. *tsnetserver.Server implements it.
type stopper interface {
	StopAccepting() error
}

// transports drains the upstreams behind the router. *router.Router implements
// it.
type transports interface {
	Shutdown(ctx context.Context) error
}

// drain stops accepting, lets in-flight work finish, and only then tears
// anything down. Transports drain ahead of the HTTP server because the server
// waits on handlers the transports are still holding open.
func drain(logger *slog.Logger, node stopper, server *http.Server, rt transports) error {
	logger.Info("draining", "timeout", drainTimeout)

	stopped := node.StopAccepting()

	draining, cancelDraining := context.WithTimeout(context.Background(), drainTimeout)
	defer cancelDraining()

	drained := rt.Shutdown(draining)
	if drained != nil {
		logger.Warn("upstreams did not drain", "err", drained)
	}

	closing, cancelClosing := context.WithTimeout(context.Background(), closeTimeout)
	defer cancelClosing()

	if err := server.Shutdown(closing); err != nil {
		logger.Warn("connections did not close", "err", err)
		// Close severs whatever the deadline left, so shutdown terminates.
		drained = errors.Join(drained, server.Close())
	}
	return errors.Join(stopped, drained)
}
