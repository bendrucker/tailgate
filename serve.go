package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/authserver"
	"github.com/bendrucker/tailgate/internal/cimd"
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
	// closeTimeout bounds the wait for the connections the transport drain does
	// not cover: a request at the authorization server, which may be waiting
	// on a client metadata fetch, has reached no transport. The clock is
	// separate so a transport that spends the entire drain budget still leaves
	// those connections a window to close cleanly rather than being severed.
	closeTimeout = 10 * time.Second
	// joinTimeout bounds an unattended join. A node with no auth key and no
	// saved state cannot authenticate itself, and tsnet's fallback is to print
	// a login URL every few seconds forever. Under launchd nobody reads that
	// log, so an unbounded wait is a process launchd considers healthy while it
	// serves nothing.
	joinTimeout = 90 * time.Second
	// interactiveJoinTimeout bounds a join that -open-login put in front of a
	// person, whose approval takes longer than any network round trip.
	interactiveJoinTimeout = 5 * time.Minute
)

// options carries the invocation's run-mode choices, which are the caller's
// rather than the deployment's and so live on the command line instead of in
// the config file.
type options struct {
	// OpenLoginURL opens the interactive login URL in the default browser when
	// the node joins without an auth key.
	OpenLoginURL bool
	// ConfigPath is the file cfg was loaded from, which a SIGHUP loads again.
	ConfigPath string
}

// serve runs tailgate on node until ctx is canceled or the listener fails.
// The node is joined here rather than built here, so the whole sequence runs
// against a tailnet or against a test's stand-in for one.
//
// The order is forced by what each step learns from the one before it: the
// canonical resource URLs need the FQDN the join reports, the authorization
// server needs those URLs and the node's WhoIs, and the router needs all of
// it. Nothing serves until every one of them succeeds, so a startup failure
// is downtime rather than an unauthenticated window.
func serve(ctx context.Context, logger *slog.Logger, node tsnetserver.Node, cfg *config.Config, opts options) error {
	// The node leaves the tailnet on every path out of here, including the one
	// where the drain already closed it. Close is idempotent, so the two do not
	// conflict.
	defer node.Close()

	fqdn, err := joinTailnet(ctx, node, joinTimeoutFor(opts))
	if err != nil {
		return err
	}
	logger.Info("joined tailnet", "fqdn", fqdn)

	if err := expectedFQDN(cfg.Node, fqdn); err != nil {
		return err
	}

	urls, err := resource.NewURLs(fqdn, cfg.Node.Port)
	if err != nil {
		return err
	}

	// tailgate issues its own tokens, from memory. The store and the
	// authorization server around it are built once here: they hold every
	// token a client has, so a reload must never rebuild them. The router is
	// what a reload rebuilds, and the authorization server reaches the current
	// one through the reloader for its upstream check, which is why the
	// reloader is built before the router it will serve.
	tokens := auth.NewTokens()
	routes := newReloader(opts.ConfigPath, cfg.Node, logger)
	defer routes.Close()

	authServer, err := authserver.New(authserver.Options{
		Resources:   urls,
		HasUpstream: routes.HasUpstream,
		Tokens:      tokens,
		Identify:    node.WhoIs,
		Clients:     cimd.NewFetcher(cimd.NewClient()),
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	auditor := audit.New(logger)
	if err := routes.start(cfg, func(cfg *config.Config) (served, error) {
		rt, err := handler(cfg, urls, tokens, authServer, logger, auditor)
		if err != nil {
			return nil, err
		}
		return rt, nil
	}); err != nil {
		return err
	}

	// SIGHUP's default disposition ends the process, so the handler is in
	// place before anything serves.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go reloadOnSignal(ctx, hup, routes)

	listener, err := node.ListenFunnel()
	if err != nil {
		return err
	}

	server := router.Server(routes)
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
		return drain(logger, node, server, routes)
	}
}

// A refused reload is logged by the reloader and leaves the running
// configuration in service, so there is nothing for the loop to do with the
// error.
func reloadOnSignal(ctx context.Context, signals <-chan os.Signal, routes *reloader) {
	for {
		select {
		case <-signals:
			routes.Reload()
		case <-ctx.Done():
			return
		}
	}
}

// joinTimeoutFor reports how long tailgate waits for the join, which depends
// on what it is waiting for: an unattended start has only the auth key it was
// given, while -open-login is waiting on a person to approve a login in a
// browser.
func joinTimeoutFor(opts options) time.Duration {
	if opts.OpenLoginURL {
		return interactiveJoinTimeout
	}
	return joinTimeout
}

// joinTailnet bounds the join, so a node that cannot authenticate is a startup
// failure rather than a process that runs forever without serving.
//
// The error names both remedies, since the log it lands in is all a launchd
// deployment leaves behind.
func joinTailnet(ctx context.Context, node tsnetserver.Node, timeout time.Duration) (string, error) {
	joining, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	fqdn, err := node.Up(joining)
	switch {
	case err == nil:
		return fqdn, nil
	// A canceled parent is the signal that asked tailgate to stop, which main
	// reports as the shutdown it is rather than a failure to join.
	case ctx.Err() != nil:
		return "", err
	case errors.Is(err, context.DeadlineExceeded):
		return "", fmt.Errorf("the node did not join within %s. Set TS_AUTHKEY to join unattended, or run once with -open-login on a machine with a browser to authorize interactively. The node key persists in the configured state_dir, so later starts do not log in again: %w", timeout, err)
	default:
		return "", err
	}
}

// expectedFQDN checks the name the join reported against the one the config
// names, when it names one.
//
// The control server decides the node's name: a hostname already taken comes
// back with a suffix appended. Every canonical resource URI is built from that
// name, so an unexpected one silently shifts every audience away from the URL
// each client was configured with, and each request fails at the audience
// check with nothing pointing at the cause. Refusing to serve reports it once,
// at startup, against the name a reviewer can compare to the config.
func expectedFQDN(node config.Node, joined string) error {
	expected := node.FQDN()
	if expected == "" {
		return nil
	}
	if actual := strings.ToLower(strings.TrimSuffix(joined, ".")); actual != strings.ToLower(expected) {
		return fmt.Errorf("joined the tailnet as %q, but the config expects %q: every resource URI would differ from the one clients were configured with", actual, expected)
	}
	return nil
}

// connections is the shutdown half of *http.Server. drain takes it as an
// interface because a real http.Server that never served returns from Shutdown
// before it has done anything, which leaves the end of the chain unobservable.
type connections interface {
	Shutdown(ctx context.Context) error
	Close() error
}

// drain stops accepting, lets in-flight work finish, and only then tears
// anything down. Transports drain ahead of the HTTP server because the server
// waits on handlers the transports are still holding open, and the node leaves
// the tailnet last, once nothing it carries is still in flight.
func drain(logger *slog.Logger, node tsnetserver.Node, server connections, rt served) error {
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
	return errors.Join(stopped, drained, node.Close())
}
