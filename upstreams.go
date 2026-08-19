package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/proxy/httptransport"
	"github.com/bendrucker/tailgate/internal/proxy/stdiotransport"
	"github.com/bendrucker/tailgate/internal/router"
)

// upstreams builds one transport per configured upstream. Construction never
// dials or spawns, so a broken upstream degrades to a per-request error rather
// than blocking startup.
func upstreams(cfgs []config.Upstream, logger *slog.Logger, auditor *audit.Logger) ([]router.Upstream, error) {
	routes := make([]router.Upstream, 0, len(cfgs))
	for _, cfg := range cfgs {
		route, err := upstreamRoute(cfg, logger, auditor)
		if err != nil {
			// A stdio transport starts a reaper goroutine, so the transports
			// already built are torn down rather than abandoned.
			return nil, errors.Join(err, closeUpstreams(routes))
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func upstreamRoute(cfg config.Upstream, logger *slog.Logger, auditor *audit.Logger) (router.Upstream, error) {
	logger = logger.With("upstream", cfg.Name)

	switch cfg.Transport {
	case config.TransportHTTP:
		target, err := upstreamURL(cfg.URL)
		if err != nil {
			return router.Upstream{}, fmt.Errorf("upstream %q: %w", cfg.Name, err)
		}
		return router.Upstream{
			Name:      cfg.Name,
			Transport: httptransport.New(target, logger),
		}, nil

	case config.TransportStdio:
		idle, err := idleTimeout(cfg.IdleTimeout)
		if err != nil {
			return router.Upstream{}, fmt.Errorf("upstream %q: idle_timeout: %w", cfg.Name, err)
		}
		return router.Upstream{
			Name: cfg.Name,
			Transport: stdiotransport.New(stdiotransport.Options{
				Name:        cfg.Name,
				Command:     cfg.Command,
				Args:        cfg.Args,
				Env:         cfg.Env,
				Dir:         cfg.Dir,
				UID:         cfg.UID,
				GID:         cfg.GID,
				MaxSessions: cfg.MaxChildren,
				IdleTimeout: idle,
				Logger:      logger,
				Audit:       auditor,
			}),
			// A stdio child has no sessions of its own, so this transport mints
			// the ids and binds them to the caller itself.
			TransportManagesSessions: true,
		}, nil
	}
	return router.Upstream{}, fmt.Errorf("upstream %q: unknown transport %q", cfg.Name, cfg.Transport)
}

// upstreamURL parses an HTTP upstream's endpoint. The config validates only
// that it is present, and construction never dials, so an address no request
// could ever be built from is the one failure still catchable before serving.
func upstreamURL(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("url %q has no host", raw)
	}
	switch target.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("url %q must be http or https", raw)
	}
	return target, nil
}

func idleTimeout(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	return time.ParseDuration(raw)
}

func closeUpstreams(routes []router.Upstream) error {
	var err error
	for _, route := range routes {
		err = errors.Join(err, route.Transport.Close())
	}
	return err
}
