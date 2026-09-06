package main

import (
	"errors"
	"fmt"
	"log/slog"

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

// upstreamRoute builds one transport from an upstream the config package has
// already parsed, so there is nothing left here to reject but a transport name
// the switch does not know.
func upstreamRoute(cfg config.Upstream, logger *slog.Logger, auditor *audit.Logger) (router.Upstream, error) {
	logger = logger.With("upstream", cfg.Name)

	switch cfg.Transport {
	case config.TransportHTTP:
		return router.Upstream{
			Name:      cfg.Name,
			Transport: httptransport.New(cfg.URL, logger),
		}, nil

	case config.TransportStdio:
		options := stdiotransport.Options{
			Name:        cfg.Name,
			Command:     cfg.Command,
			Args:        cfg.Args,
			Env:         cfg.Env,
			Dir:         cfg.Dir,
			MaxSessions: cfg.MaxChildren,
			IdleTimeout: cfg.IdleTimeout,
			Logger:      logger,
			Audit:       auditor,
		}
		// The transport still spells an unset credential as a zero uid and gid.
		if credential := cfg.Credential; credential != nil {
			options.UID, options.GID = credential.UID, credential.GID
		}
		return router.Upstream{
			Name:      cfg.Name,
			Transport: stdiotransport.New(options),
			// A stdio child has no sessions of its own, so this transport mints
			// the ids and binds them to the caller itself.
			TransportManagesSessions: true,
		}, nil
	}
	return router.Upstream{}, fmt.Errorf("upstream %q: unknown transport %q", cfg.Name, cfg.Transport)
}

func closeUpstreams(routes []router.Upstream) error {
	var err error
	for _, route := range routes {
		err = errors.Join(err, route.Transport.Close())
	}
	return err
}
