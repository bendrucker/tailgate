package main

import (
	"errors"
	"log/slog"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/resource"
	"github.com/bendrucker/tailgate/internal/router"
	"github.com/bendrucker/tailgate/internal/site"
)

// handler assembles tailgate's public surface: the RFC 9728 metadata documents,
// the authorization server, and the authorized route to each upstream's
// transport. It takes urls rather than the FQDN because every canonical URI
// must come from the one instance the token store, the authorization server,
// and the metadata documents all read.
//
// The verifier and authorization server outlive the router. Both hold the
// tokens clients already have, and the router is what a configuration change
// rebuilds, so they are built once by the caller and passed in.
//
// The returned Router owns the transports. Shut it down to drain them and close
// it to tear them down.
func handler(cfg *config.Config, urls *resource.URLs, verifier router.Verifier, authServer router.AuthServer, logger *slog.Logger, auditor *audit.Logger) (*router.Router, error) {
	routes, err := upstreams(cfg.Upstreams, logger, auditor)
	if err != nil {
		return nil, err
	}

	// The metadata names tailgate itself as the authorization server, since
	// tailgate issues the tokens its upstreams accept.
	metadata, err := resource.NewHandler(urls, urls.Origin(), upstreamNames(cfg))
	if err != nil {
		return nil, errors.Join(err, closeUpstreams(routes))
	}

	// The favicon is optional, but a configured path that fails to load is a
	// broken deployment, so it fails startup rather than serving iconless.
	var pages router.Site
	if cfg.Favicon != "" {
		s, err := site.New(cfg.Favicon)
		if err != nil {
			return nil, errors.Join(err, closeUpstreams(routes))
		}
		pages = s
	}

	rt, err := router.New(router.Options{
		Upstreams:  routes,
		Resources:  urls,
		Metadata:   metadata,
		AuthServer: authServer,
		Site:       pages,
		Verifier:   verifier,
		Authorizer: auth.NewAuthorizer(cfg.Policy),
		Audit:      auditor,
		// tailgate serves exactly one origin, and only a browser sends the
		// header at all. Anything else is a rebinding attempt.
		AllowedOrigins: []string{urls.Origin()},
		Logger:         logger,
	})
	if err != nil {
		return nil, errors.Join(err, closeUpstreams(routes))
	}
	return rt, nil
}

func upstreamNames(cfg *config.Config) []string {
	names := make([]string, len(cfg.Upstreams))
	for i, upstream := range cfg.Upstreams {
		names[i] = upstream.Name
	}
	return names
}
