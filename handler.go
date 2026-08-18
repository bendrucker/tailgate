package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/authserver"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/resource"
	"github.com/bendrucker/tailgate/internal/router"
)

// handler assembles tailgate's public surface: the RFC 9728 metadata documents,
// the authorization-server endpoints tailgate fronts for clients that skip that
// discovery, and the authorized route to each upstream's transport. It takes urls rather
// than the FQDN because every canonical URI must come from the one instance the
// verifier and the metadata documents also read.
//
// The returned Router owns the transports. Shut it down to drain them and close
// it to tear them down.
func handler(cfg *config.Config, urls *resource.URLs, verifier router.Verifier, issuerClient *http.Client, logger *slog.Logger, auditor *audit.Logger) (*router.Router, error) {
	routes, err := upstreams(cfg.Upstreams, logger, auditor)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(routes))
	for i, route := range routes {
		names[i] = route.Name
	}

	// The metadata names tailgate itself as the authorization server, matching
	// what the facade below publishes. Naming the issuer instead would send a
	// discovering client to endpoints tailgate does not front, and its
	// /authorize is tailnet-only, so a browser arriving from outside is refused.
	// Tokens still originate at the issuer: the facade redirects there for the
	// human step and proxies the exchange.
	metadata, err := resource.NewHandler(urls, urls.Origin(), names)
	if err != nil {
		return nil, errors.Join(err, closeUpstreams(routes))
	}

	facade, err := authserver.New(urls.Origin(), cfg.OIDC.Issuer, issuerClient, logger)
	if err != nil {
		return nil, errors.Join(err, closeUpstreams(routes))
	}

	rt, err := router.New(router.Options{
		Upstreams:  routes,
		Resources:  urls,
		Metadata:   metadata,
		AuthServer: facade,
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
