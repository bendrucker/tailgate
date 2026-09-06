package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/proxy/httptransport"
	"github.com/bendrucker/tailgate/internal/proxy/stdiotransport"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return parsed
}

func TestUpstreamRoute(t *testing.T) {
	for _, tc := range []struct {
		name           string
		upstream       config.Upstream
		expectedType   any
		managesSession bool
	}{
		{
			name: "http",
			upstream: config.Upstream{
				Name:      "docs",
				Transport: config.TransportHTTP,
				URL:       mustParseURL(t, "http://127.0.0.1:9000/mcp"),
			},
			expectedType: (*httptransport.Transport)(nil),
		},
		{
			name: "stdio",
			upstream: config.Upstream{
				Name:        "files",
				Transport:   config.TransportStdio,
				Command:     "mcp-files",
				Args:        []string{"--root", "/srv"},
				MaxChildren: 2,
				IdleTimeout: 90 * time.Second,
			},
			expectedType: (*stdiotransport.Transport)(nil),
			// The router must not bind sessions this transport binds itself.
			managesSession: true,
		},
		{
			name: "stdio under its own credential",
			upstream: config.Upstream{
				Name:       "files",
				Transport:  config.TransportStdio,
				Command:    "mcp-files",
				Credential: &config.Credential{UID: 570, GID: 570},
			},
			expectedType:   (*stdiotransport.Transport)(nil),
			managesSession: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := discardLogger()
			route, err := upstreamRoute(tc.upstream, logger, audit.New(logger))
			if err != nil {
				t.Fatalf("upstreamRoute: %v", err)
			}
			defer route.Transport.Close()

			if route.Name != tc.upstream.Name {
				t.Errorf("expected name %s, got %s", tc.upstream.Name, route.Name)
			}
			if got, expected := fmt.Sprintf("%T", route.Transport), fmt.Sprintf("%T", tc.expectedType); got != expected {
				t.Errorf("expected transport %s, got %s", expected, got)
			}
			if route.TransportManagesSessions != tc.managesSession {
				t.Errorf("expected TransportManagesSessions %t, got %t", tc.managesSession, route.TransportManagesSessions)
			}
		})
	}
}

// A transport name the switch does not know is all a parsed configuration
// leaves for this to reject, since every value an upstream carries was parsed
// before it got here.
func TestUpstreamRouteRejectsUnknownTransport(t *testing.T) {
	logger := discardLogger()
	route, err := upstreamRoute(config.Upstream{Name: "docs", Transport: "grpc"}, logger, audit.New(logger))
	if err == nil {
		route.Transport.Close()
		t.Fatal("expected an error for an unknown transport")
	}
}

// TestUpstreamsClosesOnFailure covers the leak a partial build would leave. A
// stdio transport runs a reaper goroutine from construction, so an upstream
// built before the failing one is closed rather than dropped.
func TestUpstreamsClosesOnFailure(t *testing.T) {
	logger := discardLogger()
	routes, err := upstreams([]config.Upstream{
		{Name: "files", Transport: config.TransportStdio, Command: "mcp-files"},
		{Name: "docs", Transport: "grpc"},
	}, logger, audit.New(logger))
	if err == nil {
		closeUpstreams(routes)
		t.Fatal("expected error")
	}
	if routes != nil {
		t.Errorf("expected no routes, got %d", len(routes))
	}
}
