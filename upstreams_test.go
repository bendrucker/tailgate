package main

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/proxy/httptransport"
	"github.com/bendrucker/tailgate/internal/proxy/stdiotransport"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
				URL:       "http://127.0.0.1:9000/mcp",
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
				IdleTimeout: "90s",
			},
			expectedType: (*stdiotransport.Transport)(nil),
			// The router must not bind sessions this transport binds itself.
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

func TestUpstreamRouteRejects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream config.Upstream
	}{
		{
			name:     "unknown transport",
			upstream: config.Upstream{Name: "docs", Transport: "grpc"},
		},
		{
			name:     "relative url",
			upstream: config.Upstream{Name: "docs", Transport: config.TransportHTTP, URL: "/mcp"},
		},
		{
			name:     "non http scheme",
			upstream: config.Upstream{Name: "docs", Transport: config.TransportHTTP, URL: "ws://127.0.0.1:9000/mcp"},
		},
		{
			name:     "unparseable url",
			upstream: config.Upstream{Name: "docs", Transport: config.TransportHTTP, URL: "http://[::1"},
		},
		{
			name: "unparseable idle timeout",
			upstream: config.Upstream{
				Name:        "files",
				Transport:   config.TransportStdio,
				Command:     "mcp-files",
				IdleTimeout: "forever",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := discardLogger()
			route, err := upstreamRoute(tc.upstream, logger, audit.New(logger))
			if err == nil {
				route.Transport.Close()
				t.Fatalf("expected error for %+v", tc.upstream)
			}
		})
	}
}

// TestUpstreamsClosesOnFailure covers the leak a partial build would leave. A
// stdio transport runs a reaper goroutine from construction, so an upstream
// built before the failing one is closed rather than dropped.
func TestUpstreamsClosesOnFailure(t *testing.T) {
	logger := discardLogger()
	routes, err := upstreams([]config.Upstream{
		{Name: "files", Transport: config.TransportStdio, Command: "mcp-files"},
		{Name: "docs", Transport: config.TransportHTTP, URL: "ws://127.0.0.1:9000/mcp"},
	}, logger, audit.New(logger))
	if err == nil {
		closeUpstreams(routes)
		t.Fatal("expected error")
	}
	if routes != nil {
		t.Errorf("expected no routes, got %d", len(routes))
	}
}
