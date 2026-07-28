package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/bendrucker/tailgate/internal/config"
)

func main() {
	configPath := flag.String("config", "tailgate.hujson", "path to the tailgate config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "path", *configPath, "err", err)
		os.Exit(1)
	}

	if err := run(context.Background(), logger, cfg); err != nil {
		logger.Error("tailgate exited", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	// TODO(workflow): wire the tsnet Funnel listener, the OAuth resource server,
	// token verification and authorization, the router, and the upstream
	// transports. See CLAUDE.md for the layer-2 work units.
	_ = ctx
	logger.Info("tailgate configured", "node", cfg.Node.Hostname, "upstreams", len(cfg.Upstreams))
	return nil
}
