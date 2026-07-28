package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bendrucker/tailgate/internal/config"
)

func main() {
	configPath := flag.String("config", "tailgate.hujson", "path to the tailgate config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "path", *configPath, "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, logger, cfg); err != nil {
		// A canceled context is the signal that asked tailgate to stop, so it
		// reports the shutdown it completed rather than a failure.
		if errors.Is(err, context.Canceled) {
			logger.Info("tailgate stopped")
			return
		}
		logger.Error("tailgate exited", "err", err)
		os.Exit(1)
	}
	logger.Info("tailgate stopped")
}
