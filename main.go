package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bendrucker/tailgate/internal/config"
)

func main() {
	// Serving is the default, so a deployment's command line stays
	// `tailgate -config ...` and the generator is the named mode.
	if len(os.Args) > 1 && os.Args[1] == "grant" {
		if err := grantCommand(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	configPath := flag.String("config", "tailgate.hujson", "path to the tailgate config file")
	openLogin := flag.Bool("open-login", false, "open the interactive login URL in the default browser when the node has no auth key")
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

	if err := serve(ctx, logger, cfg, options{OpenLoginURL: *openLogin}); err != nil {
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
