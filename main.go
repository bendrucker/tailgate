package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/bendrucker/tailgate/internal/config"
)

// errReported marks a failure the command already wrote to its own output.
// A FlagSet reports a parse error before returning it, so main exits on one
// without printing it a second time.
var errReported = errors.New("reported")

const usageHeader = `tailgate fronts MCP servers behind Tailscale Funnel. It joins the tailnet as
its own node, validates tsidp OIDC tokens, and proxies authorized requests to
HTTP and stdio MCP upstreams at /mcp/<name>.

Usage:
  tailgate [flags]        serve the configured upstreams
  tailgate grant [flags]  print the tsidp policy grant authorizing those upstreams

Flags:
`

const usageFooter = `
Set TS_AUTHKEY to join the tailnet on the first start. The node key then
persists in node.state_dir, so later starts do not log in again.

Run "tailgate grant -h" for its flags.
`

// refuse reports a bad invocation and exits. Both entry points to it are usage
// errors rather than runtime failures, so they share an exit code distinct from
// the one a failed serve returns.
func refuse(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	fmt.Fprintln(os.Stderr, "Run 'tailgate -h' for usage.")
	os.Exit(2)
}

// usage brackets PrintDefaults so the flag list is generated from the flags
// main registers and cannot drift from them.
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, usageHeader)
	flag.PrintDefaults()
	fmt.Fprint(out, usageFooter)
}

func main() {
	configPath := flag.String("config", "tailgate.hujson", "path to the tailgate config file")
	openLogin := flag.Bool("open-login", false, "open the interactive login URL in the default browser when the node has no auth key")
	flag.CommandLine.Usage = usage

	// Serving is the default, so a deployment's command line stays
	// `tailgate -config ...` and the generator is the named mode. A leading
	// argument that is not a flag has to name a command: falling through on a
	// misspelled one starts serving.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "grant":
			if err := grantCommand(os.Args[2:], os.Stdout, os.Stderr); err != nil {
				if !errors.Is(err, errReported) {
					fmt.Fprintln(os.Stderr, err)
				}
				os.Exit(1)
			}
			return
		case "help":
			flag.CommandLine.SetOutput(os.Stdout)
			usage()
			return
		default:
			refuse("tailgate: unknown command %q", os.Args[1])
		}
	}

	flag.Parse()

	// The dispatch above only sees a command in the first argument. flag.Parse
	// stops at the first non-flag rather than reporting it, so one written after
	// the flags would otherwise fall through and start serving.
	if flag.NArg() > 0 {
		refuse("tailgate: unexpected argument %q", flag.Arg(0))
	}

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
