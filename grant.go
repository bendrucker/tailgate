package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/grant"
	"github.com/bendrucker/tailgate/internal/resource"
)

// grantCommand prints the tsidp application-capability grant authorizing the
// configured upstreams, for the tailnet policy that applies it.
//
// It never contacts the control server, so the grant can be generated, reviewed,
// and applied before the node it describes exists. That requires node.tailnet,
// because the canonical URIs are built from the FQDN and nothing else can supply
// it offline.
func grantCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("grant", flag.ContinueOnError)
	flags.SetOutput(out)
	configPath := flags.String("config", "tailgate.hujson", "path to the tailgate config file")
	src := flags.String("src", "", "policy source, comma separated (default "+grant.DefaultSrc+")")
	dst := flags.String("dst", "", "policy destination naming tsidp's node, comma separated (default "+grant.DefaultDst+")")
	users := flags.String("users", "", "tsidp rule users, comma separated (default "+grant.DefaultUser+")")
	adminUI := flags.Bool("allow-admin-ui", false, "grant access to tsidp's admin UI")
	dcr := flags.Bool("allow-dcr", false, "grant dynamic client registration")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	fqdn := cfg.Node.FQDN()
	if fqdn == "" {
		return fmt.Errorf("grant: node.tailnet is required to generate a grant, since the resource URIs are built from the node's FQDN")
	}

	urls, err := resource.NewURLs(fqdn, cfg.Node.Port)
	if err != nil {
		return err
	}

	names := make([]string, len(cfg.Upstreams))
	for i, upstream := range cfg.Upstreams {
		names[i] = upstream.Name
	}

	g, err := grant.New(urls, names, grant.Options{
		Src:          split(*src),
		Dst:          split(*dst),
		Users:        split(*users),
		AllowAdminUI: *adminUI,
		AllowDCR:     *dcr,
	})
	if err != nil {
		return err
	}

	rendered, err := g.HuJSON()
	if err != nil {
		return err
	}
	_, err = out.Write(rendered)
	return err
}

func split(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	trimmed := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			trimmed = append(trimmed, part)
		}
	}
	return trimmed
}
