package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/grant"
	"github.com/bendrucker/tailgate/internal/resource"
)

const grantUsageHeader = `Usage: tailgate grant [flags]

Print the tsidp application-capability grant authorizing the configured
upstreams, as one entry of the tailnet policy's "grants" array. Append it to
the policy that applies to your tailnet, and regenerate it when upstreams
change. Editing a resource string by hand denies every request with an
audience mismatch.

Generating never contacts the control server, so the grant can be reviewed and
applied before the node exists. That needs node.tailnet in the config, since
the resource URIs are built from the node's FQDN.

Flags:
`

const grantUsageFooter = `
A grant destination must be a tag, user, group, host alias, or address, so it
cannot be derived from the issuer URL. Narrow -dst when tsidp runs on a tagged
node.

Example:
  tailgate grant -config /etc/tailgate.hujson >> tailnet-policy/grants.hujson
`

// grantCommand implements `tailgate grant`, which grantUsageHeader documents.
func grantCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("grant", flag.ContinueOnError)
	flags.SetOutput(out)
	configPath := flags.String("config", "tailgate.hujson", "path to the tailgate config file")
	// The flag defaults are the package's, so PrintDefaults renders them and
	// they cannot drift from what grant.New falls back to.
	src := flags.String("src", grant.DefaultSrc, "policy source, comma separated")
	dst := flags.String("dst", grant.DefaultDst, "policy destination naming tsidp's node, comma separated")
	users := flags.String("users", grant.DefaultUser, "tsidp rule users, comma separated")
	adminUI := flags.Bool("allow-admin-ui", false, "grant access to tsidp's admin UI")
	dcr := flags.Bool("allow-dcr", false, "grant dynamic client registration")
	flags.Usage = func() {
		fmt.Fprint(out, grantUsageHeader)
		flags.PrintDefaults()
		fmt.Fprint(out, grantUsageFooter)
	}
	if err := flags.Parse(args); err != nil {
		// ContinueOnError writes the failure and the usage before returning it,
		// and -h asks for the usage alone.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errReported
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
