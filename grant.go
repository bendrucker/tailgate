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
func grantCommand(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("grant", flag.ContinueOnError)
	// Only the generated grant goes to out. The usage footer documents appending
	// that stream to a policy file, so a diagnostic written there lands in the
	// policy instead of in front of the operator.
	flags.SetOutput(errOut)
	configPath := flags.String("config", "tailgate.hujson", "path to the tailgate config file")
	// The flag defaults are the package's, so PrintDefaults renders them and
	// they cannot drift from what grant.New falls back to.
	src := flags.String("src", grant.DefaultSrc, "policy source, comma separated")
	dst := flags.String("dst", grant.DefaultDst, "policy destination naming tsidp's node, comma separated")
	// -users stays empty so an unset flag falls back to the identities the
	// config's policy allows, which is a default PrintDefaults cannot render.
	users := flags.String("users", "", "tsidp rule users, comma separated (default: the identities the config's policy allows)")
	adminUI := flags.Bool("allow-admin-ui", false, "grant access to tsidp's admin UI")
	dcr := flags.Bool("allow-dcr", false, "grant dynamic client registration")
	flags.Usage = func() {
		w := flags.Output()
		fmt.Fprint(w, grantUsageHeader)
		flags.PrintDefaults()
		fmt.Fprint(w, grantUsageFooter)
	}
	if err := flags.Parse(args); err != nil {
		// ContinueOnError writes the failure and the usage before returning it,
		// and -h asks for the usage alone.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errReported
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(errOut, "tailgate grant: unexpected argument %q\n", flags.Arg(0))
		fmt.Fprintln(errOut, "Run 'tailgate grant -h' for usage.")
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
		Users:        orPolicyUsers(split(*users), cfg.Policy),
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

// orPolicyUsers narrows the grant's users to the identities tailgate's own
// policy allows, unless the caller named them itself.
//
// tsidp's users field and tailgate's policy gate the same thing from opposite
// ends: who may mint a token whose audience names an upstream, and who may
// reach that upstream with one. Leaving the first at the wildcard collapses the
// two into one, so anyone on the tailnet holds a token tailgate would have to
// deny by policy alone.
//
// A policy condition naming no identity leaves the grant at the wildcard rather
// than at the subset it could enumerate. Such a rule allows an identity this
// cannot name, and a grant narrower than the policy denies at the token request
// instead, where nothing in tailgate's audit log accounts for it.
func orPolicyUsers(explicit []string, policy []config.Rule) []string {
	if len(explicit) > 0 {
		return explicit
	}

	var users []string
	seen := make(map[string]bool)
	add := func(user string) {
		if user != "" && !seen[user] {
			seen[user] = true
			users = append(users, user)
		}
	}
	for _, rule := range policy {
		for _, match := range rule.Allow {
			if match.Email == "" && match.Subject == "" {
				return nil
			}
			add(match.Email)
			add(match.Subject)
		}
	}
	return users
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
