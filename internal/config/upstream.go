package config

import (
	"fmt"
	"math"
	"net/url"
	"time"
)

// Transport names the wire protocol tailgate uses to reach an upstream.
const (
	TransportHTTP  = "http"
	TransportStdio = "stdio"
)

// Upstream is one MCP server tailgate fronts, addressed at /mcp/<name>.
type Upstream struct {
	Name      string
	Transport string

	// URL is the endpoint of an HTTP upstream, parsed and known to name an
	// http or https host.
	URL *url.URL

	// Stdio transport.
	Command     string
	Args        []string
	Env         []string
	Dir         string
	MaxChildren int
	IdleTimeout time.Duration
	// Credential is the user and group a stdio child runs under, or nil when
	// the config names none.
	Credential *Credential
}

// Credential is the user and group a stdio child runs under instead of
// tailgate's own. A child left at tailgate's uid can read the node key out of
// state_dir, read every other upstream's secrets out of the config file, and
// attach to tailgate itself for a live bearer token. Setting one is
// privileged, so a tailgate that cannot change a child's uid fails the spawn
// rather than running the child uncontained.
//
// The pair is present or absent together, which is why it is a type of its own
// rather than two integers whose zero value has to stand for unset: uid 0 is
// the one uid holding every privilege the containment exists to withhold, and
// the file has no way to spell it.
type Credential struct {
	UID int
	GID int
}

// upstream is one entry of the upstreams array as the file spells it, whose
// url, idle_timeout, uid, and gid are parsed into the Upstream a consumer
// holds.
type upstream struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`

	// HTTP transport.
	URL string `json:"url,omitempty"`

	// Stdio transport.
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
	Env         []string `json:"env,omitempty"`
	Dir         string   `json:"dir,omitempty"`
	MaxChildren int      `json:"max_children,omitempty"`
	IdleTimeout string   `json:"idle_timeout,omitempty"`

	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`
}

func (u upstream) parse() (Upstream, error) {
	if u.Name == "" {
		return Upstream{}, fmt.Errorf("config: upstream name is required")
	}
	// The name becomes a single path segment of the canonical resource URI,
	// matched byte-for-byte against token audiences and routes. Anything
	// outside this set (slashes, dots, URL metacharacters, uppercase) would
	// mint an aliased, unroutable, or divergently escaped URI.
	if !upstreamName.MatchString(u.Name) {
		return Upstream{}, fmt.Errorf("config: upstream name %q must match %s", u.Name, upstreamName)
	}

	parsed := Upstream{Name: u.Name, Transport: u.Transport}
	switch u.Transport {
	case TransportHTTP:
		target, err := u.endpoint()
		if err != nil {
			return Upstream{}, err
		}
		parsed.URL = target
		if u.UID != 0 || u.GID != 0 {
			return Upstream{}, fmt.Errorf("config: upstream %q: uid and gid apply only to the stdio transport", u.Name)
		}
	case TransportStdio:
		if u.Command == "" {
			return Upstream{}, fmt.Errorf("config: upstream %q: command is required for stdio transport", u.Name)
		}
		idle, err := u.idle()
		if err != nil {
			return Upstream{}, err
		}
		credential, err := u.credential()
		if err != nil {
			return Upstream{}, err
		}
		parsed.Command = u.Command
		parsed.Args = u.Args
		parsed.Env = u.Env
		parsed.Dir = u.Dir
		parsed.MaxChildren = u.MaxChildren
		parsed.IdleTimeout = idle
		parsed.Credential = credential
	default:
		return Upstream{}, fmt.Errorf("config: upstream %q: unknown transport %q", u.Name, u.Transport)
	}
	return parsed, nil
}

// endpoint parses an HTTP upstream's address. Construction never dials, so an
// address no request could ever be built from is the last failure catchable
// before serving, and catching it here rather than at assembly keeps a reload
// from accepting a file it then refuses to serve.
func (u upstream) endpoint() (*url.URL, error) {
	if u.URL == "" {
		return nil, fmt.Errorf("config: upstream %q: url is required for http transport", u.Name)
	}
	target, err := url.Parse(u.URL)
	if err != nil {
		return nil, fmt.Errorf("config: upstream %q: url: %w", u.Name, err)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("config: upstream %q: url %q has no host", u.Name, u.URL)
	}
	switch target.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("config: upstream %q: url %q must be http or https", u.Name, u.URL)
	}
	return target, nil
}

func (u upstream) idle() (time.Duration, error) {
	if u.IdleTimeout == "" {
		return 0, nil
	}
	idle, err := time.ParseDuration(u.IdleTimeout)
	if err != nil {
		return 0, fmt.Errorf("config: upstream %q: idle_timeout: %w", u.Name, err)
	}
	return idle, nil
}

// credential reads the uid and gid a stdio child runs under. They are required
// together: a child that keeps tailgate's uid while taking a different group is
// not a boundary, and one that takes a uid while its gid falls through to zero
// runs in the root group.
func (u upstream) credential() (*Credential, error) {
	switch {
	case u.UID == 0 && u.GID == 0:
		return nil, nil
	case u.UID == 0 || u.GID == 0:
		return nil, fmt.Errorf("config: upstream %q: uid and gid must be set together", u.Name)
	case u.UID < 0 || u.GID < 0:
		return nil, fmt.Errorf("config: upstream %q: uid %d and gid %d must be positive", u.Name, u.UID, u.GID)
	case u.UID > math.MaxUint32 || u.GID > math.MaxUint32:
		return nil, fmt.Errorf("config: upstream %q: uid %d and gid %d exceed the range of a uid_t", u.Name, u.UID, u.GID)
	}
	return &Credential{UID: u.UID, GID: u.GID}, nil
}
