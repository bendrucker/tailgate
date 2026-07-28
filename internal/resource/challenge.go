package resource

import "strings"

// ChallengeOptions carries the optional RFC 6750 section 3 error parameters on
// a WWW-Authenticate challenge. The zero value produces a bare challenge,
// which is what a request carrying no credentials gets: the error parameters
// describe a token that was presented and rejected.
type ChallengeOptions struct {
	// Error is an RFC 6750 error code, such as invalid_token or
	// insufficient_scope.
	Error string
	// ErrorDescription is human-readable detail for the developer of the
	// calling client. It must not restate the credential that failed.
	ErrorDescription string
}

// Challenge builds the WWW-Authenticate value for a 401 on the named upstream.
// The resource_metadata parameter points at that upstream's metadata document
// per RFC 9728 section 5.1, which is how an MCP client discovers the
// authorization server with no prior configuration.
func (u *URLs) Challenge(name string, opts ChallengeOptions) string {
	params := []string{"resource_metadata=" + quoteParam(u.MetadataURL(name))}
	if opts.Error != "" {
		params = append(params, "error="+quoteParam(opts.Error))
	}
	if opts.ErrorDescription != "" {
		params = append(params, "error_description="+quoteParam(opts.ErrorDescription))
	}
	return "Bearer " + strings.Join(params, ", ")
}

// quoteParam renders v as an RFC 9110 quoted-string. Descriptions can be built
// from a rejected request, so bytes outside printable ASCII are dropped rather
// than escaped: a bare CR or LF would either split the header or make net/http
// refuse to write the response at all.
func quoteParam(v string) string {
	var quoted strings.Builder
	quoted.Grow(len(v) + 2)
	quoted.WriteByte('"')
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c > 0x7e {
			continue
		}
		if c == '"' || c == '\\' {
			quoted.WriteByte('\\')
		}
		quoted.WriteByte(c)
	}
	quoted.WriteByte('"')
	return quoted.String()
}
