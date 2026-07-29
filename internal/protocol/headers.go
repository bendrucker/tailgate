package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// The HTTP headers the streamable HTTP transport defines.
const (
	// VersionHeader carries the revision the request speaks.
	VersionHeader = "MCP-Protocol-Version"
	// MethodHeader mirrors the JSON-RPC method.
	MethodHeader = "Mcp-Method"
	// NameHeader mirrors params.name or params.uri, whichever names the thing
	// the method acts on.
	NameHeader = "Mcp-Name"
	// SessionHeader carried the session identifier through 2025-11-25.
	SessionHeader = "Mcp-Session-Id"
)

// ErrHeaderMismatch reports a request whose mirrored headers disagree with its
// body, or that omits one the revision requires. It maps to 400 and JSON-RPC
// error code [CodeHeaderMismatch].
//
// The mismatch is a security condition, not a formatting one: an intermediary
// that routes on the header while the server executes on the body can be made
// to disagree with itself, which is the attack the mirroring rules exist to
// close.
var ErrHeaderMismatch = errors.New("protocol: request headers do not match the body")

// CodeHeaderMismatch is the JSON-RPC error code for [ErrHeaderMismatch],
// allocated from the range the MCP specification reserves for itself.
const CodeHeaderMismatch = -32020

// HeaderError is a mismatch attributed to one header, so a refusal can name
// the header at fault without quoting the caller-supplied value it carried.
type HeaderError struct {
	// Header is the field that failed, or "" when the body itself was
	// unreadable and no single header can be blamed.
	Header string
	Detail string
}

func (e *HeaderError) Error() string {
	if e.Header == "" {
		return ErrHeaderMismatch.Error() + ": " + e.Detail
	}
	return ErrHeaderMismatch.Error() + ": " + e.Header + ": " + e.Detail
}

func (e *HeaderError) Unwrap() error { return ErrHeaderMismatch }

func mismatch(header, format string, args ...any) *HeaderError {
	return &HeaderError{Header: header, Detail: fmt.Sprintf(format, args...)}
}

// The sentinel wrapping a header value that could not be sent as plain ASCII.
const (
	base64Prefix = "=?base64?"
	base64Suffix = "?="
)

// The params._meta keys this revision carries per-request, in place of the
// initialize handshake that used to negotiate them once per session.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// namedMethods maps each method that must carry Mcp-Name to the params field
// the header mirrors.
var namedMethods = map[string]string{
	"tools/call":     "name",
	"prompts/get":    "name",
	"resources/read": "uri",
}

// ValidateMirrored checks a request body against the headers that mirror it.
// It is the intermediary half of the streamable HTTP header contract: tailgate
// forwards both the headers and the body, so it must not pass on a pair that
// disagree even though the upstream is obliged to check them again.
//
// The Mcp-Param-* headers a server may ask clients to mirror tool arguments
// into are deliberately not checked. tailgate never sees a tool's inputSchema,
// so it cannot tell which argument a given one restates, and RFC 9110 has it
// forward an unrecognized field untouched.
//
// body must be the complete request body. Callers that have not buffered it
// cannot run this check, and must not claim to have run it.
func ValidateMirrored(header http.Header, body []byte) error {
	msg, err := parseEnvelope(body)
	if err != nil {
		return err
	}

	method, err := singleHeader(header, MethodHeader)
	if err != nil {
		return err
	}
	switch {
	case msg.method == "":
		// A body carrying an id and no method is neither request nor
		// notification. Passing it on would hand the upstream a message no
		// mirrored header describes, which downstream reads as one the
		// intermediary vouched for.
		return mismatch(MethodHeader, "body carries no method")
	case method == "" && !msg.isRequest:
		// The revision requires the mirrored headers and the per-request
		// _meta on requests. It states neither for notifications, so an
		// unmirrored one is left alone rather than refused, and the version
		// check below does not apply to it either.
		return nil
	case method != msg.method:
		return mismatch(MethodHeader, "header is %q, body method is %q", method, msg.method)
	}

	version, err := singleHeader(header, VersionHeader)
	if err != nil {
		return err
	}
	if msg.protocolVersion != version {
		return mismatch(VersionHeader, "header is %q, body _meta declares %q", version, msg.protocolVersion)
	}

	field, named := namedMethods[msg.method]
	if !named {
		return nil
	}
	name, err := decodedHeader(header, NameHeader)
	if err != nil {
		return err
	}
	if expected := msg.params[field]; name != expected {
		return mismatch(NameHeader, "header is %q, body params.%s is %q", name, field, expected)
	}
	return nil
}

// envelope is the part of a JSON-RPC message the mirrored headers restate.
type envelope struct {
	method          string
	protocolVersion string
	// params holds only the string-valued members the headers can mirror.
	params    map[string]string
	isRequest bool
}

// parseEnvelope reads the mirrored fields out of a request body. A body that
// is not a JSON-RPC message fails the check rather than skipping it: nothing
// downstream can be validated against it, and forwarding it unchecked is the
// case the mirroring rules exist to prevent.
func parseEnvelope(body []byte) (envelope, error) {
	var raw struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return envelope{}, mismatch("", "body is not a JSON-RPC message: %v", err)
	}

	msg := envelope{
		method:    raw.Method,
		params:    map[string]string{},
		isRequest: hasID(raw.ID),
	}

	// JSON-RPC permits array params, and a method with no arguments may omit
	// them, so anything but an object simply mirrors nothing.
	if len(raw.Params) == 0 || !bytes.HasPrefix(bytes.TrimLeft(raw.Params, " \t\r\n"), []byte("{")) {
		return msg, nil
	}
	var params struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
		Meta struct {
			ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(raw.Params, &params); err != nil {
		return envelope{}, mismatch("", "request params are malformed: %v", err)
	}
	msg.params["name"] = params.Name
	msg.params["uri"] = params.URI
	msg.protocolVersion = params.Meta.ProtocolVersion
	return msg, nil
}

// hasID reports whether the message expects a response. A null id is not an
// identifier, so a message carrying one is not a request.
func hasID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// singleHeader reads a header that may appear at most once. A repeated header
// is a mismatch rather than a value to choose from: which copy an intermediary
// downstream would read is not decidable here.
func singleHeader(header http.Header, name string) (string, error) {
	values := header.Values(name)
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", mismatch(name, "header appears %d times", len(values))
	}
}

// decodedHeader reads a header whose value may carry the Base64 sentinel,
// returning the value the body is compared against.
func decodedHeader(header http.Header, name string) (string, error) {
	value, err := singleHeader(header, name)
	if err != nil {
		return "", err
	}
	return DecodeValue(value)
}

// DecodeValue unwraps the Base64 sentinel a client uses for a header value
// that cannot be sent as plain ASCII. A value without the sentinel is its own
// decoding.
func DecodeValue(value string) (string, error) {
	encoded, ok := strings.CutPrefix(value, base64Prefix)
	if !ok {
		return value, nil
	}
	encoded, ok = strings.CutSuffix(encoded, base64Suffix)
	if !ok {
		return "", mismatch("", "%s sentinel is unterminated", base64Prefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", mismatch("", "header value is not valid base64: %v", err)
	}
	return string(decoded), nil
}
