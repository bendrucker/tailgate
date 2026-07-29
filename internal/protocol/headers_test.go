package protocol

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// meta is the _meta block every 2026-07-28 request body carries.
// Built from the exported key rather than a literal, so the constant callers
// declare the version with and the tag the parser reads it from cannot drift.
var meta = fmt.Sprintf(`"_meta":{%q:%q}`, MetaProtocolVersion, Rev20260728)

func TestValidateMirrored(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string][]string
		body    string
		err     error
	}{
		{
			name: "tools/call with matching headers",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/call"},
				NameHeader:    {"get_weather"},
			},
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{},` + meta + `}}`,
		},
		{
			name: "resources/read mirrors the uri",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"resources/read"},
				NameHeader:    {"file:///app/config.json"},
			},
			body: `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///app/config.json",` + meta + `}}`,
		},
		{
			name: "method with no name requirement",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/list"},
			},
			body: `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{` + meta + `}}`,
		},
		{
			name: "base64 sentinel decodes before comparison",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/call"},
				NameHeader:    {"=?base64?SGVsbG8sIOS4lueVjA==?="},
			},
			body: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"Hello, 世界",` + meta + `}}`,
		},
		{
			name: "unrecognized Mcp-Param headers are forwarded, not judged",
			headers: map[string][]string{
				VersionHeader:            {"2026-07-28"},
				MethodHeader:             {"tools/call"},
				NameHeader:               {"execute_sql"},
				"Mcp-Param-Region":       {"us-west1"},
				"Mcp-Param-Unrecognized": {"anything at all"},
			},
			body: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"execute_sql","arguments":{"region":"us-west1"},` + meta + `}}`,
		},
		{
			name: "method header disagrees with the body",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/list"},
			},
			body: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"x",` + meta + `}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "name header disagrees with the body",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/call"},
				NameHeader:    {"read_file"},
			},
			body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_file","arguments":{},` + meta + `}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "required name header is missing",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/call"},
			},
			body: `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_weather",` + meta + `}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "required method header is missing",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
			},
			body: `{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{` + meta + `}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "body declares a different protocol version",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/list"},
			},
			body: `{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "body omits the protocol version the revision requires",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/list"},
			},
			body: `{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "repeated method header is not a value to choose from",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/list", "tools/call"},
			},
			body: `{"jsonrpc":"2.0","id":12,"method":"tools/list","params":{` + meta + `}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "body is not JSON",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/list"},
			},
			body: `not json`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "notification without mirrored headers is left alone",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
			},
			body: `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{` + meta + `}}`,
		},
		{
			name: "notification carries no protocol version to mirror",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
			},
			body: `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"x"}}`,
		},
		{
			name: "notification with no params at all",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
			},
			body: `{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
		},
		{
			name: "body carries an id and no method",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
			},
			body: `{"jsonrpc":"2.0","id":"tailgate-3","params":{` + meta + `},"result":{}}`,
			err:  ErrHeaderMismatch,
		},
		{
			name: "malformed base64 sentinel",
			headers: map[string][]string{
				VersionHeader: {"2026-07-28"},
				MethodHeader:  {"tools/call"},
				NameHeader:    {"=?base64?not valid base64!?="},
			},
			body: `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"x",` + meta + `}}`,
			err:  ErrHeaderMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			for name, values := range tc.headers {
				for _, value := range values {
					header.Add(name, value)
				}
			}
			err := ValidateMirrored(header, []byte(tc.body))
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected error %v, got %v", tc.err, err)
			}
		})
	}
}

func TestDecodeValue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		value    string
		expected string
		err      error
	}{
		{
			name:     "plain ascii passes through",
			value:    "us-west1",
			expected: "us-west1",
		},
		{
			name:     "non-ascii value",
			value:    "=?base64?SGVsbG8sIOS4lueVjA==?=",
			expected: "Hello, 世界",
		},
		{
			name:     "value that itself looks like the sentinel",
			value:    "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
			expected: "=?base64?literal?=",
		},
		{
			name:     "leading and trailing space survives encoding",
			value:    "=?base64?IHBhZGRlZCA=?=",
			expected: " padded ",
		},
		{
			name:  "unterminated sentinel",
			value: "=?base64?SGVsbG8s",
			err:   ErrHeaderMismatch,
		},
		{
			name:  "sentinel wrapping invalid base64",
			value: "=?base64?!!!?=",
			err:   ErrHeaderMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeValue(tc.value)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected error %v, got %v", tc.err, err)
			}
			if decoded != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, decoded)
			}
		})
	}
}
